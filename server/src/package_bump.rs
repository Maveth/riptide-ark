//! Spend the server's change to lift a stuck round package.
//!
//! A round funding transaction's id is fixed once wallets have signed the
//! tree, so the funding transaction itself is not replaced. The vtxo tree
//! output stays put. When a round has been unconfirmed for
//! [`Config::round_package_bump_blocks`](crate::config::Config::round_package_bump_blocks),
//! the server spends the change it still holds at the tip of that
//! unconfirmed chain and pays enough that the whole ancestor package
//! reaches [`FeeEstimator::package_bump_target`](crate::fee_estimator::FeeEstimator::package_bump_target).

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::{Amount, FeeRate, OutPoint, Sequence, Transaction, Txid};
use bitcoin_ext::FeeRateExt;
use serde::Deserialize;
use tracing::{info, warn};

use ark::rounds::ROUND_TX_VTXO_TREE_VOUT;

use crate::bitcoind::{json_arg, BitcoindErrorExt};
use crate::nursery::NurseryTxKind;
use crate::wallet::BdkWalletExt;
use crate::Server;

/// Fee the child must pay so `ancestor` plus the child reaches `target`.
pub fn package_child_fee(
	ancestor_fee: Amount,
	ancestor_vsize: u64,
	child_vsize: u64,
	target: FeeRate,
) -> Amount {
	let total = ancestor_vsize.saturating_add(child_vsize);
	let needed = total.saturating_mul(target.to_sat_per_kvb()).div_ceil(1_000);
	Amount::from_sat(needed.saturating_sub(ancestor_fee.to_sat()))
}

/// Blocks since the nursery expected this tx to have been broadcast.
///
/// The nursery stores the height by which the tx should confirm, which is
/// the broadcast height plus `expect_within`.
pub fn blocks_unconfirmed(tip: u32, confirm_target: u32, expect_within: u32) -> u32 {
	let broadcast = confirm_target.saturating_sub(expect_within);
	tip.saturating_sub(broadcast)
}

/// A round's tree output is never a bump input. Any other output is.
pub fn is_tree_output(outpoint: OutPoint, round_txids: &HashSet<Txid>) -> bool {
	round_txids.contains(&outpoint.txid) && outpoint.vout == ROUND_TX_VTXO_TREE_VOUT
}

pub fn start(srv: Arc<Server>) {
	tokio::spawn(async move {
		let _worker = srv.rtmgr.spawn("RoundPackageBump");
		let mut tip = srv.chain_tip_watcher();
		loop {
			if let Err(e) = bump_stuck_rounds(&srv).await {
				warn!("round package bump failed: {:#}", e);
			}
			if tip.changed().await.is_err() {
				break;
			}
		}
	});
}

async fn bump_stuck_rounds(srv: &Server) -> anyhow::Result<()> {
	let wait = srv.config.round_package_bump_blocks;
	if wait == 0 {
		return Ok(());
	}
	let target = srv.fee_estimator.package_bump_target();
	let tip = srv.chain_tip().height.to_u32();
	let expect_within = srv.config.nursery_confirm_target_blocks.to_u32();
	let rounds = srv.db.read(async |t| t.get_active_nursery_txs(srv.chain_tip().height).await)
		.await.context("listing nursery txs")?
		.into_iter()
		.filter(|tx| tx.kind == NurseryTxKind::Round && tx.confirmed_at_height.is_none())
		.filter(|tx| {
			blocks_unconfirmed(tip, tx.confirm_target_height.to_u32(), expect_within) >= wait
		})
		.map(|tx| tx.txid)
		.collect::<HashSet<_>>();
	if rounds.is_empty() {
		return Ok(());
	}

	let mut family = rounds.clone();
	for txid in &rounds {
		let descendants = mempool_descendants(srv, *txid).await?;
		family.extend(descendants);
	}

	let tips = {
		let wallet = srv.rounds_wallet.lock().await;
		let mut tips = Vec::new();
		for utxo in wallet.list_unspent() {
			if utxo.chain_position.is_confirmed() {
				continue;
			}
			if !family.contains(&utxo.outpoint.txid) || is_tree_output(utxo.outpoint, &rounds) {
				continue;
			}
			tips.push((utxo.outpoint, utxo.txout.value));
		}
		tips
	};
	let tips = deepest_tips(srv, tips).await?;
	for (outpoint, value) in tips {
		if let Err(e) = bump_one(srv, outpoint, value, target).await {
			warn!("could not bump {outpoint}: {e:#}");
		}
	}
	Ok(())
}

async fn bump_one(
	srv: &Server, outpoint: OutPoint, input_value: Amount, target: FeeRate,
) -> anyhow::Result<()> {
	let ancestor = ancestor_fee(srv, outpoint.txid).await?;
	let Some(ancestor) = ancestor else {
		info!("skipping bump of {outpoint}: not in the mempool");
		return Ok(());
	};
	let rate_now = package_child_fee(ancestor.fee, ancestor.vsize, 0, target);
	if rate_now == Amount::ZERO {
		return Ok(());
	}

	let (mut wallet, built) = srv.rounds_wallet.build_blocking(move |wallet| {
		let _hold = wallet.lock_wallet_utxo(outpoint)
			.with_context(|| format!("change {outpoint} is already reserved"))?;
		let built = build_child(wallet, outpoint, input_value, ancestor, target)?;
		wallet.commit_tx(&built.0);
		Ok(built)
	}).await?;
	wallet.persist().await.context("persisting package bump")?;
	drop(wallet);

	let (tx, fee) = built;
	let txid = tx.compute_txid();
	info!(
		"round package bump {txid} spends {outpoint} fee {fee} target {} sat/kvb",
		target.to_sat_per_kvb(),
	);
	let confirm_at = srv.chain_tip().height + srv.config.nursery_confirm_target_blocks;
	srv.tx_nursery.broadcast_tx(tx, NurseryTxKind::Internal, confirm_at).await?;
	Ok(())
}

struct Ancestor {
	fee: Amount,
	vsize: u64,
}

fn build_child(
	wallet: &mut crate::wallet::PersistedWallet,
	outpoint: OutPoint,
	input_value: Amount,
	ancestor: Ancestor,
	target: FeeRate,
) -> anyhow::Result<(Transaction, Amount)> {
	let mut fee = package_child_fee(ancestor.fee, ancestor.vsize, 110, target);
	if fee > input_value {
		bail!("bump of {outpoint} needs {fee}, the change is only {input_value}");
	}
	for _ in 0..3 {
		let tx = sign_child(wallet, outpoint, fee)?;
		let vsize = tx.weight().to_wu().div_ceil(4);
		let needed = package_child_fee(ancestor.fee, ancestor.vsize, vsize, target);
		let paid = input_value - tx.output.iter().map(|o| o.value).sum::<Amount>();
		if paid >= needed {
			return Ok((tx, paid));
		}
		fee = needed;
	}
	bail!("could not price the package bump of {outpoint}")
}

fn sign_child(
	wallet: &mut crate::wallet::PersistedWallet,
	outpoint: OutPoint,
	fee: Amount,
) -> anyhow::Result<Transaction> {
	let spk = wallet.reveal_next_address(bitcoin_ext::bdk::KEYCHAIN).address.script_pubkey();
	let mut builder = wallet.build_tx();
	builder.add_utxo(outpoint).context("change output is not spendable")?;
	builder.manually_selected_only();
	builder.drain_to(spk);
	builder.fee_absolute(fee);
	builder.set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);
	let psbt = builder.finish().context("building package bump")?;
	wallet.finish_tx(psbt).context("signing package bump")
}

async fn ancestor_fee(srv: &Server, txid: Txid) -> anyhow::Result<Option<Ancestor>> {
	#[derive(Deserialize)]
	struct Fees {
		#[serde(with = "bitcoin::amount::serde::as_btc")]
		ancestor: Amount,
	}
	#[derive(Deserialize)]
	struct Entry {
		ancestorsize: u64,
		fees: Fees,
	}
	let raw = match srv.bitcoind.call_raw("getmempoolentry", &[json_arg(txid)?]).await {
		Ok(raw) => raw,
		Err(e) if e.is_not_found() => return Ok(None),
		Err(e) => return Err(e.into()),
	};
	let entry: Entry = serde_json::from_value(raw).context("mempool entry")?;
	Ok(Some(Ancestor { fee: entry.fees.ancestor, vsize: entry.ancestorsize }))
}

async fn mempool_descendants(srv: &Server, txid: Txid) -> anyhow::Result<Vec<Txid>> {
	let raw = match srv.bitcoind.call_raw("getmempooldescendants", &[json_arg(txid)?, false.into()]).await {
		Ok(raw) => raw,
		Err(e) if e.is_not_found() => return Ok(Vec::new()),
		Err(e) => return Err(e.into()),
	};
	Ok(serde_json::from_value(raw).context("mempool descendants")?)
}

/// Drop a coin whose transaction is an ancestor of another candidate.
async fn deepest_tips(
	srv: &Server, tips: Vec<(OutPoint, Amount)>,
) -> anyhow::Result<Vec<(OutPoint, Amount)>> {
	let mut keep = Vec::new();
	for tip in &tips {
		let mut shadowed = false;
		for other in &tips {
			if other.0.txid == tip.0.txid {
				continue;
			}
			let ancestors = mempool_ancestors(srv, other.0.txid).await?;
			if ancestors.contains(&tip.0.txid) {
				shadowed = true;
				break;
			}
		}
		if !shadowed {
			keep.push(*tip);
		}
	}
	Ok(keep)
}

async fn mempool_ancestors(srv: &Server, txid: Txid) -> anyhow::Result<HashSet<Txid>> {
	let raw = match srv.bitcoind.call_raw("getmempoolancestors", &[json_arg(txid)?, false.into()]).await {
		Ok(raw) => raw,
		Err(e) if e.is_not_found() => return Ok(HashSet::new()),
		Err(e) => return Err(e.into()),
	};
	let ids: Vec<Txid> = serde_json::from_value(raw).context("mempool ancestors")?;
	Ok(ids.into_iter().collect())
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::FeeRate;
	use bitcoin::hashes::{sha256d, Hash};
	use bitcoin_ext::FeeRateExt;

	fn txid(byte: u8) -> Txid {
		Txid::from_raw_hash(sha256d::Hash::from_byte_array([byte; 32]))
	}

	#[test]
	fn twelve_blocks_is_the_gate() {
		assert_eq!(blocks_unconfirmed(100, 94, 6), 12);
		assert!(blocks_unconfirmed(100, 94, 6) >= 12);
		assert!(blocks_unconfirmed(99, 94, 6) < 12);
	}

	#[test]
	fn child_fee_lifts_the_package_to_the_target() {
		let target = FeeRate::from_sat_per_kvb_ceil(3_000);
		let fee = package_child_fee(Amount::from_sat(942), 930, 150, target);
		let total_fee = 942 + fee.to_sat();
		let total_vsize = 930 + 150;
		assert!(total_fee * 1_000 >= total_vsize * 3_000);
		assert!(package_child_fee(Amount::from_sat(3_000), 1_000, 0, target) == Amount::ZERO);
	}

	#[test]
	fn the_tree_output_is_not_a_bump_input() {
		let round = txid(7);
		let mut rounds = HashSet::new();
		rounds.insert(round);
		assert!(is_tree_output(OutPoint::new(round, 0), &rounds));
		assert!(!is_tree_output(OutPoint::new(round, 1), &rounds));
		assert!(!is_tree_output(OutPoint::new(txid(8), 0), &rounds));
	}
}
