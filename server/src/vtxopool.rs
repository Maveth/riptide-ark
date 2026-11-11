
use std::{fmt, str};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::time::Duration;

use anyhow::Context;
use bdk_wallet::coin_selection::SingleRandomDraw;
use bitcoin::secp256k1::{rand, Keypair};
use bitcoin::{Amount, OutPoint, Transaction};
use futures::{stream, StreamExt, TryStreamExt};
use tracing::{debug, error, info, warn};

use ark::{ServerVtxo, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::arkoor::ArkoorDestination;
use ark::vtxo::Full;
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::tree::signed::{LeafVtxoCosignContext, UnlockPreimage};
use ark::tree::signed::builder::SignedTreeBuilder;
use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef, P2TR_DUST};
use bitcoin_ext::bdk::{WalletExt, WithGuaranteedChange};

use crate::database::vtxopool::PoolVtxo;
use crate::database::lightning_credit::FailureCredit;
use crate::database::htlc_vtxo::{self, HtlcDirection};
use crate::database::tree::VtxoTreeUpdate;
use crate::wallet::BdkWalletExt;
use crate::{database, telemetry, Server, SECP};
use crate::nursery::NurseryTxKind;


/// Type used to express a vtxo issuance target for the [VtxoPool]
///
/// The string representation is `"<amount>:<count>"`, for example
/// `"10000sat:50"` or `"0.01 btc:30"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VtxoTarget {
	pub amount: Amount,
	pub count: usize,
}

impl fmt::Display for VtxoTarget {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}:{}", self.amount, self.count)
	}
}

impl str::FromStr for VtxoTarget {
	type Err = &'static str;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut parts = s.split(":");
		Ok(VtxoTarget {
			amount: parts.next().unwrap().parse().map_err(|_| "invalid amount")?,
			count: parts.next().ok_or("invalid vtxo target format")?
				.parse().map_err(|_| "invalid count")?,
		})
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	/// Keep this many spendable on-chain sats for offboards and rounds.
	/// This limits automatic pool issuance, not user withdrawals.
	#[serde(default)]
	pub onchain_reserve_sat: u64,
	/// the amounts to create vtxos in
	///
	/// The string representation of the elements is `"<amount>:<count>"`,
	/// for example `["10000sat:50", "0.01 btc:30"]`.
	#[serde(with = "crate::utils::serde::string::vec")]
	pub vtxo_targets: Vec<VtxoTarget>,
	/// below what percentage of the target should we issue more vtxos
	pub vtxo_target_issue_threshold: u8,
	/// number of blocks for the vtxo lifetime
	pub vtxo_lifetime: BlockDelta,
	/// number of blocks before their expiry to discard vtxos
	pub vtxo_pre_expiry: BlockDelta,
	/// maximum arkoor depth to keep change until
	#[serde(alias = "vtxo_max_arkoor_depth")]
	pub max_vtxo_exit_depth: u16,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			onchain_reserve_sat: 0,
			vtxo_targets: Vec::new(),
			vtxo_target_issue_threshold: 80,
			vtxo_lifetime: BlockDelta::new(144 * 3),
			vtxo_pre_expiry: BlockDelta::new(144),
			// The server refuses to cosign arkoors past `max_vtxo_exit_depth`
			// in the top-level config, which is higher. This field here is
			// only for the pool of VTXO.
			max_vtxo_exit_depth: 50,
		}
	}
}

impl Config {
	/// The lifetime we want for the ephemeral keys on the VTXOs
	///
	/// We take double the created VTXO lifetime.
	fn vtxo_key_lifetime(&self) -> Duration {
		// take double as a buffer
		Duration::from_secs(60 * 10 * u64::from(self.vtxo_lifetime) * 2)
	}
}

struct Data {
	/// A quick manual index into the vtxo pool.
	/// We first order by expiry height and then by amount.
	pool: BTreeMap<BlockHeight, BTreeMap<Amount, Vec<VtxoId>>>,
}

impl Data {
	/// Insert a new vtxo into the pool data
	pub fn insert(&mut self, vtxo: VtxoId, expiry: BlockHeight, amount: Amount) {
		self.pool.entry(expiry).or_default().entry(amount).or_default().push(vtxo);
	}

	/// Shorthand to insert a series of vtxos at once
	pub fn insert_vtxos(&mut self, vtxos: &[PoolVtxo]) {
		for v in vtxos {
			self.insert(v.id(), v.expiry_height(), v.amount());
		}
	}

	pub async fn load_from_db(
		db: &database::Db,
		max_exit_depth: u16,
	) -> anyhow::Result<Self> {
		let stream = db.load_vtxopool().await?;
		tokio::pin!(stream);

		let mut ret = Data { pool: BTreeMap::new() };
		while let Some(v) = stream.try_next().await? {
			if v.exit_depth() > max_exit_depth {
				debug!("Not serving vtxo pool vtxo {}: exit depth {} exceeds \
					the maximum of {}", v.id(), v.exit_depth(), max_exit_depth,
				);
				continue;
			}
			ret.insert(v.id(), v.expiry_height(), v.amount());
		}

		telemetry::set_vtxo_pool_metrics(&ret.pool);

		Ok(ret)
	}

	/// Tally the total number of vtxos in the pool
	#[cfg(any(debug_assertions, test))]
	fn len(&self) -> usize {
		let mut len = 0;
		for (_, map) in &self.pool {
			for (_, vec) in map {
				len += vec.len();
			}
		}
		len
	}

	/// Tally the number of vtxos we have for the given amount
	pub fn count_amount(&self, amount: Amount) -> usize {
		let mut count = 0;
		for (_, map) in &self.pool {
			count += map.get(&amount).map(|v| v.len()).unwrap_or(0);
		}
		count
	}

	/// Prune the data structure from empty vectors and maps
	fn prune(&mut self) {
		#[cfg(debug_assertions)]
		let before = self.len();

		self.pool.retain(|_, c| {
			c.retain(|_, c| !c.is_empty());
			!c.is_empty()
		});

		#[cfg(debug_assertions)]
		debug_assert_eq!(before, self.len());
	}

	/// Prune all vtxos expiring before or on the threshold.
	///
	/// Caller is responsible for updating telemetry afterwards.
	pub fn prune_expiring(&mut self, threshold: BlockHeight) {
		self.pool.retain(|expiration_height, _vtxo_map| {
			let prune = *expiration_height > threshold;
			if prune {
				slog!(VtxoBucketPruned, threshold, expiration_height: *expiration_height);
			}
			prune
		 });
	}

	/// Take inputs from the pool to match the required amount
	///
	/// Will always prioritize VTXOs that are closer to expiry.
	///
	/// Returns empty vector on failure.
	pub fn take_inputs(
		&mut self,
		required_amount: Amount,
		eligible: impl Fn(&VtxoId) -> bool,
	) -> Vec<(VtxoId, BlockHeight, Amount)> {
		// The strategy here is to always prioritize expiry.
		// For each expiry "bucket", pick the highest amount if the
		// required amount exceeds it, otherwise pick the smallest amount
		// larger than the required amount.
		//
		// This means that for 700, we won't pick 500 + 200, but just 1000.
		//
		// This also means that if we only have a some small ones at the earliest
		// height and larger ones at further heights, we'll pick all the small ones
		// before we move up to the next height.

		let mut remaining = required_amount;
		let mut ret = Vec::<(VtxoId, BlockHeight, Amount)>::new();
		'main:
		for (height, for_height) in self.pool.iter_mut() {
			let mut amount_iter = for_height.iter_mut().rev()
				.filter(|(_, ids)| ids.iter().any(&eligible)).peekable();
			while let Some((amount, for_amount)) = amount_iter.next() {
				let next_amount = amount_iter.peek().map(|p| *p.0).unwrap_or(Amount::ZERO);
				while !for_amount.is_empty() && remaining > next_amount {
					let Some(index) = for_amount.iter().rposition(&eligible) else { break; };
					let id = for_amount.swap_remove(index);
					ret.push((id, *height, *amount));
					remaining = remaining.checked_sub(*amount).unwrap_or(Amount::ZERO);
					if remaining == Amount::ZERO {
						break 'main;
					}
				}
			}
		}

		if remaining != Amount::ZERO {
			// required amount too high, put everything back and return empty
			for (v, h, a) in ret {
				self.insert(v, h, a);
			}
			return vec![];
		}

		self.prune();

		ret
	}
}


fn update_all_bucket_metrics(data: &parking_lot::Mutex<Data>) {
	let data = data.lock();
	telemetry::set_vtxo_pool_metrics(&data.pool);
}

/// Checks that change outputs contains at most one non-dust and one dust output
///
/// Returns change outputs with non-dust first and dust last
fn check_change_outputs(change: Vec<Vtxo<Full>>) -> anyhow::Result<Vec<Vtxo<Full>>> {
	let (change, dust_change) = change.into_iter()
		.partition::<Vec<_>, _>(|v| v.amount() >= P2TR_DUST);
	if change.len() > 1 {
		error!("The vtxo pool returned more than one non-dust change output");
		bail!("More than one non-dust change output");
	};
	if dust_change.len() > 1 {
		error!("The vtxo pool returned more than one dust change output");
		bail!("More than one dust change output");
	};
	if !change.is_empty() && !dust_change.is_empty() {
		debug!("The vtxo pool produced both non-dust and dust \
			change outputs, dust one will be dropped from the pool");
	}

	Ok(change.into_iter().chain(dust_change.into_iter()).collect())
}

/// Both deadlines must leave room for the complete unilateral recovery path.
fn pool_receive_has_headroom(
	tip: u32, output_depth: u32, exit_delta: u32, htlc_delta: u32,
	htlc_expiry: u32, vtxo_expiry: u32,
) -> bool {
	tip.checked_add(output_depth).and_then(|h| h.checked_add(exit_delta))
		.and_then(|h| h.checked_add(htlc_delta)).and_then(|h| h.checked_add(12))
		.is_some_and(|deadline| deadline < htlc_expiry && deadline < vtxo_expiry)
}

pub struct VtxoPool {
	config: Config,
	started: AtomicBool,

	data: Arc<parking_lot::Mutex<Data>>,
}

impl VtxoPool {
	/// Create a VTXO from pool
	///
	/// The caller is responsible for requesting arkoor preparation
	/// with correct destination: [`VtxoPolicy::ServerHtlcRecv`]
	#[tracing::instrument(skip(self, srv, credit))]
	async fn prepare_arkoor(
		&self,
		srv: &Server,
		dest: ArkoorDestination,
		inputs: &[(VtxoId, BlockHeight, Amount)],
		credit: Option<&FailureCredit>,
		pubkey_payment: bool,
	) -> anyhow::Result<Vec<Vtxo<Full>>> {
		let input_ids = inputs.iter().map(|v| v.0).collect::<Vec<_>>();
		let mut input_vtxos = srv.db.read(async |t| t.get_pool_vtxos_by_ids(&input_ids).await).await?;

		// We sort the vtxos in order of increasing amounts
		// This ensures we spend the smallest vtxos first and
		// we don't have any vtxo that serves as change
		input_vtxos.sort_by(|v1, v2| v1.amount().cmp(&v2.amount()));

		// Validate that the inputs are still usable and unlocked
		let _vtxo_guard = srv.vtxos_in_flux.try_lock(&input_ids).map_err(|e| {
			anyhow::anyhow!("some VTXO is already locked by another process: {}", e.id)
		})?;

		let keys = {
			let mut ret = Vec::with_capacity(input_vtxos.len());
			for v in &input_vtxos {
				ret.push(srv.get_ephemeral_cosign_key(v.user_pubkey()).await
					.with_context(|| format!(
						"failed to fetch ephemeral keys for vtxo {}: {}",
						v.id(), v.user_pubkey(),
					))?
				);
			}
			ret
		};

		let change_key = srv.generate_ephemeral_cosign_key(self.config.vtxo_key_lifetime()).await?;
		let full_inputs = input_vtxos.into_iter().map(|v| v.into_inner()).collect();
		let change_policy = VtxoPolicy::new_pubkey(change_key.public_key());
		let pubkey_payment = pubkey_payment || credit.is_some();
		let (builder, _reserve) = if pubkey_payment {
			ArkoorPackageBuilder::new_funded_payment(full_inputs, dest.clone(), change_policy)
		} else {
			ArkoorPackageBuilder::new_funded_lightning_receive(full_inputs, dest.clone(), change_policy)
		}.context("funded pool allocation failed")?;
		let builder = builder.cosign_both(&keys, srv.server_key.leak_ref())
			.context("error cosigning arkoor")?;

		let signed_vtxs = builder.signed_virtual_transactions();
		let internal_vtxos = builder.build_signed_internal_vtxos();
		let input_spend_info = builder.input_spend_info().collect::<Vec<_>>();
		let output_vtxos = builder.build_signed_vtxos();

		let (sent, change) = output_vtxos.into_iter()
			.partition::<Vec<_>, _>(|v| *v.policy() == dest.policy);

		for vtxo in &sent {
			if pubkey_payment {
				ensure!(matches!(vtxo.policy(), VtxoPolicy::Pubkey(_)), "invalid reimbursement destination");
				ensure!(pool_receive_has_headroom(srv.chain_tip().height.to_u32(),
					u32::from(vtxo.exit_depth()), u32::from(vtxo.exit_delta().to_u16()),
					0, vtxo.expiry_height().to_u32(), vtxo.expiry_height().to_u32()),
					"reimbursement has insufficient recovery headroom");
				continue;
			}
			let VtxoPolicy::ServerHtlcRecv(p) = vtxo.policy() else { bail!("invalid pool destination"); };
			ensure!(pool_receive_has_headroom(srv.chain_tip().height.to_u32(),
				u32::from(vtxo.exit_depth()), u32::from(vtxo.exit_delta().to_u16()),
				u32::from(p.htlc_expiry_delta.to_u16()), p.htlc_expiry.to_u32(),
				vtxo.expiry_height().to_u32()), "pool HTLC has insufficient recovery headroom");
		}
		let change = check_change_outputs(change)?;

		let update = VtxoTreeUpdate::new()
			.upsert_signed_tx(signed_vtxs)
			.insert_oor_spent_vtxos(internal_vtxos)
			.insert_unspent_vtxos(
				sent.iter().cloned().map(ServerVtxo::from),
				if credit.is_some() { database::SpendState::Spendable }
				else { database::SpendState::HtlcRecvUnclaimed },
			)
			.insert_unspent_vtxos(
				change.iter().cloned().map(ServerVtxo::from),
				database::SpendState::Pool,
			)
			.mark_vtxos_oor_spent(input_spend_info);

		// An htlc-recv vtxo exists as soon as we hand out our signatures,
		// so its htlc_vtxo row is written together with the vtxo itself.
		let htlc_recvs = sent.iter()
			.filter_map(|v| match v.policy() {
				VtxoPolicy::ServerHtlcRecv(p) =>
					Some((v.id(), p.payment_hash, p.htlc_expiry)),
				VtxoPolicy::ServerHtlcRecv_v0(p) =>
					Some((v.id(), p.payment_hash, p.htlc_expiry)),
				_ => None,
			})
			.collect::<Vec<_>>();

		let delivery = srv.db.write(async |t| {
			t.execute_vtxo_tree_update(update).await?;
			let delivery = if let Some(credit) = credit {
				// Persist the exact signed result in the SAME transaction as the
				// pool spend. A retry after a lost response returns these bytes.
				t.complete_lightning_failure_credit(credit, &sent).await?
			} else { None };
			htlc_vtxo::create_htlc_vtxos(&t, &htlc_recvs, HtlcDirection::Outgoing).await?;
			t.mark_vtxopool_vtxos_spent(inputs.iter().map(|v| v.0)).await
				.context("failed to mark vtxopool vtxos as spent")?;
			Ok(delivery)
		}).await?;
		if let (Some(cp), Some(mailbox)) = (delivery, credit.and_then(|c| c.legacy_mailbox)) {
			srv.mailbox_manager.notify(mailbox, cp);
		}

		for input in inputs {
			slog!(SpentPoolVtxo, vtxo: input.0, amount: input.2, destination: dest.clone());
		}

		// Forget the input keys now the vtxo has been arkoored to its new owner.
		for key in &keys {
			if let Err(e) = srv.drop_ephemeral_cosign_key(key.public_key()).await {
				warn!("Failed to drop ephemeral cosign key {} for arkoored pool vtxo: {:#}",
					key.public_key(), e);
			}
		}

		// We stored all change output VTXOs, but in the pool we only keep the
		// first one (nondust) to avoid later serving one whose ephemeral key was deleted.
		// Change past the arkoor depth cap is not kept either; like dust
		// change, it is swept after expiry.
		if let Some(change) = change.first() {
			if change.exit_depth() > self.config.max_vtxo_exit_depth {
				info!("Dropping vtxo pool change {} from the pool: exit depth {} \
					exceeds the maximum of {}",
					change.id(), change.exit_depth(), self.config.max_vtxo_exit_depth,
				);
			} else {
				let new = PoolVtxo::new(change.clone());
				if let Err(e) = srv.db.write(async |t| t.store_vtxopool_vtxo(&new).await).await {
					// don't abort for this
					warn!("Failed to store change from a vtxopool spend: {:#}", e);
				} else {
					self.data.lock().insert_vtxos(&[new.clone()]);
					slog!(ChangePoolVtxo, vtxo: new.id(), amount: new.amount());
				}
			}
		}

		Ok(sent)
	}

	#[tracing::instrument(skip(self, srv))]
	pub async fn send_arkoor(
		&self,
		srv: &Server,
		dest: ArkoorDestination,
	) -> anyhow::Result<Vec<Vtxo<Full>>> {
		self.send_funded_arkoor(srv, dest, None, false).await
	}

	/// Pay an ordinary Ark coin from pool liquidity.
	pub async fn pay_to_pubkey(
		&self, srv: &Server, dest: ArkoorDestination,
	) -> anyhow::Result<Vec<Vtxo<Full>>> {
		ensure!(matches!(&dest.policy, VtxoPolicy::Pubkey(_)), "tab return destination is not a pubkey");
		self.send_funded_arkoor(srv, dest, None, true).await
	}

	pub(crate) async fn reimburse(
		&self, srv: &Server, credit: &FailureCredit,
	) -> anyhow::Result<Vec<Vtxo<Full>>> {
		if let Some(paid) = &credit.paid { return Ok(paid.clone()); }
		ensure!(credit.inline_reimbursement || credit.legacy_mailbox.is_some(),
			"legacy reimbursement awaits a delivery mailbox");
		let refund = srv.db.read(async |t| t.get_user_vtxos_by_id(&[credit.refund_id]).await).await?;
		let policy = refund.first().context("missing refund VTXO")?.vtxo.policy().clone();
		ensure!(matches!(&policy, VtxoPolicy::Pubkey(_)), "refund recipient is not a pubkey");
		self.send_funded_arkoor(srv, ArkoorDestination {
			total_amount: credit.amount, policy,
		}, Some(credit), false).await
	}

	async fn send_funded_arkoor(
		&self, srv: &Server, dest: ArkoorDestination, credit: Option<&FailureCredit>,
		pubkey_payment: bool,
	) -> anyhow::Result<Vec<Vtxo<Full>>> {
		ensure!(matches!(&dest.policy, VtxoPolicy::ServerHtlcRecv(_))
			|| ((credit.is_some() || pubkey_payment) && matches!(&dest.policy, VtxoPolicy::Pubkey(_))),
			"invalid pool destination");
		// Snapshot candidates without holding the mutex across database I/O.
		let ids = self.data.lock().pool.values().flat_map(|bucket| bucket.values())
			.flatten().copied().collect::<Vec<_>>();
		let candidates = srv.db.read(async |t| t.get_pool_vtxos_by_ids(&ids).await).await?;
		let tip = srv.chain_tip().height.to_u32();
		let eligible = candidates.iter().filter(|v| {
			let (htlc_delta, expiry) = match &dest.policy {
				VtxoPolicy::ServerHtlcRecv(p) => (u32::from(p.htlc_expiry_delta.to_u16()), p.htlc_expiry.to_u32()),
				_ => (0, v.expiry_height().to_u32()),
			};
			// A funded receive adds a checkpoint and an HTLC transaction.
			pool_receive_has_headroom(tip, u32::from(v.exit_depth()) + 2,
				u32::from(v.exit_delta().to_u16()), htlc_delta,
				expiry, v.expiry_height().to_u32())
		}).map(|v| v.id()).collect::<HashSet<_>>();
		let inputs = {
			let mut data = self.data.lock();
			let mut count = 1u64;
			loop {
				let reserve = ark::exit_policy::paperclip_funding().per_transaction()
					.checked_mul(3 * count).context("pool reserve overflow")?;
				let required = dest.total_amount.checked_add(reserve).context("pool amount overflow")?;
				let inputs = data.take_inputs(required, |id| eligible.contains(id));
				if inputs.is_empty() || inputs.len() as u64 <= count { break inputs; }
				count = inputs.len() as u64;
				for (id, height, amount) in inputs { data.insert(id, height, amount); }
			}
		};
		if inputs.is_empty() {
			bail!("no Ark receive liquidity with sufficient recovery time; retry after pool replenishment");
		}

		// we try, but if we fail, we place back the inputs
		match self.prepare_arkoor(srv, dest, &inputs, credit, pubkey_payment).await {
			Ok(v) => {
				update_all_bucket_metrics(&self.data);
				Ok(v)
			},
			Err(e) => {
				let mut guard = self.data.lock();
				for (v, h, a) in inputs {
					guard.insert(v, h, a);
				}
				Err(e)
			},
		}
	}

	pub async fn new(config: Config, db: &database::Db) -> anyhow::Result<VtxoPool> {
		let data = Data::load_from_db(db, config.max_vtxo_exit_depth).await?;

		Ok(VtxoPool {
			config,
			started: false.into(),
			data: Arc::new(parking_lot::Mutex::new(data)),
		})
	}

	pub fn start(
		&self,
		srv: Arc<Server>,
		sync_height_rx: tokio::sync::watch::Receiver<BlockRef>,
	) {
		if self.started.swap(true, atomic::Ordering::Relaxed) {
			return;
		}

		let proc = Process {
			srv: srv.clone(),
			config: self.config.clone(),
			data: self.data.clone(),
			sync_height_rx,
		};
		tokio::spawn(proc.run());
	}
}

struct Process {
	srv: Arc<Server>,
	config: Config,

	data: Arc<parking_lot::Mutex<Data>>,

	/// Issuance occurs after a sync has completed
	sync_height_rx: tokio::sync::watch::Receiver<BlockRef>,
}

impl Process {
	#[tracing::instrument(skip(self))]
	async fn issue_vtxos(&self, issuance: Vec<(Amount, usize)>) -> anyhow::Result<()> {
		let nb_vtxos = issuance.iter().map(|i| i.1).sum();
		if nb_vtxos < 2 {
			warn!("Ignoring vtxopool issuance request for 1 VTXO");
			return Ok(());
		}

		// Gate the tx-committing path on shutdown: we don't want to broadcast
		// an issuance funding tx on the way out. Past this point the critical
		// worker guard keeps shutdown waiting for the wallet commit and
		// broadcast to finish, so this is the last chance to bail out cleanly.
		if self.srv.rtmgr.shutdown_requested() {
			info!("Shutdown pending; skipping VTXO pool issuance");
			return Ok(());
		}

		let (requests, leaf_keys) = {
			let mut leaf_keys = Vec::with_capacity(nb_vtxos);
			let mut requests = Vec::with_capacity(nb_vtxos);
			for (amount, count) in issuance {
				let keys = stream::iter(0..count).map(|_| {
					self.srv.generate_ephemeral_cosign_key(self.config.vtxo_key_lifetime())
				})
				.buffer_unordered(10)
				.collect::<Vec<_>>().await
				.into_iter().collect::<Result<Vec<_>, _>>()?;

				requests.extend(keys.iter().map(|key| {
					VtxoRequest {
						policy: VtxoPolicy::new_pubkey(key.public_key()),
						amount: amount,
					}
				}));
				leaf_keys.extend(keys);

				slog!(PreparingPoolIssuance, amount, count);
			}
			(requests, leaf_keys)
		};

		let expiry = self.srv.chain_tip().height + self.config.vtxo_lifetime;

		let cosign_key = Keypair::new(&*SECP, &mut rand::thread_rng());
		let server_cosign_key = self.srv.generate_ephemeral_cosign_key(
			Duration::from_secs(600),
		).await?;
		let unlock_preimage = rand::random::<UnlockPreimage>();

		let builder = SignedTreeBuilder::new(
			requests.iter().cloned(),
			cosign_key.public_key(),
			unlock_preimage,
			expiry,
			self.srv.server_pubkey,
			server_cosign_key.public_key(),
			self.srv.config.vtxo_exit_delta,
		).context("builder error")?
			.with_exit_funding(ark::exit_policy::paperclip_funding()).context("pool recovery funding")?;

		let fee_rate = self.srv.fee_estimator.slow();

		let funding_txout = builder.funding_txout();

		let txout = funding_txout.clone();
		let reserve = Amount::from_sat(self.config.onchain_reserve_sat);
		let (mut wallet, funding_psbt) = self.srv.rounds_wallet.build_blocking(
			move |wallet| {
				let selection = WithGuaranteedChange(SingleRandomDraw);
				let psbt = wallet.build_tx_at_chunk_feerate(selection, fee_rate, |b| {
					b.add_recipient(txout.script_pubkey.clone(), txout.value);
					Ok(())
				}).context("failed to build signed tree funding tx")?;
				let cost = txout.value.checked_add(psbt.fee().context("pool funding fee")?)
					.context("pool funding cost overflow")?;
				if wallet.available_balance().checked_sub(cost).is_none_or(|remaining| remaining < reserve) {
					wallet.mark_output_keys_unused(&psbt.unsigned_tx);
					anyhow::bail!("pool issuance deferred to preserve {} sats of on-chain payout liquidity", reserve.to_sat());
				}
				Ok(psbt)
			},
		).await?;

		let funding_txid = funding_psbt.unsigned_tx.compute_txid();
		let total_amount = builder.total_required_value();
		slog!(PreparingPoolIssuanceTx, txid: funding_txid, total_count: requests.len(), total_amount);
		let vout = funding_psbt.unsigned_tx.output.iter().position(|o| *o == funding_txout)
			.context("wallet send didn't include our txout")?;
		let utxo = OutPoint::new(funding_txid, vout as u32);

		let builder = builder
			.set_utxo(utxo)
			.generate_user_nonces(&cosign_key);

		let cosign = self.srv.cosign_vtxo_tree(
			requests.iter().cloned(),
			cosign_key.public_key(),
			unlock_preimage,
			server_cosign_key.public_key(),
			expiry,
			utxo,
			builder.user_pub_nonces().to_vec(),
		).await.context("server error cosigning vtxo tree")?;
		builder.verify_cosign_response(&cosign).context("invalid server tree cosign")?;

		let tree = builder.build_tree(&cosign, &cosign_key)
			.context("error finishing signed tree with cosign")?;
		let tree = tree.into_cached_tree();

		// finish VTXOs by cosigning leaves
		// we rely here on the order of the vtxos being identical to the order of the requests
		let mut vtxos = tree.output_vtxos().collect::<Vec<_>>();
		for (vtxo, leaf_key) in vtxos.iter_mut().zip(leaf_keys.iter()) {
			let (ctx, req) = LeafVtxoCosignContext::new(vtxo, &funding_psbt.unsigned_tx, &leaf_key)
				.context("pool vtxo is not a hArk leaf")?;
			let resp = self.srv.cosign_hashlocked_leaf(&req, vtxo, &funding_psbt.unsigned_tx)?;
			ensure!(ctx.finalize(vtxo, resp), "failed to finalize leaf vtxo");
			ensure!(vtxo.provide_unlock_preimage(unlock_preimage), "invalid unlock preimage");
		}

		// finish and broadcast the tx
		let tx = wallet.finish_tx(funding_psbt).context("error finishing tree funding tx")?;

		// Create the vtxos and virtual transactions in the database
		// before committing the funding tx to the wallet. The funding tx
		// is handed to the nursery in the same db tx, so that once the
		// wallet considers its inputs spent, broadcast follow-up is
		// guaranteed even if a later step fails.
		let confirm_target = self.srv.nursery_confirm_target();
		let update = VtxoTreeUpdate::new()
			.upsert_funding_tx(&tx)
			.upsert_signed_tx(tree.internal_node_txs().iter().cloned())
			.upsert_unsigned_tx(tree.unsigned_leaf_txs().iter().map(Transaction::compute_txid))
			.insert_oor_spent_vtxos(tree.internal_vtxos())
			.insert_unspent_vtxos(
				tree.output_vtxos().map(ServerVtxo::from),
				database::SpendState::Pool,
			);
		self.srv.db.write(async |t| {
			t.execute_vtxo_tree_update(update).await?;
			t.upsert_nursery_tx(&tx, NurseryTxKind::VtxoPool, confirm_target).await
		}).await?;

		// Here we commit the transaction to the wallet
		wallet.commit_tx(&tx);
		wallet.persist().await.context("error persisting wallet after signing tree funding tx")?;
		drop(wallet);
		let txid = tx.compute_txid();

		// store the new vtxos
		let pool_vtxos = vtxos.into_iter()
			.map(|v| PoolVtxo::new(v)).collect::<Vec<_>>();
		self.srv.db.write(async |t| {
			t.add_funding_vtxos_to_frontier(txid, None).await
				.context("failed to add vtxopool vtxos to frontier")?;
			t.store_vtxopool_vtxos(&pool_vtxos).await.context("storing pool vtxos")?;
			Ok(())
		}).await?;
		self.data.lock().insert_vtxos(&pool_vtxos);
		update_all_bucket_metrics(&self.data);

		slog!(FinishedPoolIssuance, txid: funding_txid, total_count: requests.len(), total_amount);

		self.srv.tx_nursery.broadcast_tx(tx, NurseryTxKind::VtxoPool, confirm_target).await
			.with_context(|| format!("error broadcasting vtxopool issuance tx {}", txid))?;

		Ok(())
	}

	fn calculate_required_issuance(
		&self,
		expiry_threshold: BlockHeight,
	) -> (Vec<(Amount, usize)>, bool) {
		info!("Checking vtxo pool issuance with expiry threshold {:?}", expiry_threshold);
		let mut data = self.data.lock();
		data.prune_expiring(expiry_threshold);

		let mut must_issue = false;
		let mut issuance = Vec::with_capacity(self.config.vtxo_targets.len());
		for target in &self.config.vtxo_targets {
			let count = data.count_amount(target.amount);

			if let Some(issue) = target.count.checked_sub(count) {
				issuance.push((target.amount, issue));
			}

			if count * 100 < target.count * self.config.vtxo_target_issue_threshold as usize {
				slog!(MustIssueVtxos, target_amount: target.amount,
					target_count: target.count, current_count: count);
				must_issue = true;
			}
		}
		(issuance, must_issue)
	}

	#[tracing::instrument(
		name = "vtxo_pool_issuance"
		skip(self),
		fields(otel.kind = "server")
	)]
	async fn check_maybe_issue_vtxos(&self) -> anyhow::Result<()> {
		let tip = self.srv.chain_tip().height;
		// Replenish before outputs become unusable for safe Lightning receives.
		let recovery_window = u32::from(self.config.max_vtxo_exit_depth) + 2
			+ u32::from(self.srv.config.vtxo_exit_delta.to_u16())
			+ u32::from(self.srv.config.htlc_expiry_delta.to_u16()) + 12;
		let window = recovery_window.max(u32::from(self.config.vtxo_pre_expiry.to_u16()));
		ensure!(window < u32::from(self.config.vtxo_lifetime.to_u16()),
			"pool lifetime must exceed receive recovery and pre-expiry windows");
		let threshold = BlockHeight::new(tip.to_u32().checked_add(window)
			.context("pool refresh threshold overflow")?);

		// NB this needs to be a different method because otherwise borrowck complains
		// about the mutex not being send even if we add a manual `drop()`
		let (issuance, must_issue) = self.calculate_required_issuance(threshold);
		update_all_bucket_metrics(&self.data);

		if must_issue {
			self.issue_vtxos(issuance).await?;
		}

		Ok(())
	}

	async fn run(mut self) {
		let _worker = self.srv.rtmgr.spawn_critical("VtxoPool");

		loop {
			// Don't issue until we are fully caught up: the wallet only holds
			// every confirmed utxo once we reach the tip. Comparing the whole
			// block ref also holds off on an equal-height reorg, where the tip
			// has moved to another block of the same height.
			let synced = *self.sync_height_rx.borrow() == self.srv.chain_tip();
			if synced {
				if let Err(e) = self.check_maybe_issue_vtxos().await {
					error!("Error from VTXO pool: {:#}", e);
				}
				if let Err(e) = self.srv.retry_legacy_lightning_credits().await {
					warn!("Legacy Lightning reimbursement retry: {e:#}");
				}
			}

			tokio::select! {
				_ = tokio::time::sleep(Duration::from_secs(30)) => {},
				res = self.sync_height_rx.changed() => {
					if res.is_err() {
						info!("Sync height watcher closed. Exiting VtxoPool...");
						return;
					}
				},
				_ = self.srv.rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting VtxoPool...");
					return;
				},
			}
		}
	}
}

#[cfg(test)]
mod test {
	use bitcoin::Txid;
	use bitcoin::hashes::Hash;

	use super::*;

	fn id(i: u32) -> VtxoId {
		OutPoint::new(Txid::all_zeros(), i).into()
	}

	fn sat(v: u64) -> Amount {
		Amount::from_sat(v)
	}

	fn h(v: u32) -> BlockHeight {
		BlockHeight::new(v)
	}

	/// assert a given selection
	#[track_caller]
	fn assert_sel(
		selection: &[(VtxoId, BlockHeight, Amount)],
		expected: &[(BlockHeight, Amount)],
	) {
		let mut sel = selection.to_vec();
		for (height, amount) in expected {
			if let Some(i) = sel.iter().position(|(_, h, a)| h == height && a == amount) {
				sel.swap_remove(i);
			} else {
				panic!("missing item: ({}, {}), selection: {:?}",
					height, amount.to_sat(), selection,
				);
			}
		}
		if !sel.is_empty() {
			panic!("additional items: {:?}", sel);
		}
	}

	#[test]
	fn test_receive_recovery_headroom() {
		// Reproduce the expired-soon pool output from the external receive failure.
		assert!(!pool_receive_has_headroom(975216, 4, 144, 40, 975432, 975373));
		assert!(pool_receive_has_headroom(975216, 4, 144, 40, 975432, 975648));
		assert!(!pool_receive_has_headroom(100, 4, 144, 40, 300, 500));
		assert!(!pool_receive_has_headroom(100, 4, 144, 40, 500, 300));
		assert!(!pool_receive_has_headroom(u32::MAX, 4, 144, 40, u32::MAX, u32::MAX));
	}

	#[test]
	fn test_receive_selection_skips_ineligible_and_restores_on_failure() {
		let mut data = Data { pool: BTreeMap::new() };
		data.insert(id(1), h(100), sat(300000));
		data.insert(id(2), h(200), sat(300000));
		let selected = data.take_inputs(sat(16000), |v| *v == id(2));
		assert_eq!(selected, vec![(id(2), h(200), sat(300000))]);
		data.insert(id(2), h(200), sat(300000));
		assert!(data.take_inputs(sat(400000), |v| *v == id(2)).is_empty());
		assert_eq!(data.len(), 2);
		assert!(data.take_inputs(sat(1), |_| false).is_empty());
		assert_eq!(data.len(), 2);
		// An ineligible smaller denomination must not hide an eligible larger one.
		data.insert(id(3), h(200), sat(100000));
		assert_eq!(data.take_inputs(sat(10000), |v| *v == id(2)),
			vec![(id(2), h(200), sat(300000))]);
	}

	#[test]
	fn test_vtxo_selection() {
		let vtxos = [
			(id(1), h(100), sat(1000)),
			(id(2), h(100), sat(1000)),
			(id(3), h(100), sat(2000)),
			(id(4), h(100), sat(2000)),
			(id(5), h(100), sat(3000)),
			(id(6), h(100), sat(3000)),
			(id(11), h(110), sat(1000)),
			(id(12), h(110), sat(1000)),
			(id(13), h(110), sat(2000)),
			(id(14), h(110), sat(2000)),
			(id(15), h(110), sat(3000)),
			(id(16), h(110), sat(3000)),
			(id(17), h(120), sat(1000)),
			(id(18), h(120), sat(1000)),
		];
		let len = vtxos.len();

		let mut data = Data { pool: BTreeMap::new() };
		for (v, h, a) in vtxos {
			data.insert(v, h, a);
		}
		assert_eq!(data.len(), len);

		let sel = data.take_inputs(sat(500), |_| true);
		assert_sel(&sel, &[(h(100), sat(1000))]);

		let sel = data.take_inputs(sat(2500), |_| true);
		assert_sel(&sel, &[(h(100), sat(3000))]);

		let sel = data.take_inputs(sat(1000), |_| true);
		assert_sel(&sel, &[(h(100), sat(1000))]);

		// the 2x 1000 at height 100 are already used
		let sel = data.take_inputs(sat(900), |_| true);
		assert_sel(&sel, &[(h(100), sat(2000))]);

		// left at 100: 3000, 2000
		let sel = data.take_inputs(sat(5500), |_| true);
		assert_sel(&sel, &[(h(100), sat(2000)), (h(100), sat(3000)), (h(110), sat(1000))]);

		let len = data.len();
		let sel = data.take_inputs(Amount::MAX_MONEY, |_| true);
		assert!(sel.is_empty());
		assert_eq!(data.len(), len);
	}

}
