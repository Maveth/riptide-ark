//! Checks for a fully signed, funded recovery path under a specified relay policy.
//! These checks are admission checks, not a promise of future block inclusion.

use bitcoin::{Amount, FeeRate, Transaction, TxOut};
use bitcoin_ext::{BlockDelta, BlockHeight};

use crate::{Vtxo, VtxoPolicy};
pub use bitcoin_ext::fee::ExitFormat;
use crate::vtxo::Full;
use crate::lightning::Preimage;

#[derive(Debug, Clone, Copy)]
pub struct FundedExitPolicy {
	pub minimum_relay: FeeRate,
	pub dust_relay: FeeRate,
	/// Additional blocks beyond one confirmation per ancestor and the CSV delay.
	pub confirmation_margin: BlockDelta,
	/// Reserve for the final claim, deducted from the recovered output.
	pub claim_fee: Amount,
}

pub const PAPERCLIP_EXIT_PROFILE: u32 = 2;

// Update path. The live number is still 2. `docs/bark-like-recovery.md` says
// not to repurpose profile 2, and not to use the legacy-v3 encoding as a new
// protocol identity. We reused 2 and carried the new shape in `zero_fee_board`.
// Checked 2026-11-11: profile 1 is only the old private regtest note in
// VALIDATION.md. Profile 2, on published Paperclip, is the funded StandardV2
// exit. Decided 2026-11-11: this server does not add an old-shaped round.
// Nobody here holds that shape. The next handshake is profile 3, and both this
// wallet and this server must require it. A 2 on either side is a different
// Ark and is refused. Do not ship 3 on one side alone.
// The transaction inside profile 2 changed.
//
// Older wallets build StandardV2. A board is a 1,000 sat anchor plus a 1,000
// sat miner fee (`legacy_standard_funding`). A transfer, when the server
// advertises small anchors, is a 330 sat anchor plus a 1,000 sat miner fee
// (`legacy_small_anchor_funding`). `BoardCosignRequest.zero_fee_board` is
// unset, so this server signs that older board.
//
// This wallet builds a version-3 parent with miner fee 0 and one zero-value
// anchor (`paperclip_funding`). It sets `zero_fee_board` and the server signs
// that board. Rounds on this server use the same zero-fee shape. An older
// wallet can board and pay here, and it can exit its own coin. It cannot join
// one of these rounds, because it still requires the 1,000 plus 1,000 tree.
//
// Spending follows the coin, not the server. A zero-fee coin stays zero-fee.
// A 1,000 plus 1,000 coin stays on `legacy_standard_funding`, which an older
// server still accepts as its own profile. Our smaller transfer budget is
// `small_anchor_transfer_funding`: a 330 sat anchor and a 100 sat miner fee.
// Paperclip main also added `economical_transfer_funding`, 330 plus 198, as an
// opt-in ordinary transfer. This server accepts that shape too.

/// Miner fee for a recovery transaction that pays its own fee.
/// About 1,000 vB at this node's 0.1 sat/vB relay floor.
pub const RECOVERY_MINER_FEE: Amount = Amount::from_sat(100);

/// Version-3 parent with miner fee 0 and one zero-value pay-to-anchor.
/// The child spends the anchor. This is the shape the template whitelist keeps.
pub fn paperclip_funding() -> crate::tree::signed::TreeExitFunding {
	crate::tree::signed::TreeExitFunding::new(Amount::ZERO, Amount::ZERO)
		.expect("zero-anchor profile is valid")
}

/// Ordinary-transfer budget for servers advertising small_anchor_transfers.
/// Retains the legacy miner-fee floor and encoding while reducing the standard
/// P2WSH anchor to its dust threshold at the supported 3 sat/vB dust policy.
/// Server capability negotiation is required before wallets use this budget.
pub fn small_anchor_transfer_funding() -> crate::tree::signed::TreeExitFunding {
	crate::tree::signed::TreeExitFunding::new(bitcoin_ext::P2TR_DUST, RECOVERY_MINER_FEE)
		.expect("constant funded transfer budget is valid")
		.with_format(bitcoin_ext::fee::ExitFormat::StandardV2)
}

/// Opt-in ordinary transfers: 330-sat anchor plus 198-sat miner fee.
/// Builders check the signed-size relay floor before any signature is made.
pub fn economical_transfer_funding() -> crate::tree::signed::TreeExitFunding {
	crate::tree::signed::TreeExitFunding::economical_transfer()
}

/// The profile older wallets still build: 1,000 sat anchor and 1,000 sat miner fee.
pub fn legacy_standard_funding() -> crate::tree::signed::TreeExitFunding {
	crate::tree::signed::TreeExitFunding::new(Amount::from_sat(1000), Amount::from_sat(1000))
		.expect("legacy standard profile is valid")
		.with_format(bitcoin_ext::fee::ExitFormat::StandardV2)
}

/// Older wallets that saw small-anchor transfers use a 330 sat anchor and a 1,000 sat miner fee.
pub fn legacy_small_anchor_funding() -> crate::tree::signed::TreeExitFunding {
	crate::tree::signed::TreeExitFunding::new(Amount::from_sat(330), Amount::from_sat(1000))
		.expect("legacy small-anchor profile is valid")
		.with_format(bitcoin_ext::fee::ExitFormat::StandardV2)
}

fn zero_value_anchor(output: &TxOut) -> bool {
	output.value == Amount::ZERO && output.script_pubkey == *bitcoin_ext::fee::P2A_SCRIPT
}

pub fn paperclip_policy() -> FundedExitPolicy {
	FundedExitPolicy {
		minimum_relay: FeeRate::from_sat_per_kwu(25),
		dust_relay: FeeRate::from_sat_per_kwu(750),
		confirmation_margin: BlockDelta::new(12),
		claim_fee: RECOVERY_MINER_FEE,
	}
}

impl FundedExitPolicy {
	/// Check an ordinary pubkey balance before accepting it as recoverable.
	/// HTLC recovery has extra conditions and needs separate checks.
	pub fn check(
		&self,
		vtxo: &Vtxo<Full>,
		funding: &Transaction,
		tip: BlockHeight,
	) -> Result<(), String> {
		if !matches!(vtxo.policy(), VtxoPolicy::Pubkey(..)) {
			return Err("funded recovery check only supports ordinary pubkey balances".into());
		}
		let deadline = self.recovery_deadline(vtxo, tip, u32::from(vtxo.exit_delta().to_u16()), None)?;
		self.check_path(vtxo, funding, deadline)
	}

	/// Check the user's outgoing HTLC refund path, including both timelocks.
	pub fn check_lightning_send(
		&self, vtxo: &Vtxo<Full>, funding: &Transaction, tip: BlockHeight,
	) -> Result<(), String> {
		let VtxoPolicy::ServerHtlcSend(policy) = vtxo.policy() else {
			return Err("expected a current outgoing Lightning HTLC".into());
		};
		let delay = u32::from(vtxo.exit_delta().to_u16()).checked_mul(2)
			.filter(|d| *d <= u32::from(u16::MAX)).ok_or("HTLC refund delay overflow")?;
		if policy.htlc_expiry.to_u32() >= 500_000_000 {
			return Err("HTLC expiry must be a block height".into());
		}
		let deadline = self.recovery_deadline(vtxo, tip, delay, Some(policy.htlc_expiry))?;
		self.check_path(vtxo, funding, deadline)
	}

	/// Check the entire incoming recovery path before revealing the preimage.
	/// The user must confirm a claim before the server's absolute HTLC timeout.
	pub fn check_lightning_receive(
		&self, vtxo: &Vtxo<Full>, funding: &Transaction, tip: BlockHeight, preimage: &Preimage,
	) -> Result<(), String> {
		let VtxoPolicy::ServerHtlcRecv(policy) = vtxo.policy() else {
			return Err("expected a current incoming Lightning HTLC".into());
		};
		if preimage.compute_payment_hash() != policy.payment_hash {
			return Err("preimage does not match incoming HTLC".into());
		}
		let delay = u32::from(vtxo.exit_delta().to_u16())
			.checked_add(u32::from(policy.htlc_expiry_delta.to_u16()))
			.filter(|d| *d <= u32::from(u16::MAX)).ok_or("HTLC claim delay overflow")?;
		let deadline = self.recovery_deadline(vtxo, tip, delay, None)?;
		if policy.htlc_expiry.to_u32() >= 500_000_000 || deadline >= policy.htlc_expiry.to_u32() {
			return Err("insufficient time to claim before the incoming HTLC timeout".into());
		}
		self.check_path(vtxo, funding, deadline)
	}

	fn recovery_deadline(
		&self, vtxo: &Vtxo<Full>, tip: BlockHeight, delay: u32, absolute: Option<BlockHeight>,
	) -> Result<u32, String> {
		if self.minimum_relay.to_sat_per_kwu() == 0 || self.confirmation_margin.to_u16() == 0
			|| self.dust_relay.to_sat_per_kwu() > 25_000_000 || self.claim_fee == Amount::ZERO {
			return Err("invalid exit policy bounds".into());
		}
		let steps = u32::try_from(vtxo.genesis.items.len()).map_err(|_| "exit depth overflow")?;
		let relative = tip.to_u32().checked_add(steps).and_then(|h| h.checked_add(delay))
			.ok_or("exit deadline overflow")?;
		relative.max(absolute.map(|h| h.to_u32()).unwrap_or(0))
			.checked_add(u32::from(self.confirmation_margin.to_u16()))
			.ok_or_else(|| "exit deadline overflow".into())
	}

	fn check_path(&self, vtxo: &Vtxo<Full>, funding: &Transaction, deadline: u32) -> Result<(), String> {
		if deadline >= vtxo.expiry_height().to_u32() {
			return Err("insufficient time to complete recovery before expiry".into());
		}
		vtxo.validate(funding).map_err(|e| e.to_string())?;
		let mut prev = funding.output.get(vtxo.chain_anchor().vout as usize)
			.ok_or("missing funding output")?.clone();
		for item in vtxo.transactions() {
			let total = item.tx.output.iter().try_fold(Amount::ZERO, |sum, o| {
				if zero_value_anchor(o) { return Some(sum); }
				if o.value < o.script_pubkey.minimal_non_dust_custom(self.dust_relay) { return None; }
				sum.checked_add(o.value)
			}).ok_or("dust output or output value overflow in recovery path")?;
			let fee = prev.value.checked_sub(total).ok_or("unfunded recovery transaction")?;
			// A version-3 parent with fee 0 and one zero pay-to-anchor is mined
			// because the child pays. It is not held to the per-transaction floor.
			let zero_anchor_parent = fee == Amount::ZERO
				&& item.tx.version.0 == 3
				&& item.tx.output.iter().filter(|o| zero_value_anchor(o)).count() == 1;
			if !zero_anchor_parent {
				let required = (item.tx.vsize() as u64).checked_mul(4)
					.and_then(|w| w.checked_mul(self.minimum_relay.to_sat_per_kwu()))
					.and_then(|v| v.checked_add(999)).map(|v| v / 1000)
					.ok_or("relay fee overflow")?;
				if fee.to_sat() < required { return Err("recovery parent is below its individual relay floor".into()); }
			}
			prev = item.tx.output.get(item.output_idx).ok_or("invalid recovery output index")?.clone();
		}
		let claim_floor = prev.script_pubkey.minimal_non_dust_custom(self.dust_relay);
		if prev.value.checked_sub(self.claim_fee).is_none_or(|a| a < claim_floor) {
			return Err("insufficient balance for a non-dust final claim after fees".into());
		}
		Ok(())
	}
}
