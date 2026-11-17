//! Combine several vtxos into one.
//!
//! An in-Ark combine pays no miner fee. The coins are inputs to one
//! transaction, the user signs each input, and the server cosigns.
//! One exit reserve stays on the resulting coin so that coin can exit.

use bitcoin::amount::CheckedSum;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, Witness};

use crate::arkoor::ArkoorConstructionError;
use crate::exit_policy::paperclip_policy;
use crate::tree::signed::TreeExitFunding;
use crate::vtxo::Full;
use crate::{Vtxo, VtxoPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtxoCombine {
	pub inputs: Vec<OutPoint>,
	pub output_amount: Amount,
	pub exit_anchor: Amount,
	pub transaction: Transaction,
}

/// Spend `inputs` into one vtxo.
///
/// The output is the sum of the inputs minus one exit anchor. That anchor
/// is the only value set aside, and it belongs to the resulting coin's exit.
/// A coin smaller than an exit by itself is allowed, because the total pays
/// the anchor once.
pub fn combine_for_exit(
	inputs: &[Vtxo<Full>], output_policy: &VtxoPolicy, funding: TreeExitFunding,
) -> Result<VtxoCombine, ArkoorConstructionError> {
	if inputs.len() < 2 {
		return Err(ArkoorConstructionError::NoOutputs);
	}
	let first = &inputs[0];
	if inputs.iter().any(|input| {
		input.server_pubkey() != first.server_pubkey()
			|| input.expiry_height() != first.expiry_height()
			|| input.exit_delta() != first.exit_delta()
	}) {
		return Err(ArkoorConstructionError::IncompatibleExitFunding);
	}
	if !matches!(output_policy, VtxoPolicy::Pubkey(_)) {
		return Err(ArkoorConstructionError::IncompatibleExitFunding);
	}

	let total = inputs.iter().map(|input| input.amount()).checked_sum()
		.ok_or(ArkoorConstructionError::Overflow)?;
	let exit_anchor = funding.anchor();
	let floor = bitcoin_ext::P2TR_DUST + paperclip_policy().claim_fee;
	let output_amount = total.checked_sub(exit_anchor).ok_or(ArkoorConstructionError::Dust)?;
	if output_amount < floor {
		return Err(ArkoorConstructionError::Dust);
	}

	let transaction = Transaction {
		version: funding.format().version(),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: inputs.iter().map(|input| TxIn {
			previous_output: input.point(),
			script_sig: bitcoin::ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		}).collect(),
		output: vec![
			output_policy.txout(output_amount, first.server_pubkey(), first.exit_delta(), first.expiry_height()),
			funding.format().anchor(exit_anchor),
		],
	};
	let output_sum = transaction.output.iter().map(|output| output.value).checked_sum()
		.ok_or(ArkoorConstructionError::Overflow)?;
	if output_sum != total {
		return Err(ArkoorConstructionError::Unbalanced { input: total, output: output_sum });
	}

	Ok(VtxoCombine {
		inputs: inputs.iter().map(|input| input.point()).collect(),
		output_amount,
		exit_anchor,
		transaction,
	})
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::exit_policy::small_anchor_transfer_funding;
	use crate::test_util::dummy::DummyTestVtxoSpec;
	use bitcoin::secp256k1::Keypair;

	#[test]
	fn small_coin_joins_a_larger_one_and_pays_one_exit_anchor() {
		let server = Keypair::new(crate::SECP, &mut bitcoin::secp256k1::rand::rngs::OsRng);
		let user = Keypair::new(crate::SECP, &mut bitcoin::secp256k1::rand::rngs::OsRng);
		let small = DummyTestVtxoSpec {
			amount: Amount::from_sat(500),
			fee: Amount::ZERO,
			server_keypair: server,
			user_keypair: user,
			..DummyTestVtxoSpec::default()
		};
		let large = DummyTestVtxoSpec {
			amount: Amount::from_sat(4_953_730),
			fee: Amount::ZERO,
			server_keypair: server,
			user_keypair: user,
			..DummyTestVtxoSpec::default()
		};
		let (_, small_vtxo) = small.build();
		let (_, large_vtxo) = large.build();
		let funding = small_anchor_transfer_funding();
		let combined = combine_for_exit(
			&[small_vtxo, large_vtxo],
			&VtxoPolicy::new_pubkey(user.public_key()),
			funding,
		).expect("500 joins the larger coin");
		assert_eq!(combined.transaction.input.len(), 2);
		assert_eq!(combined.exit_anchor, funding.anchor());
		assert_eq!(combined.output_amount, Amount::from_sat(4_953_730 + 500) - funding.anchor());
		let input_value = Amount::from_sat(4_953_730 + 500);
		let output_value = combined.transaction.output.iter().map(|o| o.value).sum::<Amount>();
		assert_eq!(input_value, output_value);
	}

	#[test]
	fn two_small_coins_that_cannot_exit_are_rejected() {
		let server = Keypair::new(crate::SECP, &mut bitcoin::secp256k1::rand::rngs::OsRng);
		let user = Keypair::new(crate::SECP, &mut bitcoin::secp256k1::rand::rngs::OsRng);
		let spec = |amount| DummyTestVtxoSpec {
			amount: Amount::from_sat(amount),
			fee: Amount::ZERO,
			server_keypair: server,
			user_keypair: user,
			..DummyTestVtxoSpec::default()
		};
		let (_, a) = spec(200).build();
		let (_, b) = spec(200).build();
		let err = combine_for_exit(
			&[a, b],
			&VtxoPolicy::new_pubkey(user.public_key()),
			small_anchor_transfer_funding(),
		);
		assert!(matches!(err, Err(ArkoorConstructionError::Dust)));
	}
}
