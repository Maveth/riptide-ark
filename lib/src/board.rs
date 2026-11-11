//!
//! Board flow:
//!
//! * user creates a builder using [BoardBuilder::new]
//! * user creates the funding tx which pays to [BoardBuilder::funding_script_pubkey]
//! * user sets the funding output in [BoardBuilder::set_funding_details]
//! * user generates signing nonces using [BoardBuilder::generate_user_nonces]
//! * user sends all board info to the server
//! * server creates a builder using [BoardBuilder::new_for_cosign]
//! * server cosigns using [BoardBuilder::server_cosign] and sends cosign response to user
//! * user validates cosign response using [BoardBuilder::verify_cosign_response]
//! * user finishes the vtxos by cross-signing using [BoardBuilder::build_vtxo]

use bitcoin_ext::unified::UnifiedSighash;
use std::marker::PhantomData;

use bitcoin::sighash::{self, SighashCache};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Amount, OutPoint, ScriptBuf, TapSighash, Transaction, TxOut, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, PublicKey};

use bitcoin_ext::{BlockDelta, BlockHeight, TaprootSpendInfoExt};

use crate::error::IncorrectSigningKeyError;
use crate::{musig, scripts, SECP};
use crate::tree::signed::cosign_taproot;
use crate::vtxo::{self, Full, Vtxo, VtxoId, VtxoPolicy, ServerVtxo, ServerVtxoPolicy, GenesisItem, GenesisTransition};

use self::state::BuilderState;


/// The output index of the board vtxo in the board tx.
pub const BOARD_FUNDING_TX_VTXO_VOUT: u32 = 0;

/// Cached data computed from the exit transaction.
#[derive(Debug)]
struct ExitData {
	sighash: TapSighash,
	funding_taproot: TaprootSpendInfo,
	tx: Transaction,
	txid: Txid,
}

fn output_sum(outputs: &[TxOut]) -> Option<Amount> {
	outputs.iter().try_fold(Amount::ZERO, |sum, output| sum.checked_add(output.value))
}

fn compute_exit_data(
	user_pubkey: PublicKey,
	server_pubkey: PublicKey,
	expiry_height: BlockHeight,
	exit_delta: BlockDelta,
	amount: Amount,
	fee: Amount,
	miner_fee: Amount,
	exit_format: bitcoin_ext::fee::ExitFormat,
	utxo: OutPoint,
	other_outputs: &[TxOut],
) -> ExitData {
	let combined_pubkey = musig::combine_keys([user_pubkey, server_pubkey])
		.x_only_public_key().0;
	let funding_taproot = cosign_taproot(combined_pubkey, server_pubkey, expiry_height);
	let funding_txout = TxOut {
		value: amount,
		script_pubkey: funding_taproot.script_pubkey(),
	};

	let exit_taproot = VtxoPolicy::new_pubkey(user_pubkey)
		.taproot(server_pubkey, exit_delta, expiry_height);
	let other_sum = output_sum(other_outputs).expect("exit sibling outputs fit in Amount");
	let exit_txout = TxOut {
		value: amount - fee - miner_fee - other_sum,
		script_pubkey: exit_taproot.script_pubkey(),
	};

	// output_idx 0, then siblings, then the anchor. GenesisItem::tx rebuilds this order.
	let mut outputs = Vec::with_capacity(other_outputs.len().saturating_add(2));
	outputs.push(exit_txout);
	outputs.extend(other_outputs.iter().cloned());
	outputs.push(exit_format.anchor(fee));
	let mut tx = vtxo::create_exit_tx(utxo, outputs[0].clone(), None, fee);
	tx.version = exit_format.version();
	tx.output = outputs;
	let sighash = SighashCache::new(&tx).unified_taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[funding_txout]), sighash::TapSighashType::Default,
	).expect("matching prevouts");

	let txid = tx.compute_txid();
	ExitData { sighash, funding_taproot, tx, txid }
}

/// Pay the boarding service fee to the server without turning it into a miner fee.
fn board_service_output(server_pubkey: PublicKey, value: Amount) -> TxOut {
	TxOut {
		value,
		script_pubkey: ScriptBuf::new_p2tr(&SECP, server_pubkey.x_only_public_key().0, None),
	}
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum BoardFundingError {
	#[error("funded exit needs a non-dust balance and anchor, and an individual relay fee")]
	InsufficientExitReserve,
	#[error("fee larger than amount: amount {amount}, fee {fee}")]
	FeeHigherThanAmount {
		amount: Amount,
		fee: Amount,
	},
	#[error("amount is zero")]
	ZeroAmount,
	#[error("amount after fee is <= 0: amount {amount}, fee {fee}")]
	ZeroAmountAfterFee {
		amount: Amount,
		fee: Amount,
	},
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum BoardFromVtxoError {
	#[error("funding txid mismatch: expected {expected}, got {got}")]
	FundingTxMismatch {
		expected: Txid,
		got: Txid,
	},
	#[error("server pubkey mismatch: expected {expected}, got {got}")]
	ServerPubkeyMismatch {
		expected: PublicKey,
		got: PublicKey,
	},
	#[error("vtxo id mismatch: expected {expected}, got {got}")]
	VtxoIdMismatch {
		expected: OutPoint,
		got: OutPoint,
	},
	#[error("incorrect number of genesis items {genesis_count}, should be 1")]
	IncorrectGenesisItemCount {
		genesis_count: usize,
	},
	#[error("funding output mismatch: expected {expected:?}, got {got:?}")]
	FundingOutputMismatch {
		expected: TxOut,
		got: Option<TxOut>,
	},
}

/// Partial signature the server responds to a board request.
#[derive(Debug)]
pub struct BoardCosignResponse {
	pub pub_nonce: musig::PublicNonce,
	pub partial_signature: musig::PartialSignature,
}

pub mod state {
	mod sealed {
		/// Just a trait to seal the BuilderState trait.
		pub trait Sealed {}
		impl Sealed for super::Preparing {}
		impl Sealed for super::CanGenerateNonces {}
		impl Sealed for super::ServerCanCosign {}
		impl Sealed for super::CanFinish {}
		impl Sealed for super::ServerCanBuildVtxos {}
	}

	/// A marker trait used as a generic for [super::BoardBuilder].
	pub trait BuilderState: sealed::Sealed {}

	/// The user is preparing the board tx.
	pub struct Preparing;
	impl BuilderState for Preparing {}

	/// The UTXO that will be used to fund the board is known, so the
	/// user's signing nonces can be generated.
	pub struct CanGenerateNonces;
	impl BuilderState for CanGenerateNonces {}

	/// All the information for the server to cosign the VTXO is known.
	pub struct ServerCanCosign;
	impl BuilderState for ServerCanCosign {}

	/// The user is ready to build the VTXO as soon as it has
	/// a cosign response from the server.
	pub struct CanFinish;
	impl BuilderState for CanFinish {}

	/// All the information for the server to build the VTXO is known.
	pub struct ServerCanBuildVtxos;
	impl BuilderState for ServerCanBuildVtxos {}

	/// Trait to capture all states that have sufficient information
	/// for either party to create signatures.
	pub trait CanSign: BuilderState {}
	impl CanSign for ServerCanCosign {}
	impl CanSign for CanFinish {}

	/// Trait for once the funding details are known
	pub trait HasFundingDetails: BuilderState {}
	impl HasFundingDetails for CanGenerateNonces {}
	impl HasFundingDetails for ServerCanCosign {}
	impl HasFundingDetails for CanFinish {}
}

/// A request for the server to cosign an board vtxo.
///
/// An object of this type is created by the user, sent to the server who will
/// cosign the request and return his partial signature (along with public nonce)
/// back to the user so that the user can finish the request and create a [Vtxo].
///
/// Currently you can only create VTXOs with [VtxoPolicy::Pubkey].
#[derive(Debug)]
pub struct BoardBuilder<S: BuilderState> {
	pub user_pubkey: PublicKey,
	pub expiry_height: BlockHeight,
	pub server_pubkey: PublicKey,
	pub exit_delta: BlockDelta,

	amount: Option<Amount>,
	fee: Option<Amount>,
	miner_fee: Amount,
	exit_format: bitcoin_ext::fee::ExitFormat,
	/// Sibling outputs placed after the VTXO output and before the anchor.
	other_outputs: Vec<TxOut>,
	utxo: Option<OutPoint>,

	user_pub_nonce: Option<musig::PublicNonce>,
	user_sec_nonce: Option<musig::SecretNonce>,

	// Cached exit tx data (computed when funding details are set)
	exit_data: Option<ExitData>,

	/// The signed VTXO provided by the user
	signed_vtxo: Option<Vtxo<Full>>,

	_state: PhantomData<S>,
}

impl<S: BuilderState> BoardBuilder<S> {
	/// The scriptPubkey to send the board funds to.
	pub fn funding_script_pubkey(&self) -> ScriptBuf {
		let combined_pubkey = musig::combine_keys([self.user_pubkey, self.server_pubkey])
			.x_only_public_key().0;
		cosign_taproot(combined_pubkey, self.server_pubkey, self.expiry_height).script_pubkey()
	}

	fn to_state<S2: BuilderState>(self) -> BoardBuilder<S2> {
		BoardBuilder {
			user_pubkey: self.user_pubkey,
			expiry_height: self.expiry_height,
			server_pubkey: self.server_pubkey,
			exit_delta: self.exit_delta,
			amount: self.amount,
			utxo: self.utxo,
			fee: self.fee,
			miner_fee: self.miner_fee,
			exit_format: self.exit_format,
			other_outputs: self.other_outputs,
			user_pub_nonce: self.user_pub_nonce,
			user_sec_nonce: self.user_sec_nonce,
			exit_data: self.exit_data,
			signed_vtxo: self.signed_vtxo,
			_state: PhantomData,
		}
	}
}

impl BoardBuilder<state::Preparing> {
	pub fn with_exit_format(mut self, format: bitcoin_ext::fee::ExitFormat) -> Self {
		self.exit_format = format;
		self
	}

	/// Create a new builder to construct a board vtxo.
	///
	/// See module-level documentation for an overview of the board flow.
	pub fn new(
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
	) -> BoardBuilder<state::Preparing> {
		BoardBuilder {
			user_pubkey, expiry_height, server_pubkey, exit_delta,
			amount: None,
			utxo: None,
			fee: None,
			miner_fee: Amount::ZERO,
			exit_format: bitcoin_ext::fee::ExitFormat::LegacyV3,
			other_outputs: Vec::new(),
			user_pub_nonce: None,
			user_sec_nonce: None,
			exit_data: None,
			signed_vtxo: None,
			_state: PhantomData,
		}
	}

	/// Set the UTXO where the board will be funded, the total board amount and the fee to be
	/// deducted.
	pub fn set_funding_details(
		mut self,
		amount: Amount,
		fee: Amount,
		utxo: OutPoint,
	) -> Result<BoardBuilder<state::CanGenerateNonces>, BoardFundingError> {
		if amount == Amount::ZERO {
			return Err(BoardFundingError::ZeroAmount);
		} else if fee > amount {
			return Err(BoardFundingError::FeeHigherThanAmount { amount, fee });
		} else if amount - fee == Amount::ZERO {
			return Err(BoardFundingError::ZeroAmountAfterFee { amount, fee });
		}

		let exit_data = compute_exit_data(
			self.user_pubkey, self.server_pubkey, self.expiry_height,
			self.exit_delta, amount, fee, Amount::ZERO, self.exit_format, utxo,
			&self.other_outputs,
		);

		self.amount = Some(amount);
		self.utxo = Some(utxo);
		self.fee = Some(fee);
		self.exit_data = Some(exit_data);

		Ok(self.to_state())
	}

	/// Fund a new exit before either party generates signing nonces.
	/// The anchor and actual miner fee are distinct, explicit deductions.
	pub fn set_funded_funding_details(
		self,
		amount: Amount,
		anchor: Amount,
		miner_fee: Amount,
		utxo: OutPoint,
	) -> Result<BoardBuilder<state::CanGenerateNonces>, BoardFundingError> {
		let deduction = anchor.checked_add(miner_fee)
			.ok_or(BoardFundingError::FeeHigherThanAmount { amount, fee: Amount::MAX_MONEY })?;
		let remaining = amount.checked_sub(deduction)
			.ok_or(BoardFundingError::FeeHigherThanAmount { amount, fee: deduction })?;
		let zero_anchor = anchor == Amount::ZERO && miner_fee == Amount::ZERO;
		if remaining < bitcoin_ext::P2TR_DUST
			|| (!zero_anchor && anchor < bitcoin_ext::P2TR_DUST)
			|| (!zero_anchor && miner_fee < crate::exit_policy::RECOVERY_MINER_FEE)
		{
			return Err(BoardFundingError::InsufficientExitReserve);
		}
		let mut builder = self.set_funding_details(amount, anchor, utxo)?;
		builder.miner_fee = miner_fee;
		builder.exit_data = Some(compute_exit_data(
			builder.user_pubkey, builder.server_pubkey, builder.expiry_height,
			builder.exit_delta, amount, anchor, miner_fee, builder.exit_format, utxo,
			&builder.other_outputs,
		));
		Ok(builder)
	}

	/// Version-3 exit with miner fee 0 and one zero-value pay-to-anchor.
	///
	/// A non-zero boarding service fee is its own server output. Putting that
	/// fee on the anchor, or leaving it as the transaction fee, is not the
	/// shape a strict node can be told to keep.
	pub fn set_zero_fee_board_details(
		mut self,
		amount: Amount,
		service_fee: Amount,
		utxo: OutPoint,
	) -> Result<BoardBuilder<state::CanGenerateNonces>, BoardFundingError> {
		if amount == Amount::ZERO {
			return Err(BoardFundingError::ZeroAmount);
		}
		let remaining = amount.checked_sub(service_fee)
			.ok_or(BoardFundingError::FeeHigherThanAmount { amount, fee: service_fee })?;
		let claim_floor = bitcoin_ext::P2TR_DUST.checked_add(crate::exit_policy::RECOVERY_MINER_FEE)
			.ok_or(BoardFundingError::FeeHigherThanAmount { amount, fee: Amount::MAX_MONEY })?;
		if remaining < claim_floor {
			return Err(BoardFundingError::InsufficientExitReserve);
		}
		let other_outputs = if service_fee == Amount::ZERO {
			Vec::new()
		} else if service_fee < bitcoin_ext::P2TR_DUST {
			return Err(BoardFundingError::InsufficientExitReserve);
		} else {
			vec![board_service_output(self.server_pubkey, service_fee)]
		};

		self.exit_format = bitcoin_ext::fee::ExitFormat::LegacyV3;
		self.miner_fee = Amount::ZERO;
		self.other_outputs = other_outputs;
		self.amount = Some(amount);
		self.utxo = Some(utxo);
		self.fee = Some(Amount::ZERO);
		self.exit_data = Some(compute_exit_data(
			self.user_pubkey, self.server_pubkey, self.expiry_height,
			self.exit_delta, amount, Amount::ZERO, Amount::ZERO, self.exit_format, utxo,
			&self.other_outputs,
		));
		Ok(self.to_state())
	}
}

impl BoardBuilder<state::CanGenerateNonces> {
	/// Generate user nonces.
	pub fn generate_user_nonces(mut self) -> BoardBuilder<state::CanFinish> {
		let exit_data = self.exit_data.as_ref().expect("state invariant");
		let funding_taproot = &exit_data.funding_taproot;
		let exit_sighash = exit_data.sighash;

		let (agg, _) = musig::tweaked_key_agg(
			[self.user_pubkey, self.server_pubkey],
			funding_taproot.tap_tweak().to_byte_array(),
		);
		//TODO(stevenroose) consider trying to move this to musig module
		let (sec_nonce, pub_nonce) = agg.nonce_gen_with_uniform_randomness(
			musig::SessionSecretRand::assume_uniformly_random(rand::random()),
			musig::pubkey_to(self.user_pubkey),
			&exit_sighash.to_byte_array(),
			rand::random(),
		);

		self.user_pub_nonce = Some(pub_nonce);
		self.user_sec_nonce = Some(sec_nonce);
		self.to_state()
	}

	/// Returns a reference to the exit transaction.
	///
	/// The exit transaction spends the board's funding UTXO and creates
	/// the VTXO output.
	pub fn exit_tx(&self) -> &Transaction {
		&self.exit_data.as_ref().expect("state invariant").tx
	}

	/// Returns spend information mapping input VTXO IDs to spending transaction IDs.
	pub fn spend_info(&self) -> Vec<(VtxoId, Txid)> {
		let exit_txid = self.exit_data.as_ref().expect("state invariant").txid;
		vec![(self.utxo.expect("state invariant").into(), exit_txid)]
	}
}

impl<S: state::CanSign> BoardBuilder<S> {
	pub fn user_pub_nonce(&self) -> &musig::PublicNonce {
		self.user_pub_nonce.as_ref().expect("state invariant")
	}
}

impl BoardBuilder<state::ServerCanCosign> {
	/// This constructor is to be used by the server with the information provided
	/// by the user.
	pub fn new_for_cosign(
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		amount: Amount,
		fee: Amount,
		utxo: OutPoint,
		user_pub_nonce: musig::PublicNonce,
	) -> BoardBuilder<state::ServerCanCosign> {
		let exit_data = compute_exit_data(
			user_pubkey, server_pubkey, expiry_height, exit_delta, amount, fee, Amount::ZERO, bitcoin_ext::fee::ExitFormat::LegacyV3, utxo, &[],
		);

		BoardBuilder {
			user_pubkey, expiry_height, server_pubkey, exit_delta,
			amount: Some(amount),
			fee: Some(fee),
			miner_fee: Amount::ZERO,
			exit_format: bitcoin_ext::fee::ExitFormat::LegacyV3,
			other_outputs: Vec::new(),
			utxo: Some(utxo),
			user_pub_nonce: Some(user_pub_nonce),
			user_sec_nonce: None,
			exit_data: Some(exit_data),
			signed_vtxo: None,
			_state: PhantomData,
		}
	}

	/// Reconstruct the funded transaction before the server co-signs it.
	pub fn new_for_funded_cosign(
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		amount: Amount,
		anchor: Amount,
		miner_fee: Amount,
		utxo: OutPoint,
		user_pub_nonce: musig::PublicNonce,
	) -> Result<Self, BoardFundingError> {
		let mut builder = BoardBuilder::new(user_pubkey, expiry_height, server_pubkey, exit_delta)
			.set_funded_funding_details(amount, anchor, miner_fee, utxo)?;
		builder.user_pub_nonce = Some(user_pub_nonce);
		Ok(builder.to_state())
	}

	/// Reconstruct profile 2 before signing; legacy constructors remain unchanged.
	pub fn new_for_standard_cosign(
		user_pubkey: PublicKey, expiry_height: BlockHeight, server_pubkey: PublicKey,
		exit_delta: BlockDelta, amount: Amount, anchor: Amount, miner_fee: Amount,
		utxo: OutPoint, user_pub_nonce: musig::PublicNonce,
	) -> Result<Self, BoardFundingError> {
		let mut builder = BoardBuilder::new(user_pubkey, expiry_height, server_pubkey, exit_delta)
			.with_exit_format(bitcoin_ext::fee::ExitFormat::StandardV2)
			.set_funded_funding_details(amount, anchor, miner_fee, utxo)?;
		builder.user_pub_nonce = Some(user_pub_nonce);
		Ok(builder.to_state())
	}

	/// Reconstruct the version-3 zero-fee exit before the server co-signs it.
	pub fn new_for_zero_fee_cosign(
		user_pubkey: PublicKey, expiry_height: BlockHeight, server_pubkey: PublicKey,
		exit_delta: BlockDelta, amount: Amount, service_fee: Amount,
		utxo: OutPoint, user_pub_nonce: musig::PublicNonce,
	) -> Result<Self, BoardFundingError> {
		let mut builder = BoardBuilder::new(user_pubkey, expiry_height, server_pubkey, exit_delta)
			.set_zero_fee_board_details(amount, service_fee, utxo)?;
		builder.user_pub_nonce = Some(user_pub_nonce);
		Ok(builder.to_state())
	}

	/// This method is used by the server to cosign the board request.
	///
	/// Returns `None` if utxo or user_pub_nonce field is not provided.
	pub fn server_cosign(&self, key: &Keypair) -> BoardCosignResponse {
		let exit_data = self.exit_data.as_ref().expect("state invariant");
		let sighash = exit_data.sighash;
		let taproot = &exit_data.funding_taproot;
		let (pub_nonce, partial_signature) = musig::deterministic_partial_sign(
			key,
			[self.user_pubkey],
			&[&self.user_pub_nonce()],
			sighash.to_byte_array(),
			Some(taproot.tap_tweak().to_byte_array()),
		);
		BoardCosignResponse { pub_nonce, partial_signature }
	}
}

impl BoardBuilder<state::ServerCanBuildVtxos> {
	/// Constructs a BoardBuilder from a vtxo
	///
	/// This is used to validate that a vtxo is a board
	/// that originates from the provided server.
	///
	/// This call assumes the [Vtxo] is valid. The caller
	/// has to call [Vtxo::validate] before using this
	/// constructor.
	pub fn new_from_vtxo(
		vtxo: &Vtxo<Full>,
		funding_tx: &Transaction,
		server_pubkey: PublicKey,
	) -> Result<Self, BoardFromVtxoError> {
		if vtxo.chain_anchor().txid != funding_tx.compute_txid() {
			return Err(BoardFromVtxoError::FundingTxMismatch {
				expected: vtxo.chain_anchor().txid,
				got: funding_tx.compute_txid(),
			})
		}

		if vtxo.server_pubkey() != server_pubkey {
			return Err(BoardFromVtxoError::ServerPubkeyMismatch {
				expected: server_pubkey,
				got: vtxo.server_pubkey(),
			})
		}

		if vtxo.genesis.items.len() != 1 {
			return Err(BoardFromVtxoError::IncorrectGenesisItemCount {
				genesis_count: vtxo.genesis.items.len(),
			});
		}

		let item = vtxo.genesis.items.first().unwrap();
		let fee = item.fee_amount;
		let miner_fee = item.miner_fee;
		let exit_format = item.exit_format;
		let other_outputs = item.other_outputs.clone();
		let other_sum = output_sum(&other_outputs).expect("board sibling outputs fit in Amount");
		let amount = vtxo.amount() + fee + miner_fee + other_sum;
		let exit_data = compute_exit_data(
			vtxo.user_pubkey(),
			server_pubkey,
			vtxo.expiry_height,
			vtxo.exit_delta,
			amount,
			fee,
			miner_fee,
			exit_format,
			vtxo.chain_anchor(),
			&other_outputs,
		);

		// The exit txid doesn't commit to the funding script, so check it
		// is the user+server musig output and not one the user owns alone.
		let expected_funding_txout = TxOut {
			value: vtxo.amount() + fee + miner_fee,
			script_pubkey: exit_data.funding_taproot.script_pubkey(),
		};
		let funding_txout = funding_tx.output.get(vtxo.chain_anchor().vout as usize);
		if funding_txout != Some(&expected_funding_txout) {
			return Err(BoardFromVtxoError::FundingOutputMismatch {
				expected: expected_funding_txout,
				got: funding_txout.cloned(),
			});
		}

		// We compute the vtxo_id again from all reconstructed data
		// It must match exactly
		let expected_vtxo_id = OutPoint::new(exit_data.txid, BOARD_FUNDING_TX_VTXO_VOUT);
		if vtxo.point() != expected_vtxo_id {
			return Err(BoardFromVtxoError::VtxoIdMismatch {
				expected: expected_vtxo_id,
				got: vtxo.point(),
			})
		}

		Ok(Self {
			user_pub_nonce: None,
			user_sec_nonce: None,
			amount: Some(amount),
			fee: Some(fee),
			miner_fee,
			exit_format,
			other_outputs,
			user_pubkey: vtxo.user_pubkey(),
			server_pubkey,
			expiry_height: vtxo.expiry_height,
			exit_delta: vtxo.exit_delta,
			utxo: Some(vtxo.chain_anchor()),
			exit_data: Some(exit_data),
			signed_vtxo: Some(vtxo.clone()),
			_state: PhantomData,
		})
	}

	/// Returns the txid of the exit transaction.
	pub fn exit_txid(&self) -> Txid {
		self.exit_data.as_ref().expect("state invariant").txid
	}

	/// Builds the internal unsigned VTXOs created by this board operation.
	///
	/// Returns two VTXOs:
	/// 1. An expiry VTXO with empty genesis (for server tracking)
	/// 2. The validated output VTXO
	pub fn build_server_vtxos(&self) -> Vec<ServerVtxo<Full>> {
		let combined_pubkey = musig::combine_keys([self.user_pubkey, self.server_pubkey])
			.x_only_public_key().0;

		let vtxo = self.signed_vtxo.as_ref().expect("state invariant").clone();

		vec![
			Vtxo {
				policy: ServerVtxoPolicy::new_expiry(combined_pubkey),
				amount: self.amount.expect("state invariant"),
				expiry_height: self.expiry_height,
				server_pubkey: self.server_pubkey,
				exit_delta: self.exit_delta,
				anchor_point: self.utxo.expect("state invariant"),
				genesis: Full { items: vec![] },
				point: self.utxo.expect("state invariant"),
			},
			ServerVtxo::from(vtxo),
		]
	}

	/// Returns spend information mapping input VTXO IDs to spending transaction IDs.
	pub fn spend_info(&self) -> Vec<(VtxoId, Txid)> {
		let exit_txid = self.exit_data.as_ref().expect("state invariant").txid;
		vec![(self.utxo.expect("state invariant").into(), exit_txid)]
	}
}

impl BoardBuilder<state::CanFinish> {
	/// Validate the server's partial signature.
	pub fn verify_cosign_response(&self, server_cosign: &BoardCosignResponse) -> bool {
		let exit_data = self.exit_data.as_ref().expect("state invariant");
		let sighash = exit_data.sighash;
		let taproot = &exit_data.funding_taproot;
		scripts::verify_partial_sig(
			sighash,
			taproot.tap_tweak(),
			(self.server_pubkey, &server_cosign.pub_nonce),
			(self.user_pubkey, self.user_pub_nonce()),
			&server_cosign.partial_signature
		)
	}

	/// Finishes the board request and create a vtxo.
	pub fn build_vtxo(
		mut self,
		server_cosign: &BoardCosignResponse,
		user_key: &Keypair,
	) -> Result<Vtxo<Full>, IncorrectSigningKeyError> {
		if user_key.public_key() != self.user_pubkey {
			return Err(IncorrectSigningKeyError {
				required: Some(self.user_pubkey),
				provided: user_key.public_key(),
			});
		}

		let exit_data = self.exit_data.as_ref().expect("state invariant");
		let sighash = exit_data.sighash;
		let taproot = &exit_data.funding_taproot;
		let exit_txid = exit_data.txid;

		let agg_nonce = musig::nonce_agg(&[&self.user_pub_nonce(), &server_cosign.pub_nonce]);
		let (user_sig, final_sig) = musig::partial_sign(
			[self.user_pubkey, self.server_pubkey],
			agg_nonce,
			user_key,
			self.user_sec_nonce.take().expect("state invariant"),
			sighash.to_byte_array(),
			Some(taproot.tap_tweak().to_byte_array()),
			Some(&[&server_cosign.partial_signature]),
		);
		debug_assert!(
			scripts::verify_partial_sig(
				sighash,
				taproot.tap_tweak(),
				(self.user_pubkey, self.user_pub_nonce()),
				(self.server_pubkey, &server_cosign.pub_nonce),
				&user_sig,
			),
			"invalid board partial exit tx signature produced",
		);

		let final_sig = final_sig.expect("we provided the other sig");
		debug_assert!(
			SECP.verify_schnorr(
				&final_sig, &sighash.into(), &taproot.output_key().to_x_only_public_key(),
			).is_ok(),
			"invalid board exit tx signature produced",
		);

		let amount = self.amount.expect("state invariant");
		let fee = self.fee.expect("state invariant");
		let other_sum = output_sum(&self.other_outputs).expect("board sibling outputs fit in Amount");
		let vtxo_amount = amount.checked_sub(fee).and_then(|a| a.checked_sub(self.miner_fee))
			.and_then(|a| a.checked_sub(other_sum))
			.expect("funding deductions were checked before signing");

		Ok(Vtxo {
			amount: vtxo_amount,
			expiry_height: self.expiry_height,
			server_pubkey: self.server_pubkey,
			exit_delta: self.exit_delta,
			anchor_point: self.utxo.expect("state invariant"),
			genesis: Full {
				items: vec![GenesisItem {
					miner_fee: self.miner_fee,
			exit_format: self.exit_format,
					transition: GenesisTransition::new_cosigned(
						vec![self.user_pubkey, self.server_pubkey],
						Some(final_sig),
					),
					output_idx: 0,
					other_outputs: self.other_outputs.clone(),
					fee_amount: fee,
				}],
			},
			policy: VtxoPolicy::new_pubkey(self.user_pubkey),
			point: OutPoint::new(exit_txid, BOARD_FUNDING_TX_VTXO_VOUT),
		})
	}
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("board funding tx validation error: {0}")]
pub struct BoardFundingTxValidationError(String);


#[cfg(test)]
mod test {
	use std::str::FromStr;

	use bitcoin::{absolute, transaction, Amount};
	use bitcoin_ext::fee::ExitFormat;

	use crate::test_util::encoding_roundtrip;

	use super::*;

	#[test]
	fn funded_board_recovery_accounting() {
		let (old, _, user, server) = create_board_vtxo();
		let new = || BoardBuilder::new(user.public_key(), old.expiry_height(),
			server.public_key(), old.exit_delta());
		let amount = Amount::from_sat(100_000);
		let anchor = Amount::from_sat(330);
		let miner_fee = Amount::from_sat(500);
		let funding = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut { value: amount, script_pubkey: new().funding_script_pubkey() }],
		};
		let point = OutPoint::new(funding.compute_txid(), 0);
		let builder = new().set_funded_funding_details(amount, anchor, miner_fee, point)
			.unwrap().generate_user_nonces();
		let cosigner = BoardBuilder::new_for_funded_cosign(user.public_key(), old.expiry_height(),
			server.public_key(), old.exit_delta(), amount, anchor, miner_fee, point,
			*builder.user_pub_nonce()).unwrap();
		let response = cosigner.server_cosign(&server);
		assert!(builder.verify_cosign_response(&response));
		let vtxo = builder.build_vtxo(&response, &user).unwrap();
		// The upstream unit-only kernel checks BTC signatures. XBT consensus
		// and full validation run in the real Knots regtest probe.
		vtxo.validate_unsigned(&funding).unwrap();
		assert_eq!(vtxo.amount(), Amount::from_sat(99_170));
		let tx = vtxo.transactions().next().unwrap().tx;
		assert_eq!(amount - tx.output.iter().map(|o| o.value).sum::<Amount>(), miner_fee);
		assert_eq!(tx.input[0].witness[0].len(), 65);
		assert_eq!(tx.input[0].witness[0][64], 0x21);
		encoding_roundtrip(&vtxo);
		let rebuilt = BoardBuilder::new_from_vtxo(&vtxo, &funding, server.public_key()).unwrap();
		assert_eq!(rebuilt.exit_txid(), tx.compute_txid());

		// Invalid reserves fail before nonce generation or a funding commitment.
		for (a, m) in [(0, 500), (330, 0), (100_000, 500), (u64::MAX, 500)] {
			assert!(new().set_funded_funding_details(amount, Amount::from_sat(a),
				Amount::from_sat(m), point).is_err());
		}
	}

	#[test]
	fn standard_v2_board_recovery_accounting() {
		let (old, _, user, server) = create_board_vtxo();
		let new = || BoardBuilder::new(user.public_key(), old.expiry_height(),
			server.public_key(), old.exit_delta()).with_exit_format(bitcoin_ext::fee::ExitFormat::StandardV2);
		let amount = Amount::from_sat(100_000);
		let anchor = Amount::from_sat(330);
		let miner_fee = Amount::from_sat(500);
		let funding = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut { value: amount, script_pubkey: new().funding_script_pubkey() }],
		};
		let point = OutPoint::new(funding.compute_txid(), 0);
		let builder = new().set_funded_funding_details(amount, anchor, miner_fee, point)
			.unwrap().generate_user_nonces();
		let cosigner = BoardBuilder::new_for_standard_cosign(user.public_key(), old.expiry_height(),
			server.public_key(), old.exit_delta(), amount, anchor, miner_fee, point,
			*builder.user_pub_nonce()).unwrap();
		let response = cosigner.server_cosign(&server);
		assert!(builder.verify_cosign_response(&response));
		let vtxo = builder.build_vtxo(&response, &user).unwrap();
		// The upstream unit-only kernel checks BTC signatures. XBT consensus
		// and full validation run in the real Knots regtest probe.
		vtxo.validate_unsigned(&funding).unwrap();
		assert_eq!(vtxo.amount(), Amount::from_sat(99_170));
		let tx = vtxo.transactions().next().unwrap().tx;
		assert_eq!(amount - tx.output.iter().map(|o| o.value).sum::<Amount>(), miner_fee);
		assert_eq!(tx.version, bitcoin::transaction::Version::TWO);
		assert_eq!(tx.output[1].script_pubkey, bitcoin_ext::fee::standard_anchor_script().to_p2wsh());
		assert_eq!(tx.input[0].witness[0].len(), 65);
		assert_eq!(tx.input[0].witness[0][64], 0x21);
		encoding_roundtrip(&vtxo);
		let rebuilt = BoardBuilder::new_from_vtxo(&vtxo, &funding, server.public_key()).unwrap();
		assert_eq!(rebuilt.exit_txid(), tx.compute_txid());

		// Invalid reserves fail before nonce generation or a funding commitment.
		for (a, m) in [(0, 500), (330, 0), (100_000, 500), (u64::MAX, 500)] {
			assert!(new().set_funded_funding_details(amount, Amount::from_sat(a),
				Amount::from_sat(m), point).is_err());
		}
	}

	#[test]
	fn zero_fee_board_is_one_anchor_parent() {
		let (old, _, user, server) = create_board_vtxo();
		let amount = Amount::from_sat(50_000);
		let service_fee = Amount::from_sat(330);
		let new = || BoardBuilder::new(user.public_key(), old.expiry_height(),
			server.public_key(), old.exit_delta());
		let funding = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut { value: amount, script_pubkey: new().funding_script_pubkey() }],
		};
		let point = OutPoint::new(funding.compute_txid(), 0);
		let builder = new().set_zero_fee_board_details(amount, service_fee, point)
			.unwrap().generate_user_nonces();
		let cosigner = BoardBuilder::new_for_zero_fee_cosign(user.public_key(), old.expiry_height(),
			server.public_key(), old.exit_delta(), amount, service_fee, point,
			*builder.user_pub_nonce()).unwrap();
		let response = cosigner.server_cosign(&server);
		assert!(builder.verify_cosign_response(&response));
		let vtxo = builder.build_vtxo(&response, &user).unwrap();
		vtxo.validate_unsigned(&funding).unwrap();
		assert_eq!(vtxo.amount(), Amount::from_sat(49_670));
		let tx = vtxo.transactions().next().unwrap().tx;
		assert_eq!(tx.version, bitcoin::transaction::Version(3));
		assert_eq!(amount - tx.output.iter().map(|o| o.value).sum::<Amount>(), Amount::ZERO);
		assert_eq!(tx.output.iter().filter(|o| {
			o.value == Amount::ZERO && o.script_pubkey == *bitcoin_ext::fee::P2A_SCRIPT
		}).count(), 1);
		assert_eq!(tx.output[0].value, vtxo.amount());
		assert_eq!(tx.output[1].value, service_fee);
		assert_eq!(tx.output[1].script_pubkey, bitcoin::ScriptBuf::new_p2tr(
			&crate::SECP, server.public_key().x_only_public_key().0, None,
		));
		assert_eq!(vtxo.genesis.items[0].miner_fee, Amount::ZERO);
		assert_eq!(vtxo.genesis.items[0].fee_amount, Amount::ZERO);
		assert_eq!(vtxo.genesis.items[0].exit_format, bitcoin_ext::fee::ExitFormat::LegacyV3);
		encoding_roundtrip(&vtxo);
		let rebuilt = BoardBuilder::new_from_vtxo(&vtxo, &funding, server.public_key()).unwrap();
		assert_eq!(rebuilt.exit_txid(), tx.compute_txid());
		crate::exit_policy::paperclip_policy().check(&vtxo, &funding, BlockHeight::new(1)).unwrap();

		assert!(new().set_zero_fee_board_details(amount, Amount::from_sat(329), point).is_err());
		assert!(new().set_zero_fee_board_details(Amount::from_sat(700), service_fee, point).is_err());
	}

	#[test]
	fn test_board_builder() {
		//! Passes through the entire flow so that all assertions
		//! inside the code are ran at least once.

		let user_key = Keypair::from_str("5255d132d6ec7d4fc2a41c8f0018bb14343489ddd0344025cc60c7aa2b3fda6a").unwrap();
		let server_key = Keypair::from_str("1fb316e653eec61de11c6b794636d230379509389215df1ceb520b65313e5426").unwrap();

		// user
		let amount = Amount::from_btc(1.5).unwrap();
		let fee = Amount::from_btc(0.1).unwrap();
		let expiry = BlockHeight::new(100_000);
		let server_pubkey = server_key.public_key();
		let exit_delta = BlockDelta::new(24);
		let builder = BoardBuilder::new(
			user_key.public_key(), expiry, server_pubkey, exit_delta,
		);
		let funding_tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				value: amount,
				script_pubkey: builder.funding_script_pubkey(),
			}],
		};
		let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
		assert_eq!(utxo.to_string(), "8c4b87af4ce8456bbd682859959ba64b95d5425d761a367f4f20b8ffccb1bde0:0");
		let builder = builder.set_funding_details(amount, fee, utxo).unwrap().generate_user_nonces();

		// server
		let cosign = {
			let server_builder = BoardBuilder::new_for_cosign(
				builder.user_pubkey, expiry, server_pubkey, exit_delta, amount, fee, utxo, *builder.user_pub_nonce(),
			);
			server_builder.server_cosign(&server_key)
		};

		// user
		assert!(builder.verify_cosign_response(&cosign));
		let vtxo = builder.build_vtxo(&cosign, &user_key).unwrap();

		encoding_roundtrip(&vtxo);

		vtxo.validate(&funding_tx).unwrap();
	}

	/// Helper to create a valid vtxo and funding tx for testing new_from_vtxo
	fn create_board_vtxo() -> (Vtxo<Full>, Transaction, Keypair, Keypair) {
		let user_key = Keypair::from_str("5255d132d6ec7d4fc2a41c8f0018bb14343489ddd0344025cc60c7aa2b3fda6a").unwrap();
		let server_key = Keypair::from_str("1fb316e653eec61de11c6b794636d230379509389215df1ceb520b65313e5426").unwrap();

		let amount = Amount::from_btc(1.5).unwrap();
		let fee = Amount::from_btc(0.1).unwrap();
		let expiry = BlockHeight::new(100_000);
		let server_pubkey = server_key.public_key();
		let exit_delta = BlockDelta::new(24);

		let builder = BoardBuilder::new(
			user_key.public_key(), expiry, server_pubkey, exit_delta,
		);
		let funding_tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				value: amount,
				script_pubkey: builder.funding_script_pubkey(),
			}],
		};
		let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
		let builder = builder.set_funding_details(amount, fee, utxo).unwrap().generate_user_nonces();

		let cosign = {
			let server_builder = BoardBuilder::new_for_cosign(
				builder.user_pubkey, expiry, server_pubkey, exit_delta, amount, fee, utxo, *builder.user_pub_nonce(),
			);
			server_builder.server_cosign(&server_key)
		};

		let vtxo = builder.build_vtxo(&cosign, &user_key).unwrap();
		(vtxo, funding_tx, user_key, server_key)
	}

	#[test]
	fn test_new_from_vtxo_success() {
		let (vtxo, funding_tx, _, server_key) = create_board_vtxo();

		vtxo.validate(&funding_tx).unwrap();
		println!("amount: {}", vtxo.amount());

		// Should succeed with correct inputs
		let builder = BoardBuilder::new_from_vtxo(&vtxo, &funding_tx, server_key.public_key())
			.expect("Is valid");

		let server_vtxos = builder.build_server_vtxos();
		assert_eq!(server_vtxos.len(), 2);
		assert!(matches!(server_vtxos[0].policy(), ServerVtxoPolicy::Expiry(..)));
		assert!(matches!(server_vtxos[1].policy(), ServerVtxoPolicy::User(VtxoPolicy::Pubkey {..})));
		assert_eq!(server_vtxos[1].id(), vtxo.id());
		assert_eq!(server_vtxos[1].txout(), vtxo.txout());
		assert_eq!(server_vtxos[0].txout(), funding_tx.output[0]);
		assert_eq!(
			server_vtxos[1].transactions().nth(0).unwrap().tx.compute_txid(),
			vtxo.transactions().nth(0).unwrap().tx.compute_txid(),
		);
	}

	#[test]
	fn test_new_from_vtxo_txid_mismatch() {
		let (vtxo, funding_tx, _, server_key) = create_board_vtxo();

		// Create a different funding tx with wrong txid
		let wrong_funding_tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				value: Amount::from_btc(2.0).unwrap(), // Different amount = different txid
				script_pubkey: funding_tx.output[0].script_pubkey.clone(),
			}],
		};

		let result = BoardBuilder::new_from_vtxo(&vtxo, &wrong_funding_tx, server_key.public_key());
		assert!(matches!(
			result,
			Err(BoardFromVtxoError::FundingTxMismatch { expected, got })
			if expected == vtxo.chain_anchor().txid && got == wrong_funding_tx.compute_txid()
		));
	}

	#[test]
	fn test_new_from_vtxo_server_pubkey_mismatch() {
		let (vtxo, funding_tx, _, _) = create_board_vtxo();

		// Use a different server pubkey
		let wrong_server_key = Keypair::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();

		let result = BoardBuilder::new_from_vtxo(&vtxo, &funding_tx, wrong_server_key.public_key());
		assert!(matches!(
			result,
			Err(BoardFromVtxoError::ServerPubkeyMismatch { expected, got })
			if expected == wrong_server_key.public_key() && got == vtxo.server_pubkey()
		));
	}

	#[test]
	fn test_new_from_vtxo_vtxoid_mismatch() {
		// This test verifies that BoardBuilder::new_from_vtxo detects when the
		// vtxo's point doesn't match the computed exit tx output.
		//
		// Note: It is not the responsibility of new_from_vtxo to validate that
		// the vtxo's point is correct in the first place. That validation
		// happens in Vtxo::validate. This check ensures internal consistency
		// when reconstructing the board from a vtxo.
		let (mut vtxo, funding_tx, _, server_key) = create_board_vtxo();

		// Tamper with the vtxo's point to cause a mismatch
		let original_point = vtxo.point;
		vtxo.point = OutPoint::new(vtxo.point.txid, vtxo.point.vout + 1);

		let result = BoardBuilder::new_from_vtxo(&vtxo, &funding_tx, server_key.public_key());
		assert!(matches!(
			result,
			Err(BoardFromVtxoError::VtxoIdMismatch { expected, got })
			if expected == original_point && got == vtxo.point
		));
	}

	#[test]
	fn test_new_from_vtxo_funding_output_value_and_index() {
		let (vtxo, funding_tx, _, server_key) = create_board_vtxo();
		for delta in [-1i64, 1] {
			let mut wrong_tx = funding_tx.clone();
			wrong_tx.output[0].value = Amount::from_sat(
				(funding_tx.output[0].value.to_sat() as i64 + delta) as u64,
			);
			let mut wrong_vtxo = vtxo.clone();
			wrong_vtxo.anchor_point.txid = wrong_tx.compute_txid();
			assert!(matches!(
				BoardBuilder::new_from_vtxo(&wrong_vtxo, &wrong_tx, server_key.public_key()),
				Err(BoardFromVtxoError::FundingOutputMismatch { got: Some(_), .. }),
			));
		}
		let mut wrong_vtxo = vtxo;
		wrong_vtxo.anchor_point.vout = u32::MAX;
		assert!(matches!(
			BoardBuilder::new_from_vtxo(&wrong_vtxo, &funding_tx, server_key.public_key()),
			Err(BoardFromVtxoError::FundingOutputMismatch { got: None, .. }),
		));
	}

	#[test]
	fn test_new_from_vtxo_funding_output_without_server_key() {
		let (honest, _, user_key, server_key) = create_board_vtxo();
		let attacker_key = Keypair::from_str("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();

		for (exit_format, miner_fee) in [
			(ExitFormat::LegacyV3, Amount::ZERO),
			(ExitFormat::LegacyV3, Amount::from_sat(500)),
			(ExitFormat::StandardV2, Amount::from_sat(500)),
		] {
			let fee = honest.genesis.items[0].fee_amount;
			let amount = honest.amount() + fee + miner_fee;
			let agg_pk = musig::combine_keys([user_key.public_key(), attacker_key.public_key()])
				.x_only_public_key().0;
			let funding_taproot = cosign_taproot(agg_pk, server_key.public_key(), honest.expiry_height);
			let funding_txout = TxOut { value: amount, script_pubkey: funding_taproot.script_pubkey() };
			let funding_tx = Transaction {
				version: transaction::Version::TWO,
				lock_time: absolute::LockTime::ZERO,
				input: vec![],
				output: vec![funding_txout.clone()],
			};
			let utxo = OutPoint::new(funding_tx.compute_txid(), 0);

			let exit = compute_exit_data(
				user_key.public_key(), server_key.public_key(), honest.expiry_height,
				honest.exit_delta, amount, fee, miner_fee, exit_format, utxo,
			);
			let sighash = SighashCache::new(&exit.tx).unified_taproot_key_spend_signature_hash(
				0, &sighash::Prevouts::All(&[funding_txout]), sighash::TapSighashType::Default,
			).unwrap();
			let sig = musig::cosign_both(
				&user_key, &attacker_key, sighash.to_byte_array(),
				Some(funding_taproot.tap_tweak().to_byte_array()),
			);

			let mut vtxo = honest.clone();
			vtxo.genesis.items[0].miner_fee = miner_fee;
			vtxo.genesis.items[0].exit_format = exit_format;
			vtxo.anchor_point = utxo;
			vtxo.point = OutPoint::new(exit.txid, BOARD_FUNDING_TX_VTXO_VOUT);
			vtxo.genesis.items[0].transition = GenesisTransition::new_cosigned(
				vec![user_key.public_key(), attacker_key.public_key()], Some(sig),
			);

			// The unit-only upstream kernel checks legacy signatures. Verify the
			// unified signature explicitly and validate the transaction structure.
			SECP.verify_schnorr(&sig, &bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array()),
				&funding_taproot.output_key().to_x_only_public_key()).unwrap();
			vtxo.validate_unsigned(&funding_tx).unwrap();
			let result = BoardBuilder::new_from_vtxo(&vtxo, &funding_tx, server_key.public_key());
			assert!(matches!(result, Err(BoardFromVtxoError::FundingOutputMismatch { .. })));
		}
	}

	#[test]
	fn test_board_funding_error() {
		fn new_builder_with_funding_details(amount: Amount, fee: Amount) -> Result<BoardBuilder<state::CanGenerateNonces>, BoardFundingError> {
			let user_key = Keypair::from_str("5255d132d6ec7d4fc2a41c8f0018bb14343489ddd0344025cc60c7aa2b3fda6a").unwrap();
			let server_key = Keypair::from_str("1fb316e653eec61de11c6b794636d230379509389215df1ceb520b65313e5426").unwrap();
			let expiry = BlockHeight::new(100_000);
			let server_pubkey = server_key.public_key();
			let exit_delta = BlockDelta::new(24);
			let builder = BoardBuilder::new(
				user_key.public_key(), expiry, server_pubkey, exit_delta,
			);
			let funding_tx = Transaction {
				version: transaction::Version::TWO,
				lock_time: absolute::LockTime::ZERO,
				input: vec![],
				output: vec![TxOut {
					value: amount,
					script_pubkey: builder.funding_script_pubkey(),
				}],
			};
			let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
			builder.set_funding_details(amount, fee, utxo)
		}

		let fee = Amount::ONE_BTC;

		let zero_amount_err = new_builder_with_funding_details(Amount::ZERO, fee).err();
		assert_eq!(zero_amount_err, Some(BoardFundingError::ZeroAmount));

		let fee_higher_err = new_builder_with_funding_details(Amount::ONE_SAT, fee).err();
		assert_eq!(fee_higher_err, Some(BoardFundingError::FeeHigherThanAmount { amount: Amount::ONE_SAT, fee }));

		let zero_amount_after_fee_err = new_builder_with_funding_details(fee, fee).err();
		assert_eq!(zero_amount_after_fee_err, Some(BoardFundingError::ZeroAmountAfterFee { amount: fee, fee }));
	}
}
