use std::collections::HashMap;

use anyhow::Context;
use bitcoin::Txid;

use ark::util::IteratorExt;
use ark::{Vtxo, VtxoId, VtxoPolicy, ServerVtxo};
use ark::vtxo::Full;
use ark::arkoor::state::{ServerCanCosign, ServerSigned};
use ark::arkoor::package::{
	ArkoorPackageCosignRequest, ArkoorPackageCosignResponse, ArkoorPackageBuilder,
};

use crate::database::htlc_vtxo::{self, HtlcResolution};
use crate::database::tree::VtxoTreeUpdate;
use crate::error::ContextExt;
use crate::{check_max_amount, Server};

pub(crate) struct ArkoorCosignRequestValidationParams {
	/// whether checkpoints should be used
	pub use_checkpoints: bool,
	/// Only the dedicated outgoing Lightning endpoint may create HTLCs.
	pub allow_lightning_send: bool,
	/// maximum number of outputs from a single input
	pub max_outputs_per_input: usize,
	/// maximum allowed exit depth (genesis items) of each input VTXO;
	/// requests where any input exceeds this are rejected to prevent
	/// unbounded genesis chain growth.
	///
	/// `None` disables the check and is reserved for recovery operations
	/// (lightning receive claims and payment revocations): they unwind an
	/// existing contract into a single claim-all output, so they can't
	/// grow a chain, while refusing them would leave the vtxo with no
	/// spend path other than a unilateral exit.
	pub max_input_exit_depth: Option<u16>,
}

/// A 1,000 sat output to the server pubkey funds the sender's Lightning tab.
/// The ledger is credited only after that output's signed chain is registered.
fn lightning_tab_funds(
	builder: &ArkoorPackageBuilder<ServerCanCosign>,
	server: bitcoin::secp256k1::PublicKey,
) -> Vec<(bitcoin::secp256k1::PublicKey, VtxoId)> {
	let chunk = bitcoin::Amount::from_sat(ark::lightning::LIGHTNING_TAB_CHUNK_SAT);
	let mut funds = Vec::new();
	for part in &builder.builders {
		if !matches!(part.input().policy(), VtxoPolicy::Pubkey(_)) {
			continue;
		}
		let user = part.input().policy().user_pubkey();
		if user == server {
			continue;
		}
		for vtxo in part.build_unsigned_vtxos() {
			if vtxo.amount() == chunk && vtxo.policy().arkoor_pubkey() == Some(server) {
				funds.push((user, vtxo.id()));
			}
		}
	}
	funds
}

impl Server {
	/// Validate the cosign request for the given validation params
	///
	/// Returns the arkoor builder that the server can then sign from.
	pub(crate) fn validate_cosign_request(
		&self,
		params: ArkoorCosignRequestValidationParams,
		cosign_req: ArkoorPackageCosignRequest<Vtxo<Full>>,
	) -> anyhow::Result<ArkoorPackageBuilder<ServerCanCosign>> {
		// this we can check before creating the builder

		if cosign_req.requests.is_empty() {
			bail!("empty request");
		}

		let use_checkpoint = cosign_req.requests.iter()
			.all_same(|r| r.use_checkpoint)
			.context("not all requests have the same use_checkpoints value")?;
		if params.use_checkpoints && !use_checkpoint {
			bail!("should use arkoor checkpoints");
		} else if !params.use_checkpoints && use_checkpoint {
			bail!("should not use arkoor checkpoints");
		}

		for request in &cosign_req.requests {
			let ordinary = matches!(request.input.policy(), VtxoPolicy::Pubkey(_))
				&& request.outputs.iter().all(|o| matches!(&o.policy, VtxoPolicy::Pubkey(_)))
				&& request.isolated_outputs.is_empty();
			// See the update path on `PAPERCLIP_EXIT_PROFILE`. Zero-fee is ours.
			// The two legacy profiles are what older wallets still sign.
			ensure!(request.exit_funding == Some(ark::exit_policy::paperclip_funding())
				|| request.exit_funding == Some(ark::exit_policy::legacy_standard_funding())
				|| (ordinary && (
					request.exit_funding == Some(ark::exit_policy::small_anchor_transfer_funding())
					|| request.exit_funding == Some(ark::exit_policy::legacy_small_anchor_funding())
					|| (self.config.experimental_economical_transfers
						&& request.exit_funding == Some(ark::exit_policy::economical_transfer_funding()))
				)),
				"funded recovery profile required");
		}
		// then we create the builder
		let ret = match ArkoorPackageBuilder::from_cosign_request(cosign_req) {
			Ok(ret) => ret,
			Err((idx, e)) => {
				return badarg!("invalid cosign request at index #{idx}: {e}");
			}
		};

		for (idx, b) in ret.builders.iter().enumerate() {
			let minimum = bitcoin_ext::P2TR_DUST + ark::exit_policy::paperclip_policy().claim_fee;
			let tip = self.chain_tip().height.to_u32();
			let base = u32::try_from(b.input().exit_depth()).context("exit depth overflow")?
				.checked_add(2).and_then(|v| v.checked_add(tip)).context("exit deadline overflow")?;
			for output in b.all_outputs() {
				let delay = u32::from(b.input().exit_delta().to_u16());
				let deadline = match &output.policy {
					VtxoPolicy::Pubkey(_) => {
						ensure!(output.total_amount >= minimum, "dust recovery output");
						base.checked_add(delay).context("exit deadline overflow")?
					},
					VtxoPolicy::ServerHtlcSend(p) if params.allow_lightning_send => {
						ensure!(matches!(b.input().policy(), VtxoPolicy::Pubkey(_)), "invalid HTLC source");
						ensure!(output.total_amount >= minimum + ark::exit_policy::paperclip_funding().per_transaction() * 2,
							"HTLC cannot fund a cooperative refund");
						ensure!(p.htlc_expiry.to_u32() < 500_000_000 && delay * 2 <= u16::MAX as u32, "invalid HTLC timelock");
						base.checked_add(delay * 2).context("refund deadline overflow")?.max(p.htlc_expiry.to_u32())
					},
					_ => bail!("output policy not permitted by this endpoint"),
				};
				ensure!(deadline.checked_add(12).context("exit deadline overflow")? < b.input().expiry_height().to_u32(),
					"refresh required before another transfer");
			}
			if let Some(max_exit_depth) = params.max_input_exit_depth {
				let depth = b.input().exit_depth();
				if depth >= max_exit_depth {
					bail!(
						"input VTXO {} (#{}) exit depth {} meets or exceeds the maximum of {}; \
						 refresh the VTXO in a round before making further OOR payments",
						b.input().id(), idx, depth, max_exit_depth,
					);
				}
			}

			let nb_outputs = b.all_outputs().count();
			if nb_outputs > params.max_outputs_per_input {
				bail!("too many outputs for input {} (#{}) ({} > {})",
					b.input().id(), idx, nb_outputs, params.max_outputs_per_input,
				);
			}
		}

		Ok(ret)
	}

	/// Returns the signed builder along with the number of VTXO rows actually
	/// inserted by the tree update. Callers gate retry-sensitive metrics on
	/// this count: `> 0` means the inputs/outputs were freshly persisted,
	/// `0` means the update collapsed onto an existing row (idempotent retry).
	pub async fn cosign_oor_with_builder(
		&self,
		builder: ArkoorPackageBuilder<ServerCanCosign>,
	) -> anyhow::Result<(ArkoorPackageBuilder<ServerSigned>, u64)> {
		self.cosign_oor_with_delivery(builder, true).await
	}

	pub(crate) async fn cosign_oor_with_delivery(
		&self, builder: ArkoorPackageBuilder<ServerCanCosign>, inline_reimbursement: bool,
	) -> anyhow::Result<(ArkoorPackageBuilder<ServerSigned>, u64)> {
		let vtxo_guard = self.vtxos_in_flux.try_lock(builder.input_ids()).map_err(|e| {
			slog!(ArkoorInputAlreadyInFlux, vtxo: e.id);
			badarg_err!("some VTXO is already locked by another process: {}", e.id)
		})?;

		// The only cosign path that spends htlc-recv vtxos is the lightning
		// receive claim, so cosigning their spend resolves them as fulfilled.
		let claimed_htlc_recvs = builder.builders.iter()
			.filter_map(|b| match b.input().policy() {
				VtxoPolicy::ServerHtlcRecv(..) | VtxoPolicy::ServerHtlcRecv_v0(..) =>
					Some(b.input().id()),
				_ => None,
			})
			.collect::<Vec<_>>();

		// Output user vtxos go in as `unregistered`. They become spendable
		// once the sender uploads the signed transaction chain via
		// register_vtxo_transactions; until then `check_spendable` rejects
		// them. This replaces the standalone chain-registration guard.
		let update = VtxoTreeUpdate::new()
			.upsert_unsigned_tx(builder.virtual_transactions())
			.insert_oor_spent_vtxos(builder.build_unsigned_internal_vtxos())
			.insert_unregistered_vtxos(builder.build_unsigned_vtxos().map(ServerVtxo::from))
			.mark_vtxos_oor_spent(builder.input_spend_info());
		let tab_funds = lightning_tab_funds(&builder, self.server_pubkey());
		let inserted = self.db.write(async |t| {
			let inserted = t.execute_vtxo_tree_update(update).await?;
			if inserted > 0 {
				for (user, vtxo) in &tab_funds {
					t.stage_lightning_tab_fund(user, *vtxo).await?;
				}
			}
			for part in &builder.builders {
				let htlcs = part.build_unsigned_vtxos().filter(|v|
					matches!(v.policy(), VtxoPolicy::ServerHtlcSend(_))).collect::<Vec<_>>();
				if htlcs.is_empty() { continue; }
				ensure!(htlcs.len() == 1, "one outgoing HTLC per input is required");
				let outputs = part.all_outputs().try_fold(bitcoin::Amount::ZERO, |n, v|
					n.checked_add(v.total_amount)).context("output sum overflow")?;
				let reserve = part.input().amount().checked_sub(outputs).context("reserve underflow")?;
				let hash = htlcs[0].policy().as_server_htlc_send().context("HTLC policy missing")?.payment_hash;
				t.record_lightning_setup_cost(htlcs[0].id(), hash, reserve).await?;
				// Only a fresh HTLC chooses delivery. Replays cannot reroute a credit.
				if inserted > 0 && !inline_reimbursement {
					t.execute("UPDATE lightning_failure_credit SET inline_reimbursement=FALSE WHERE htlc_vtxo_id=$1",
						&[&htlcs[0].id().to_string()]).await?;
				}
			}
			htlc_vtxo::set_htlc_vtxo_resolutions(
				&t, &claimed_htlc_recvs, HtlcResolution::Fulfilled,
			).await?;
			Ok(inserted)
		}).await?;
		drop(vtxo_guard);

		// Only now it's safe to sign
		let builder = builder.server_cosign(self.server_key.leak_ref())
			.context("failed to sign arkoor")?;
		Ok((builder, inserted))
	}

	pub async fn cosign_oor(
		&self,
		request: ArkoorPackageCosignRequest<VtxoId>,
	) -> anyhow::Result<ArkoorPackageCosignResponse> {
		let input_vtxo_ids = request.inputs().cloned().collect::<Vec<VtxoId>>();
		let input_vtxo_states = self.db.read(async |t| t.get_user_vtxos_by_id(&input_vtxo_ids).await).await?;

		// Keep this even though check_spendable refuses htlc vtxos too: the
		// idempotent-replay branch below skips it, this check always runs.
		for v in &input_vtxo_states {
			match v.vtxo.policy() {
				VtxoPolicy::Pubkey( ..) => {},
				VtxoPolicy::ServerHtlcSend(..) | VtxoPolicy::ServerHtlcSend_v0(..) => {
					return badarg!("server htlc send vtxo not supported");
				},
				VtxoPolicy::ServerHtlcRecv( ..) | VtxoPolicy::ServerHtlcRecv_v0(..) => {
					return badarg!("server htlc recv vtxo not supported");
				},
			}
		}

		let total_input_amount = input_vtxo_states.iter().map(|v| v.vtxo.amount()).sum();
		let request = request.set_vtxos(input_vtxo_states.into_iter().map(|v| v.vtxo))?;

		check_max_amount("arkoor send", total_input_amount, self.config.max_arkoor_amount)?;

		let validation = ArkoorCosignRequestValidationParams {
			use_checkpoints: true,
			allow_lightning_send: false,
			max_outputs_per_input: self.config.max_arkoor_fanout,
			max_input_exit_depth: Some(self.config.max_vtxo_exit_depth),
		};
		let builder = self.validate_cosign_request(validation, request)
			.badarg("invalid cosign request")?;

		// Check spendability now that we have the spending txids from the
		// builder. We use check_spendable_for_oor which allows a vtxo that&
		// is already OOR-spent by the same tx (idempotent retry).
		let chain_tip = self.chain_tip().height;
		let spend_map: HashMap<VtxoId, Txid> = builder.spend_info().collect();
		let input_vtxo_states = self.db.read(async |t| t.get_user_vtxos_by_id(&input_vtxo_ids).await).await?;
		for v in &input_vtxo_states {
			// An expired vtxo can only leave the Ark through a round or an
			// offboard. Passing it on as an arkoor would hand the receiver
			// a coin it cannot exit while the server can already sweep it.
			if !self.config.allow_expired_arkoor && v.vtxo.expiry_height() <= chain_tip {
				return badarg!("vtxo {} expired at height {} (tip = {})",
					v.vtxo_id, v.vtxo.expiry_height(), chain_tip,
				);
			}
			let spending_txid = spend_map.get(&v.vtxo_id)
				.context("missing spend info for input vtxo")?;
			v.check_spendable_for_oor(chain_tip, *spending_txid)?;
		}

		let (builder, inserted) = self.cosign_oor_with_builder(builder).await?;

		slog!(ArkoorCosign, input_ids: input_vtxo_ids,
			output_ids: builder.build_unsigned_vtxos().into_iter().map(|v| v.id()).collect(),
			amount: total_input_amount,
		);

		// inserted == 0 means the tree update collapsed onto rows that already
		// exist — i.e. an idempotent retry of an already-cosigned arkoor.
		// Counting again would double-count the payment metric.
		if inserted > 0 {
			let volume_sats = input_vtxo_states.iter()
				.map(|v| v.vtxo.amount().to_sat())
				.sum::<u64>();
			crate::telemetry::add_arkoor_payment(volume_sats);
		}

		Ok(builder.cosign_response())
	}
}
