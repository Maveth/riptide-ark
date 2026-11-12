//! The tab is a balance and a spend record. Ark's existing Lightning send
//! pays the invoice.

use anyhow::Context;
use bitcoin::secp256k1::{schnorr::Signature, PublicKey};
use bitcoin::Amount;

use ark::lightning::{Invoice, PaymentHash, Preimage, lightning_tab_message};

use crate::error::ContextExt;
use crate::Server;

use super::{lightning_max_routing_fee, lightning_user_fee};

impl Server {
	pub(crate) async fn authenticated_tab(
		&self, auth: server_rpc::protos::LightningTabAuth, action: &str, payload: &[u8],
	) -> anyhow::Result<(PublicKey, u64)> {
		let user = PublicKey::from_slice(&auth.user_pubkey).context("invalid tab user pubkey")?;
		verify_tab_signature(&user, &auth.signature, action, payload)?;
		let balance = self.lightning_tab_balance_sat(user).await?;
		Ok((user, balance))
	}
}

pub(crate) fn verify_tab_signature(
	pubkey: &PublicKey, signature: &[u8], action: &str, payload: &[u8],
) -> anyhow::Result<()> {
	let signature = Signature::from_slice(signature).context("invalid lightning tab signature")?;
	let (xonly, _) = pubkey.x_only_public_key();
	ark::SECP.verify_schnorr(
		&signature, &lightning_tab_message(action, payload), &xonly,
	).context("lightning tab signature rejected")?;
	Ok(())
}

impl Server {
	pub(crate) async fn lightning_tab_balance_sat(&self, user: PublicKey) -> anyhow::Result<u64> {
		let balance = self.db.read(async |t| t.lightning_tab_balance(&user).await).await?;
		u64::try_from(balance).context("tab balance")
	}

	/// One read for every signed key. The opt-out flag is on the same row.
	pub(crate) async fn lightning_tabs(
		&self, auths: &[server_rpc::protos::LightningTabAuth],
	) -> anyhow::Result<server_rpc::protos::LightningTabsResponse> {
		if auths.len() > 1024 {
			anyhow::bail!("too many tab keys");
		}
		let mut users = Vec::with_capacity(auths.len());
		for auth in auths {
			let user = PublicKey::from_slice(&auth.user_pubkey).context("invalid tab user pubkey")?;
			verify_tab_signature(&user, &auth.signature, "balance", &[])?;
			users.push(user.to_string());
		}
		let found = self.db.read(async |t| t.lightning_tab_accounts(&users).await).await?;
		let mut tabs = Vec::with_capacity(users.len());
		let mut balance_sat: u64 = 0;
		let mut opted_out = false;
		for user in &users {
			let (balance, opted) = found.get(user).copied().unwrap_or((0, false));
			let balance = u64::try_from(balance).context("tab balance")?;
			balance_sat = balance_sat.checked_add(balance).context("tab balance overflow")?;
			opted_out |= opted;
			tabs.push(server_rpc::protos::LightningTabEntry {
				balance_sat: balance, opted_out: opted,
			});
		}
		Ok(server_rpc::protos::LightningTabsResponse { tabs, balance_sat, opted_out })
	}

	/// Credited receives and spent sends. Same signature as a balance read,
	/// one signature per key. The reply has no invoice and no preimage.
	pub(crate) async fn lightning_tab_activity(
		&self, auths: &[server_rpc::protos::LightningTabAuth],
	) -> anyhow::Result<server_rpc::protos::LightningTabActivity> {
		if auths.len() > 1024 {
			anyhow::bail!("too many tab keys");
		}
		let mut users = Vec::with_capacity(auths.len());
		for auth in auths {
			let user = PublicKey::from_slice(&auth.user_pubkey).context("invalid tab user pubkey")?;
			verify_tab_signature(&user, &auth.signature, "activity", &[])?;
			users.push(user.to_string());
		}
		let rows = self.db.read(async |t| t.lightning_tab_activity(&users).await).await?;
		let entries = rows.into_iter().map(|row| server_rpc::protos::LightningTabActivityEntry {
			direction: row.direction,
			amount_sat: row.amount_sat,
			fee_sat: u64::try_from(row.fee_sat).unwrap_or(0),
			at: row.at.map(|t| t.to_rfc3339()).unwrap_or_default(),
			payment_hash: row.payment_hash,
		}).collect();
		Ok(server_rpc::protos::LightningTabActivity { entries })
	}

	pub(crate) async fn forfeit_lightning_tab_sat(&self, user: PublicKey) -> anyhow::Result<u64> {
		let forfeited = self.db.write(async |t| t.forfeit_lightning_tab(&user).await).await?;
		u64::try_from(forfeited).context("forfeited tab")
	}

	/// Pay the whole tab back into coins, or pay nothing.
	///
	/// Whole deposit coins are paid back first. Anything left, including
	/// Lightning receipts, is paid from pool liquidity as its own coin.
	/// The tab is empty afterwards. A later top-up starts a new 1,000 sat coin.
	pub(crate) async fn withdraw_lightning_tab(
		&self, user: PublicKey, signature: &[u8], dest: PublicKey,
	) -> anyhow::Result<(Amount, Vec<ark::Vtxo<ark::vtxo::Full>>)> {
		verify_tab_signature(&user, signature, "withdraw", &dest.serialize())?;
		let prior = self.db.read(async |t| t.lightning_tab_returns(&dest).await).await?;
		if !prior.is_empty() {
			let mut coins = Vec::with_capacity(prior.len());
			let mut total = 0i64;
			for (amount, id) in prior {
				total = amount;
				let state = self.db.read(async |t| t.get_server_vtxo_by_id(id).await).await?;
				coins.push(state.vtxo.try_into_user_vtxo()
					.map_err(|_| anyhow::anyhow!("stored tab return is not a user coin"))?);
			}
			return Ok((Amount::from_sat(u64::try_from(total)?), coins));
		}
		let balance = self.lightning_tab_balance_sat(user).await?;
		let floor = ark::lightning::lightning_tab_floor();
		if Amount::from_sat(balance) < floor {
			return badarg!("a tab under {} sats cannot become a coin", floor.to_sat());
		}
		let fund_ids = self.db.read(async |t| t.tab_fund_vtxos(&user).await).await?;
		let _guard = self.vtxos_in_flux.try_lock(&fund_ids)
			.map_err(|_| anyhow::anyhow!("tab coin is busy"))?;
		let mut funds = Vec::new();
		for id in &fund_ids {
			let state = self.db.read(async |t| t.get_server_vtxo_by_id(*id).await).await?;
			state.check_spendable(self.chain_tip().height)?;
			let input = state.vtxo.clone().try_into_user_vtxo()
				.map_err(|_| anyhow::anyhow!("tab coin is not a pubkey coin"))?;
			ensure!(input.policy().user_pubkey() == self.server_pubkey(),
				"tab coin is not held by the server");
			funds.push((*id, input));
		}
		let mut direct = Vec::new();
		let mut left = balance;
		for (id, input) in &funds {
			let amount = input.amount().to_sat();
			if left >= amount {
				direct.push((*id, input.clone()));
				left -= amount;
			}
		}
		// A leftover under the coin floor cannot be its own coin. Pay the
		// whole balance from the pool instead of leaving that scrap behind.
		if left > 0 && Amount::from_sat(left) < floor {
			direct.clear();
			left = balance;
		}
		let dest_policy = ark::VtxoPolicy::new_pubkey(dest);
		let mut paid = Vec::new();
		let mut spent_funds = Vec::new();
		if !direct.is_empty() {
			let server_key = self.server_key.leak_ref();
			let inputs: Vec<_> = direct.iter().map(|(_, vtxo)| vtxo.clone()).collect();
			let total = inputs.iter().map(|vtxo| vtxo.amount()).try_fold(Amount::ZERO, |sum, amount| {
				sum.checked_add(amount)
			}).context("tab coin total overflow")?;
			let (builder, _) = ark::arkoor::package::ArkoorPackageBuilder::new_funded_payment(
				inputs,
				ark::arkoor::ArkoorDestination { total_amount: total, policy: dest_policy.clone() },
				ark::VtxoPolicy::new_pubkey(server_key.public_key()),
			).context("tab coins cannot be paid back")?;
			let keys = vec![server_key.clone(); builder.builders.len()];
			let builder = builder.cosign_both(&keys, server_key).context("tab coin signature failed")?;
			let signed_txs = builder.signed_virtual_transactions();
			let internal = builder.build_signed_internal_vtxos();
			let spent = builder.input_spend_info().collect::<Vec<_>>();
			let outputs = builder.build_signed_vtxos();
			let (sent, change): (Vec<_>, Vec<_>) = outputs.into_iter()
				.partition(|vtxo| *vtxo.policy() == dest_policy);
			ensure!(change.is_empty(), "a whole tab coin must not leave change");
			let update = crate::database::tree::VtxoTreeUpdate::new()
				.upsert_signed_tx(signed_txs)
				.insert_oor_spent_vtxos(internal)
				.insert_unspent_vtxos(
					sent.iter().cloned().map(ark::ServerVtxo::from),
					crate::database::SpendState::Spendable,
				)
				.mark_vtxos_oor_spent(spent);
			self.db.write(async |t| t.execute_vtxo_tree_update(update).await).await?;
			spent_funds.extend(direct.iter().map(|(id, _)| *id));
			paid.extend(sent);
		}
		if left > 0 {
			let extra = self.vtxopool.pay_to_pubkey(self, ark::arkoor::ArkoorDestination {
				total_amount: Amount::from_sat(left),
				policy: dest_policy,
			}).await.context("the server cannot pay the rest of the tab back right now")?;
			paid.extend(extra);
		}
		let returned_ids: Vec<_> = paid.iter().map(|vtxo| vtxo.id()).collect();
		let settled_funds: Vec<_> = funds.iter().map(|(id, _)| *id).collect();
		self.db.write(async |t| t.settle_lightning_tab_return(
			&user, &dest, i64::try_from(balance)?, &settled_funds, &returned_ids,
		).await).await?;
		Ok((Amount::from_sat(balance), paid))
	}

	/// Debit the tab, record the spend, then hand the invoice to the normal
	/// Lightning send. No HTLC vtxo is created.
	pub(crate) async fn pay_lightning_from_tab(
		&self, invoice: Invoice, amount: Amount, user: PublicKey, signature: &[u8],
	) -> anyhow::Result<()> {
		verify_tab_signature(&user, signature, "pay", invoice.to_string().as_bytes())?;
		invoice.require_xbt().badarg("wrong invoice network identity")?;
		invoice.check_signature().badarg("invalid invoice signature")?;
		if invoice.network() != self.config.network {
			return badarg!("invoice is for another network");
		}
		if amount == Amount::ZERO {
			return badarg!("invoice amount must be positive");
		}
		let payment_amount = invoice.get_payment_amount(Some(amount))
			.badarg("invalid invoice amount")?;
		if payment_amount < ark::lightning::lightning_tab_floor()
			&& self.lightning_tab_is_opted_out(user).await?
		{
			return badarg!("this key opted out of small Lightning payments");
		}
		let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
		if !invoice.has_send_lifetime(now) {
			return badarg!("invoice expired or expires within 30 seconds; request a fresh invoice");
		}
		let hash = invoice.payment_hash();
		if self.db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await?.is_some() {
			return badarg!("the Lightning tab does not pay an invoice this server issued");
		}

		let schedule = self.config.fees.lightning_send.calculate(payment_amount, std::iter::empty())
			.context("fee overflow")?;
		let route = self.lightning_route_fee(&invoice, payment_amount).await;
		let user_fee = lightning_user_fee(route, schedule).context("fee overflow")?;
		let max_routing_fee = lightning_max_routing_fee(
			route, schedule, Amount::ZERO, self.config.ln_max_fee_ppm as u64,
		).context("routing fee overflow")?;
		let tip = self.sync_manager.chain_tip();
		let expiry = tip.height + self.config.htlc_send_expiry_delta;

		let fresh = self.db.write(async |t| t.debit_lightning_tab(
			&user, hash, &invoice.to_string(),
			i64::try_from(payment_amount.to_sat())?, i64::try_from(user_fee.to_sat())?,
		).await).await?;

		let paid = self.lightning_manager.pay_invoice(
			&invoice, payment_amount, max_routing_fee, expiry, None, Vec::new(),
			user_fee, tip.height,
		).await;
		if let Err(err) = paid {
			let open = self.db.read(async |t|
				t.get_open_lightning_payment_attempt_by_payment_hash(hash).await
			).await?;
			if open.is_none() && fresh {
				self.db.write(async |t| t.refund_lightning_tab(&hash).await).await?;
			} else if err.to_string().contains("open payment attempt already exists") {
				return Ok(());
			}
			return Err(err);
		}
		Ok(())
	}

	pub(crate) async fn lightning_tab_is_opted_out(&self, user: PublicKey) -> anyhow::Result<bool> {
		self.db.read(async |t| t.lightning_tab_opted_out(&user).await).await
	}

	pub(crate) async fn set_lightning_tab_opt_out(
		&self, user: PublicKey, opted_out: bool,
	) -> anyhow::Result<u64> {
		let balance = self.db.write(async |t| t.set_lightning_tab_opt_out(&user, opted_out).await).await?;
		u64::try_from(balance).context("tab balance")
	}

	/// Collect a small hold invoice and credit the tab. No VTXO is created.
	pub(crate) async fn settle_lightning_tab_receive(
		&self, hash: PaymentHash, preimage: Preimage, user: PublicKey, signature: &[u8],
	) -> anyhow::Result<u64> {
		if preimage.compute_payment_hash() != hash {
			return badarg!("preimage does not match payment hash");
		}
		verify_tab_signature(&user, signature, "receive-settle", hash.as_ref())?;
		if self.lightning_tab_is_opted_out(user).await? {
			return badarg!("this key opted out of small Lightning payments");
		}
		let sub = self.db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await?
			.context("no lightning receive for this payment hash")?;
		if sub.amount() >= ark::lightning::lightning_tab_floor() {
			return badarg!("this receive is large enough to be a coin");
		}
		self.htlc_settler.settle(preimage).await.context("could not record settlement")?;
		self.lightning_manager.settle_invoice(sub.id, preimage).await
			.context("could not settle the hold invoice")?;
		let balance = self.db.write(async |t| {
			let credited = t.credit_lightning_tab_receive(hash).await?;
			t.store_lightning_htlc_subscription_status(
				sub.id,
				crate::database::ln::LightningHtlcSubscriptionStatus::Settled,
				None,
				None,
			).await?;
			Ok(credited)
		}).await?;
		let balance = balance.context("this payment is not a tab receive")?;
		u64::try_from(balance).context("tab balance")
	}
}
