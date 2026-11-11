//! Ledger for the 1,000 sat Lightning tab.
//!
//! An Ark payment of exactly 1,000 sats to the server pubkey is staged at
//! cosign and credited when that output is registered. The normal Lightning
//! send debits the ledger and records the spend. A failed send puts the
//! debit back. This module does not pay invoices.

use std::str::FromStr;

use anyhow::Context;
use bitcoin::secp256k1::PublicKey;
use ark::VtxoId;
use ark::lightning::{PaymentHash, LIGHTNING_TAB_CHUNK_SAT};

use super::Tx;

impl Tx<'_> {
	pub async fn stage_lightning_tab_fund(
		&self, user: &PublicKey, vtxo: VtxoId,
	) -> anyhow::Result<()> {
		self.execute(
			"INSERT INTO lightning_tab_fund (vtxo_id, user_pubkey, amount_sat)
			 VALUES ($1, $2, $3) ON CONFLICT (vtxo_id) DO NOTHING",
			&[&vtxo.to_string(), &user.to_string(), &(LIGHTNING_TAB_CHUNK_SAT as i64)],
		).await?;
		Ok(())
	}

	/// Credit a staged fund once. A vtxo that was not staged is ignored.
	pub async fn credit_lightning_tab_fund(&self, vtxo: VtxoId) -> anyhow::Result<()> {
		let row = self.query_opt(
			"UPDATE lightning_tab_fund SET credited = TRUE
			 WHERE vtxo_id = $1 AND NOT credited
			 RETURNING user_pubkey, amount_sat",
			&[&vtxo.to_string()],
		).await?;
		if let Some(row) = row {
			let user: String = row.get(0);
			let amount: i64 = row.get(1);
			self.execute(
				"INSERT INTO lightning_tab (user_pubkey, balance_sat) VALUES ($1, $2)
				 ON CONFLICT (user_pubkey) DO UPDATE
				 SET balance_sat = lightning_tab.balance_sat + EXCLUDED.balance_sat",
				&[&user, &amount],
			).await?;
		}
		Ok(())
	}

	/// Balance and opt-out for each requested key. Missing keys are omitted.
	pub async fn lightning_tab_accounts(
		&self, users: &[String],
	) -> anyhow::Result<std::collections::HashMap<String, (i64, bool)>> {
		let rows = self.query(
			"SELECT user_pubkey, balance_sat, opted_out FROM lightning_tab
			 WHERE user_pubkey = ANY($1)",
			&[&users],
		).await?;
		let mut found = std::collections::HashMap::with_capacity(rows.len());
		for row in rows {
			found.insert(row.get(0), (row.get(1), row.get(2)));
		}
		Ok(found)
	}

	pub async fn lightning_tab_balance(&self, user: &PublicKey) -> anyhow::Result<i64> {
		let row = self.query_opt(
			"SELECT balance_sat FROM lightning_tab WHERE user_pubkey = $1",
			&[&user.to_string()],
		).await?;
		Ok(row.map(|r| r.get(0)).unwrap_or(0))
	}

	/// Debit `amount + fee` and record the spend. Returns whether this call
	/// took the sats. A spend already recorded for this payment hash does not
	/// debit again.
	pub async fn debit_lightning_tab(
		&self, user: &PublicKey, hash: PaymentHash, invoice: &str, amount: i64, fee: i64,
	) -> anyhow::Result<bool> {
		let hash = hash.to_string();
		let user = user.to_string();
		let existing = self.query_opt(
			"SELECT status, user_pubkey FROM lightning_tab_payment
			 WHERE payment_hash = $1 FOR UPDATE",
			&[&hash],
		).await?;
		if let Some(ref row) = existing {
			let owner: String = row.get("user_pubkey");
			ensure!(owner == user, "lightning tab spend belongs to another key");
			let status: String = row.get("status");
			if status == "spent" {
				return Ok(false);
			}
			ensure!(status == "refunded", "unknown lightning tab spend status");
		}
		let debit = amount.checked_add(fee).context("tab debit overflow")?;
		let taken = self.execute(
			"UPDATE lightning_tab SET balance_sat = balance_sat - $2
			 WHERE user_pubkey = $1 AND balance_sat >= $2",
			&[&user, &debit],
		).await?;
		ensure!(taken == 1, "Lightning tab does not cover {debit} sats");
		if existing.is_some() {
			self.execute(
				"UPDATE lightning_tab_payment
				 SET status = 'spent', invoice = $2, amount_sat = $3, fee_sat = $4
				 WHERE payment_hash = $1 AND status = 'refunded'",
				&[&hash, &invoice, &amount, &fee],
			).await?;
		} else {
			self.execute(
				"INSERT INTO lightning_tab_payment
				 (payment_hash, user_pubkey, invoice, amount_sat, fee_sat, status)
				 VALUES ($1, $2, $3, $4, $5, 'spent')",
				&[&hash, &user, &invoice, &amount, &fee],
			).await?;
		}
		Ok(true)
	}

	/// Invoice amount and the fee still charged, after a successful tab payment.
	pub async fn lightning_tab_spent(
		&self, hash: &PaymentHash,
	) -> anyhow::Result<Option<(i64, i64)>> {
		let row = self.query_opt(
			"SELECT amount_sat, fee_sat FROM lightning_tab_payment
			 WHERE payment_hash = $1 AND status = 'spent'",
			&[&hash.to_string()],
		).await?;
		Ok(row.map(|row| (row.get(0), row.get(1))))
	}

	/// Lower a spent tab fee to what the route actually cost, plus 1 sat.
	///
	/// An unpriced invoice, including one with a route hint, is debited at the
	/// schedule (75 sats) before the route is known. Once the payment
	/// succeeds, the unused part of that hold goes back on the tab. A second
	/// call finds the fee already lowered and changes nothing.
	pub async fn settle_lightning_tab_fee(
		&self, hash: &PaymentHash, kept_fee: i64,
	) -> anyhow::Result<()> {
		ensure!(kept_fee >= 0, "tab fee cannot be negative");
		let row = self.query_opt(
			"SELECT user_pubkey, fee_sat FROM lightning_tab_payment
			 WHERE payment_hash = $1 AND status = 'spent'
			 FOR UPDATE",
			&[&hash.to_string()],
		).await?;
		let Some(row) = row else { return Ok(()) };
		let user: String = row.get(0);
		let fee: i64 = row.get(1);
		if fee <= kept_fee {
			return Ok(());
		}
		let refund = fee - kept_fee;
		self.execute(
			"UPDATE lightning_tab SET balance_sat = balance_sat + $2 WHERE user_pubkey = $1",
			&[&user, &refund],
		).await?;
		self.execute(
			"UPDATE lightning_tab_payment SET fee_sat = $2
			 WHERE payment_hash = $1 AND status = 'spent'",
			&[&hash.to_string(), &kept_fee],
		).await?;
		Ok(())
	}

	/// Put a debited spend back. A missing or already refunded row is left alone.
	pub async fn refund_lightning_tab(&self, hash: &PaymentHash) -> anyhow::Result<()> {
		let row = self.query_opt(
			"UPDATE lightning_tab_payment SET status = 'refunded'
			 WHERE payment_hash = $1 AND status = 'spent'
			 RETURNING user_pubkey, amount_sat, fee_sat",
			&[&hash.to_string()],
		).await?;
		if let Some(row) = row {
			let user: String = row.get(0);
			let amount: i64 = row.get(1);
			let fee: i64 = row.get(2);
			let debit = amount.checked_add(fee).context("tab refund overflow")?;
			self.execute(
				"UPDATE lightning_tab SET balance_sat = balance_sat + $2 WHERE user_pubkey = $1",
				&[&user, &debit],
			).await?;
		}
		Ok(())
	}

	pub async fn forfeit_lightning_tab(&self, user: &PublicKey) -> anyhow::Result<i64> {
		let row = self.query_opt(
			"SELECT balance_sat FROM lightning_tab WHERE user_pubkey = $1 FOR UPDATE",
			&[&user.to_string()],
		).await?;
		let Some(row) = row else { return Ok(0) };
		let balance: i64 = row.get(0);
		self.execute(
			"UPDATE lightning_tab SET balance_sat = 0 WHERE user_pubkey = $1",
			&[&user.to_string()],
		).await?;
		Ok(balance)
	}

	/// Credited coins this key paid into the tab that have not been settled.
	pub async fn tab_fund_vtxos(&self, user: &PublicKey) -> anyhow::Result<Vec<VtxoId>> {
		let rows = self.query(
			"SELECT vtxo_id FROM lightning_tab_fund
			 WHERE user_pubkey = $1 AND credited AND NOT returned
			 ORDER BY vtxo_id",
			&[&user.to_string()],
		).await?;
		rows.into_iter().map(|row| VtxoId::from_str(row.get(0)).map_err(anyhow::Error::from)).collect()
	}

	pub async fn lightning_tab_returns(
		&self, dest: &PublicKey,
	) -> anyhow::Result<Vec<(i64, VtxoId)>> {
		let rows = self.query(
			"SELECT amount_sat, vtxo_id FROM lightning_tab_return WHERE dest_pubkey = $1 ORDER BY vtxo_id",
			&[&dest.to_string()],
		).await?;
		rows.into_iter().map(|row| {
			Ok((row.get(0), VtxoId::from_str(row.get(1))?))
		}).collect()
	}

	/// Zero the tab and remember the coins paid back to this destination.
	pub async fn settle_lightning_tab_return(
		&self, user: &PublicKey, dest: &PublicKey, amount: i64,
		funds: &[VtxoId], returned: &[VtxoId],
	) -> anyhow::Result<()> {
		let updated = self.execute(
			"UPDATE lightning_tab SET balance_sat = balance_sat - $2
			 WHERE user_pubkey = $1 AND balance_sat = $2",
			&[&user.to_string(), &amount],
		).await?;
		ensure!(updated == 1, "tab balance changed before it was paid back");
		for fund in funds {
			let marked = self.execute(
				"UPDATE lightning_tab_fund SET returned = TRUE
				 WHERE vtxo_id = $1 AND user_pubkey = $2 AND credited AND NOT returned",
				&[&fund.to_string(), &user.to_string()],
			).await?;
			ensure!(marked == 1, "tab coin was already settled");
		}
		for vtxo in returned {
			self.execute(
				"INSERT INTO lightning_tab_return (dest_pubkey, user_pubkey, amount_sat, vtxo_id)
				 VALUES ($1, $2, $3, $4)",
				&[&dest.to_string(), &user.to_string(), &amount, &vtxo.to_string()],
			).await?;
		}
		Ok(())
	}

	pub async fn lightning_tab_opted_out(&self, user: &PublicKey) -> anyhow::Result<bool> {
		let row = self.query_opt(
			"SELECT opted_out FROM lightning_tab WHERE user_pubkey = $1",
			&[&user.to_string()],
		).await?;
		Ok(row.map(|r| r.get(0)).unwrap_or(false))
	}

	pub async fn set_lightning_tab_opt_out(
		&self, user: &PublicKey, opted_out: bool,
	) -> anyhow::Result<i64> {
		self.execute(
			"INSERT INTO lightning_tab (user_pubkey, balance_sat, opted_out) VALUES ($1, 0, $2)
			 ON CONFLICT (user_pubkey) DO UPDATE SET opted_out = EXCLUDED.opted_out",
			&[&user.to_string(), &opted_out],
		).await?;
		self.lightning_tab_balance(user).await
	}

	pub async fn register_lightning_tab_receive(
		&self, hash: PaymentHash, user: &PublicKey, amount: i64,
	) -> anyhow::Result<()> {
		self.execute(
			"INSERT INTO lightning_tab_receive (payment_hash, user_pubkey, amount_sat)
			 VALUES ($1, $2, $3) ON CONFLICT (payment_hash) DO NOTHING",
			&[&hash.to_string(), &user.to_string(), &amount],
		).await?;
		Ok(())
	}

	pub async fn lightning_tab_receive_exists(&self, hash: PaymentHash) -> anyhow::Result<bool> {
		let row = self.query_opt(
			"SELECT 1 FROM lightning_tab_receive WHERE payment_hash = $1",
			&[&hash.to_string()],
		).await?;
		Ok(row.is_some())
	}

	/// Credit a small receive once. Returns the new balance, or None if this
	/// hash was not a tab receive.
	pub async fn credit_lightning_tab_receive(
		&self, hash: PaymentHash,
	) -> anyhow::Result<Option<i64>> {
		let row = self.query_opt(
			"UPDATE lightning_tab_receive SET credited = TRUE
			 WHERE payment_hash = $1 AND NOT credited
			 RETURNING user_pubkey, amount_sat",
			&[&hash.to_string()],
		).await?;
		let Some(row) = row else {
			let existing = self.query_opt(
				"SELECT user_pubkey FROM lightning_tab_receive
				 WHERE payment_hash = $1 AND credited",
				&[&hash.to_string()],
			).await?;
			if existing.is_none() {
				return Ok(None);
			}
			let user: String = existing.unwrap().get(0);
			let balance = self.query_opt(
				"SELECT balance_sat FROM lightning_tab WHERE user_pubkey = $1",
				&[&user],
			).await?;
			return Ok(Some(balance.map(|r| r.get(0)).unwrap_or(0)));
		};
		let user: String = row.get(0);
		let amount: i64 = row.get(1);
		self.execute(
			"INSERT INTO lightning_tab (user_pubkey, balance_sat, opted_out)
			 VALUES ($1, $2, FALSE)
			 ON CONFLICT (user_pubkey) DO UPDATE
			 SET balance_sat = lightning_tab.balance_sat + EXCLUDED.balance_sat",
			&[&user, &amount],
		).await?;
		let balance = self.query_opt(
			"SELECT balance_sat FROM lightning_tab WHERE user_pubkey = $1",
			&[&user],
		).await?;
		Ok(Some(balance.map(|r| r.get(0)).unwrap_or(amount)))
	}
}
