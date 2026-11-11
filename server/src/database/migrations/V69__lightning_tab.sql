-- Custodial Lightning tab. A 1,000 sat Ark output to the server pubkey is
-- staged at cosign and credited only when that output's signed chain is
-- registered. Mini invoices debit the ledger. Nothing is paid back as a VTXO.

CREATE TABLE lightning_tab (
	user_pubkey TEXT PRIMARY KEY,
	balance_sat BIGINT NOT NULL CHECK (balance_sat >= 0)
);

CREATE TABLE lightning_tab_fund (
	vtxo_id TEXT PRIMARY KEY,
	user_pubkey TEXT NOT NULL,
	amount_sat BIGINT NOT NULL CHECK (amount_sat = 1000),
	credited BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE lightning_tab_payment (
	payment_hash TEXT PRIMARY KEY,
	user_pubkey TEXT NOT NULL,
	invoice TEXT NOT NULL,
	amount_sat BIGINT NOT NULL CHECK (amount_sat > 0),
	fee_sat BIGINT NOT NULL CHECK (fee_sat >= 0),
	-- spent: debited, Ark's normal Lightning send owns the outcome.
	-- refunded: that send failed and the debit was put back.
	status TEXT NOT NULL CHECK (status IN ('spent', 'refunded'))
);
