CREATE TABLE lightning_address (
	name TEXT PRIMARY KEY,
	user_pubkey TEXT NOT NULL UNIQUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE lightning_address_invoice (
	payment_hash TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	user_pubkey TEXT NOT NULL,
	amount_sat BIGINT NOT NULL CHECK (amount_sat > 0),
	preimage BYTEA,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
