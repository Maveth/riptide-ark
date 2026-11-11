-- Small Lightning receives credit the tab. Opting out refuses small sends and receives.

ALTER TABLE lightning_tab ADD COLUMN opted_out BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE lightning_tab_receive (
	payment_hash TEXT PRIMARY KEY,
	user_pubkey TEXT NOT NULL,
	amount_sat BIGINT NOT NULL CHECK (amount_sat > 0),
	credited BOOLEAN NOT NULL DEFAULT FALSE
);
