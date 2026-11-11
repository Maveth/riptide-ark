ALTER TABLE lightning_tab_fund
	ADD COLUMN returned BOOLEAN NOT NULL DEFAULT FALSE,
	ADD COLUMN return_vtxo_id TEXT;

ALTER TABLE lightning_tab_fund DROP CONSTRAINT IF EXISTS lightning_tab_fund_amount_sat_check;
ALTER TABLE lightning_tab_fund ADD CHECK (amount_sat > 0);

CREATE TABLE lightning_tab_return (
	dest_pubkey TEXT PRIMARY KEY,
	user_pubkey TEXT NOT NULL,
	amount_sat BIGINT NOT NULL CHECK (amount_sat > 0),
	vtxo_id TEXT NOT NULL
);
