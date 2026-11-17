CREATE TABLE lightning_tab_fee_credit (
	payment_hash TEXT PRIMARY KEY,
	user_pubkey TEXT NOT NULL,
	refund_sat BIGINT NOT NULL CHECK (refund_sat > 0),
	kept_sat BIGINT NOT NULL CHECK (kept_sat >= 0),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The 30,000 sat coin payment already returned 311 sats to the tab.
-- Record it so activity can show the 4 sat fee that stayed.
INSERT INTO lightning_tab_fee_credit (payment_hash, user_pubkey, refund_sat, kept_sat)
SELECT a.payment_hash, t.user_pubkey, 311, 4
FROM lightning_payment_attempt a
JOIN lightning_tab t ON t.user_pubkey = (
	SELECT user_pubkey FROM lightning_tab_receive
	WHERE credited
	GROUP BY user_pubkey
	HAVING count(*) = 4
	LIMIT 1
)
WHERE a.status = 'succeeded'
	AND a.user_fee_sat = 315
	AND a.amount_msat = 30000000
	AND a.final_amount_msat = 30002450
	AND NOT EXISTS (
		SELECT 1 FROM lightning_tab_payment p WHERE p.payment_hash = a.payment_hash
	);
