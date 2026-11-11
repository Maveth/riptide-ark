ALTER TABLE lightning_tab_return DROP CONSTRAINT lightning_tab_return_pkey;
ALTER TABLE lightning_tab_return ADD PRIMARY KEY (dest_pubkey, vtxo_id);
