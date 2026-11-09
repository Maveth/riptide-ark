# Upgrading to 0.10.0

This version integrates Bark 0.8.1, commit
`303682063ed7559b06dcf37c5cb37bb7037b943f`, with the XBT protocol extensions.
It does not enable P2A or lower signed recovery reserves.

## Prepare the server

Upgrade the ASP before distributing the matching wallet update. Keep the existing
CLN node, keys, channels, and hold plugin running. Check that its RPC and hold
interfaces are reachable and that the blockchain backend is synchronized.

Back up the complete ASP data directory, configuration, and PostgreSQL database.
Verify that the database dump can be read. Keep the public API unavailable while
the ASP and watchman are stopped for migration. Drain outgoing payments and
incoming subscriptions first; do not abandon a payment with unresolved HTLCs.

The database schema advances from 68 to 80. With both old processes stopped,
run these commands using the new binary and the existing configuration:

```sh
paperclip-asp --config /path/to/asp.json data fix-board-expiry-policy
paperclip-asp --config /path/to/asp.json data fix-offboard-vtxos
paperclip-asp --config /path/to/asp.json data backfill-htlc-vtxos
paperclip-asp --config /path/to/asp.json data backfill-cln-hold
```

These commands connect to the database and apply schema migrations before their
data backfills. The hold backfill understands both BOLT11 and XBT BOLT12 records.
Check every command's result before starting the new ASP and watchman.

Verify their blockchain tips, wallets, Lightning connections, public API, and
dependent applications before reopening access. Keep monitoring enabled.
Do not automatically start an older binary against the migrated database or
restore stale financial state after the server has accepted new operations.

## Compatibility

Existing signed recovery histories and ordinary-transfer reserve profiles are
preserved. The previous watchman administration service name remains available.
Older clients retain their supported wire messages and reimbursement flow.
The new expiry field is optional; existing clients use the configured default.

Complete-wallet backups remain necessary. A seed alone does not preserve all
Ark recovery state. Wallet upgrades may migrate local state; do not downgrade
an updated wallet with pending payments or recovery actions.

## Validation scope

The integration was tested with a populated schema-68 database, a migration to
schema 80, and the released Paperclip Wallet 0.9.3. Existing balances survived,
an Ark transfer completed, and a unilateral exit confirmed with the ASP offline.
The same older wallet completed BOLT11 and BOLT12 sends and receives through the
upgraded server in isolated XBT regtest. An unreachable recipient failed without
changing the wallet balance. A pending Lightning payment survived a server
restart; after receiver cancellation, the wallet recovered its principal, with
only the recorded recovery allocations deducted and no duplicate credit.

The hold backfill was run twice against a copied test database containing BOLT11
and BOLT12 subscriptions. It preserved the corresponding holds without creating
duplicates. All 189 server library tests passed.

These are functional checks, not an independent security audit. Release-specific
package, payment-recovery, and deployment checks must also pass before rollout.
