# Paperclip ASP

Experimental XBT Ark Service Provider based on Bark by Second and the Bark
contributors. This repository contains the server and its shared dependencies.
The wallet and web interface are in [paperclip-wallet-app](https://github.com/connorslab/paperclip-wallet-app).

This is the public source repository for Paperclip's modified Bark `captaind`
server and watchman. It contains build and deployment examples, not production
keys, wallet data, or a preconfigured public operator instance.

Paperclip runs this server in public beta. Funded Lightning requires explicit
configuration; see [implementation and activation requirements](LIGHTNING.md).
Reusable BOLT12 receiving requires `experimental_bolt12_receive` and a compatible
wallet service that stays online. Existing BOLT11 wallets remain supported.

**Experimental. Regtest by default; mainnet requires explicit opt-in.** See
`MAINNET.md`. This software is not independently audited and has no warranty.
Functional tests do not guarantee security or recovery.

Reusable BOLT12 receiving and a configurable
[on-chain payout reserve](docs/payout-liquidity.md) remain supported.

## 0.10.0: Bark 0.8.1 integration

This source integrates upstream Bark 0.8.1 while retaining XBT signatures,
funded exits, economical transfers, BOLT12 receiving, and older Paperclip clients.
It adds Lightning payment accounting records, configurable receive-invoice expiry,
and protection against replacing a round participation whose inputs are already
being processed. See [upgrade requirements](docs/upgrade-0.10.0.md).

## 0.9.0: smaller ordinary-transfer recovery allocations

Enable `experimental_economical_transfers` to advertise the compatible ordinary
transfer profile. A single input allocates 1,056 sats without change or 1,584 sats
with change, about 60% below 0.8.3. Existing signed histories remain unchanged;
legacy clients continue to use their supported profile. Lightning and tree
recovery budgets are unchanged. P2A is not enabled in this release.

Fee estimates fall back independently per target, keep a minimum of 1 sat/vB,
and preserve slow/regular/fast ordering. See [fee validation](docs/fees-0.9.0.md).

## Current maintenance fixes

The source includes receive-pool recovery-time selection, earlier pool
replenishment, and safeguards for the on-chain payout reserve. The receive fix
is deployed on Paperclip's server. Existing wallet protocols remain unchanged.
See [receive recovery time](LIGHTNING.md#receive-recovery-time) and
[validation results](VALIDATION.md#receive-pool-recovery-time-fix--2026-10-02).

## Build

```sh
nix develop --command bash scripts/build.sh
./target/debug/paperclip-asp --help
```

Use the private test setup with the matching wallet revision. The application
uses funded recovery profile 2 with default Knots relay policy and
`acceptnonstdtxn=0`. Unified sighash protection and the explicit network opt-in guard
remain enabled. Ordinary public-key boards, rounds, transfers and exits carry
explicit recovery reserves. See `FUNDED-EXITS.md` for accounting and limits.

## Test the pair

```sh
export PAPERCLIP_WALLET_BIN=/absolute/path/to/paperclip-wallet
export PAPERCLIP_ASP_BIN=/absolute/path/to/paperclip-asp
export PAPERCLIP_WATCHMAN_BIN=/absolute/path/to/paperclip-watchman
export XBT_BITCOIND=/absolute/path/to/verified/knots/bin/bitcoind
nix develop --command bash scripts/test-pair.sh
```

This runs the actual deposit, refresh, transfer, cooperative withdrawal and
server-offline unilateral-exit test. It uses private regtest data, loopback-only
ASP endpoints, the pinned source harness, and no production RPC or wallets.
The fixture creates and cleans up its own daemons. Do not use existing wallet or
chain directories for the fixture. Keep its output private: it contains test data.

`scripts/lab.py` creates a separate profile-2 interactive lab and leaves the old
lab state intact. It is not the complete validation runner; use
`scripts/test-pair.sh` for this profile. Existing lab wallets need a planned
cooperative refresh, not an assumption that old signatures gained reserves.

## Operations and limits

For isolated tests, use a dedicated PostgreSQL database and separate Knots regtest
process. Bind test RPC endpoints to loopback and never connect a production
Lightning node to the test harness. For a deployed server, expose only the public
Ark API through HTTPS. Keep admin, database, blockchain and Lightning management
APIs private. See the deployment guide for configuration and backup requirements.

Comprehensive adversarial testing, production monitoring and independent review
remain prerequisites for production deployment. Lightning and liquidity-pool
allocation require explicit `experimental_funded_lightning` opt-in. See `VALIDATION.md` for verified coverage.
See `PROTOCOL.json`, `UPSTREAM.md` and the original MIT `LICENSE`.

## Deployment and current validation

[Deployment instructions](deployment/README.md) include private configuration, systemd, TLS, and backup requirements.

Profile 2 removes the TRUC/version-3 dependency. See `PROTOCOL.json` and `VALIDATION.md` for the tested scope; mainnet opt-in remains experimental.

## Recovery costs

See [recovery cost accounting and reduction work](docs/recovery-costs.md). Zero
Ark transfer service fees do not mean zero total cost. Recovery allocations are
not separately refundable and are not immediate miner fees.

[Deployed version evidence](docs/deployed-version.md) records the current runtime
identity and the limits of that evidence.
