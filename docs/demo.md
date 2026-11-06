# Demo runbook

The demo exercises deterministic policy, threshold-signed fresh protocol state, rollback-aware wallet guarding, and monitoring without connecting a real wallet or sending a transaction.

## Setup

```sh
git clone https://github.com/Shaik-Sirajuddin/eth-call-scout.git
cd eth-call-scout
npm ci
```

## End-to-end decision scenarios

```sh
npm run demo
```

The demo uses two independent simulated RPC endpoints, deterministic bytecode/storage/view-call monitoring, two ephemeral Ed25519 signers, a mandatory signature threshold, executable wallet policy, a guarded mock wallet, rollback tracking, and a hash-chained audit log.

It runs five scenarios:

1. healthy protocol plus bounded approval — allowed and forwarded;
2. whitelisted contract with changed runtime bytecode — denied by live state;
3. healthy protocol with an unapproved spender — denied by calldata policy;
4. stale signed state — denied by freshness and expiry; and
5. opaque `personal_sign` — denied at the RPC boundary.

The final summary must report `forwardedTransactions: 1`. Every denied scenario must report `walletForwarded: false`, and the audit chain must be valid with five records.

No signing key is written to disk and no network transaction is sent.

## Test the security boundary

```sh
npm run verify
```

The tests cover policy validation, exact calldata constraints, signature quorum, state tampering, stale/expired/compromised state, contract binding, rollback, persistent-store failure, RPC quorum, bytecode mismatches, lagging nodes, cache fallback, audit-log tampering, and denied-request non-forwarding.

## Real monitor pipeline

`examples/protocol-monitor.demo.json` contains synthetic invariants for offline demonstration only. For a real integration, replace every invariant with reviewed deployment data, configure independent RPC endpoints, then collect and sign:

```sh
export CALLSCOUT_RPC_PRIMARY='https://first-independent-rpc.example'
export CALLSCOUT_RPC_SECONDARY='https://second-independent-rpc.example'

npx callscout state collect protocol-monitor.json \
  --sequence 42 \
  --out state-payload.json
```

Follow [Deterministic protocol monitoring](protocol-monitoring.md) for the separate signing and verification steps.

## Monitoring demo

```sh
npx callscout scan examples/variations.ts \
  --out reports/eth-calls.html \
  --json reports/eth-calls.json
```

Open `reports/eth-calls.html`. Explain that this report is supporting evidence, while the executable policy and provider guard are the authorization boundary.
