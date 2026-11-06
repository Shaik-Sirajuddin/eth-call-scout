# Demo runbook

The demo exercises deterministic policy, threshold-signed fresh protocol state, rollback-aware wallet guarding, full transaction simulation, and monitoring without connecting a real wallet or sending a transaction.

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

The demo uses two independent monitor RPC endpoints and two independent trace-simulation endpoints, deterministic bytecode/storage/view-call monitoring, two ephemeral Ed25519 signers, a mandatory signature threshold, executable wallet policy, a guarded mock wallet, rollback tracking, and a hash-chained audit log.

It runs six scenarios:

1. healthy protocol plus bounded approval — allowed and forwarded;
2. whitelisted contract with changed runtime bytecode — denied by live state;
3. healthy protocol with an unapproved spender — denied by calldata policy;
4. simulation reveals an unauthorized internal call — denied by trace policy and consensus;
5. stale signed state — denied by freshness and expiry; and
6. opaque `personal_sign` — denied at the RPC boundary.

The final summary must report `forwardedTransactions: 1`. Every denied scenario must report `walletForwarded: false`, and the audit chain must be valid with six records.

No signing key is written to disk and no network transaction is sent.

## Test the security boundary

```sh
npm run verify
```

The tests cover secure activation rejection, policy validation, exact calldata constraints, explicit outer nonce and active-chain binding, bounded access-list parsing, signature quorum, state tampering, stale/expired/compromised state, contract binding, rollback, persistent-store failure, monitor and simulation RPC quorums, full call traces, state diffs, trace disagreement, unauthorized internal calls, EIP-7702 default denial and safe opt-in, existing and freshly installed delegate batches, wallet-originated call/static-call policy and live-state checks, delegate code identity, bytecode mismatches, lagging nodes, cache fallback, audit-log tampering, and denied-request non-forwarding.

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
