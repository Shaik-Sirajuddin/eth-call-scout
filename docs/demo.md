# Demo runbook

The demo exercises deterministic policy, threshold-signed fresh protocol state, rollback-aware wallet guarding, full transaction simulation, and monitoring without connecting a real wallet or sending a transaction.

## Setup

```sh
git clone https://github.com/x0rc1ph3r/eth-call-scout.git
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

## Live dual-Anvil transaction demo

For the judge-facing flow, run the real local chain instead of the mock scenario harness:

```sh
npm run demo:serve
# open http://127.0.0.1:4174/demo.html
```

The command compiles and deploys the demo market to two distinct Anvil processes, starts the run API, and serves the product. In the control room, a prompt becomes exact swap calldata, then passes through executable policy, a 2-of-2 signed live-state observation, two full call/log/state-diff traces, the guarded provider, and the hash-chained audit log. Safe runs mine on the primary node; compromised protocol state, a hidden internal call, and a reverting slippage path deny without forwarding. Each run remains selectable with its full nine-stage evidence trail. See [Live dual-Anvil demo](anvil-demo.md) for the full architecture and non-interactive command.

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

Judge-facing paths on the public Vercel production domain:

- `/demo.html` — agent control room
- `/report.html` — example interactive report
- `/ruleset.html` — visual wallet policy builder

See [Vercel deployment](deployment.md) for the exact import settings and the deployment-protection check required before sharing the URL.

To generate and serve the same pages locally:

```sh
npm run site:check
npm run site:serve
```

The policy studio supports draggable blocks, explicit connections, pan, zoom, fit-to-view, a minimap, local persistence, import/export, and continuous structural checks. Exported JSON must still pass the authoritative validator before it can be activated:

```sh
npx callscout policy validate path/to/exported-policy.json
```

Or generate a focused report directly:

```sh
npx callscout scan examples/variations.ts \
  --out reports/eth-calls.html \
  --json reports/eth-calls.json
```

Open `reports/eth-calls.html`. Explain that this report is supporting evidence, while the executable policy and provider guard are the authorization boundary.
