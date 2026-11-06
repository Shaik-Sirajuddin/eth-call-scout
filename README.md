# CallScout

Deterministic wallet authorization and live protocol defense for AI agents.

AI agents are useful planners, but they should not be wallet security boundaries. CallScout lets an agent propose transactions through a restricted provider while ordinary code—not a prompt—decides whether the exact transaction may reach the wallet.

> **AI proposes. Policy decides. Wallet signs.**

CallScout combines four layers:

1. **Executable wallet policy** — exact chains, wallets, contracts, selectors, value and fee ceilings, expiries, and ABI-word constraints.
2. **Authenticated protocol state** — fresh, signed protocol health can veto a whitelisted target when it is degraded, paused, compromised, stale, or unknown.
3. **Full transaction simulation** — independent trace-capable RPCs must agree on call effects, logs, gas, state writes, code changes, and asset movement before forwarding.
4. **Monitoring and evidence** — static call discovery, registry mapping, calldata decoding, interactive reports, and policy-bound authorization receipts.

The call scanner in this repository is one monitoring feature. It does not authorize wallet access and is not the root of trust.

## Why this is different from an agent instruction file

Markdown instructions and system prompts are advisory. They can be ignored, misread, injected, or lost between model calls. CallScout policies are executable JSON evaluated outside the model at the EIP-1193 provider boundary.

The guarded provider:

- forwards a fixed set of read-only RPC methods;
- evaluates the exact `eth_sendTransaction` envelope—including explicit chain, outer nonce, access list, gas, fees, calldata, target, and value—immediately before forwarding;
- requires full call, trace, log, and state-diff simulation after policy and live-state checks;
- denies raw signing, typed-data signing, opaque raw transactions, wallet permission changes, chain switching, and unsupported batch methods;
- forwards a transaction only when every deterministic check passes; and
- emits a receipt containing policy and transaction hashes for audit.

Missing data, invalid policies, unknown targets, unknown selectors, malformed calldata, and failed checks deny by default.

Version 1 has a mandatory secure activation profile: an executable policy must be wallet-bound, expiring, gas-capped, protected by at least two live-state keys with a threshold of two, and configured with at least two simulation sources and a quorum of two. Drafts that do not yet satisfy activation can still be inspected with `callscout policy audit`, but they cannot authorize a wallet.

## Quick start

Requirements: Node.js 22 or newer.

```sh
npm ci

# Validate the executable policy structure.
npx callscout policy validate examples/wallet-policy.json

# Audit a threshold-protected live-state policy.
npx callscout policy audit examples/wallet-policy-live.json

# Run the complete allow/deny scenario demo without a real wallet or RPC.
npm run demo

# Run every syntax check, security test, and the safe demo authorization.
npm run verify
```

An `allow` receipt covers only the normalized transaction hash and authenticated state hash printed in that receipt. The intent must carry its chain and pending outer nonce explicitly; CallScout never lets the wallet silently choose them after simulation. Production integrations must use the guarded provider so the copied request checked by CallScout is the request forwarded to the wallet.

## Web demo

The deployed demo includes the responsive product site plus two outputs generated from the repository's deterministic monitoring tools:

- [CallScout product site](https://shaik-sirajuddin.github.io/eth-call-scout/)
- [Interactive example call report](https://shaik-sirajuddin.github.io/eth-call-scout/report.html)
- [Browser-based ruleset builder](https://shaik-sirajuddin.github.io/eth-call-scout/ruleset.html)

Build and serve the same pages locally:

```sh
npm run site:check
npm run site:serve
# open http://127.0.0.1:4173
```

`site:check` scans the example sources, applies `.secu`, and creates `dist/report.html` and `dist/ruleset.html` alongside the landing page. The report and ruleset editor are monitoring aids, not transaction authorization. Run `npm run demo` to execute the actual offline policy, live-state, simulation, wallet-guard, and audit flow.

## Architecture

```text
Untrusted zone                         Deterministic security boundary

User goal -> AI agent -> tx proposal -> guarded EIP-1193 provider
                                            |
                         +------------------+------------------+
                         |                                     |
                  executable policy                    signed live state
                  + invariant checks                  + freshness checks
                         |                                     |
                         +---------------+---------------------+
                                         |
                           multi-RPC full transaction simulation
                           + call trace + logs + state diff
                                         |
                                  allow / deny receipt
                                         |
                                  wallet only on allow

Supporting evidence: source scanner -> registry -> ABI decoder -> review report
```

The complete trust model is in [Architecture](docs/architecture.md) and [Security model](docs/security-model.md).

## Executable policies

Policies use exact values rather than natural-language intent. The version 1 schema is at [schema/wallet-policy.schema.json](schema/wallet-policy.schema.json).

```json
{
  "version": 1,
  "name": "Conservative mainnet agent",
  "defaultAction": "deny",
  "chains": [1],
  "wallets": ["0x1111111111111111111111111111111111111111"],
  "validUntil": "2030-01-01T00:00:00.000Z",
  "protocolState": {
    "required": true,
    "maxAgeSeconds": 300,
    "threshold": 2,
    "trustedKeys": [
      { "id": "operations", "algorithm": "ed25519", "publicKey": "<base64 SPKI DER>" },
      { "id": "security", "algorithm": "ed25519", "publicKey": "<base64 SPKI DER>" }
    ]
  },
  "simulation": {
    "required": true,
    "blockTag": "pending",
    "quorum": 2,
    "maxBlockSkew": 5,
    "maxGasEstimate": "350000",
    "maxCallDepth": 8,
    "maxInternalCalls": 64,
    "maxStateAccounts": 128,
    "maxStorageWrites": 256,
    "denyCodeChanges": true,
    "eip7702": {
      "allowAuthorizationList": false,
      "allowDelegatedWallet": false,
      "maxAuthorizations": 1,
      "delegates": []
    },
    "allowedCallTypes": ["CALL", "STATICCALL", "DELEGATECALL"],
    "internalTargets": [],
    "assetLimits": [],
    "sources": [
      { "id": "sim-a", "env": "CALLSCOUT_SIM_PRIMARY" },
      { "id": "sim-b", "env": "CALLSCOUT_SIM_SECONDARY" }
    ]
  },
  "invariants": {
    "maxNativeValueWei": "10000000000000000",
    "maxGas": "350000",
    "maxGasPriceWei": "100000000000",
    "maxFeePerGasWei": "100000000000",
    "maxPriorityFeePerGasWei": "5000000000",
    "requireCalldata": true,
    "denyUnlimitedApproval": true
  },
  "contracts": [
    {
      "chainId": 1,
      "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "protocolId": "usdc",
      "maxNativeValueWei": "0",
      "methods": [
        {
          "selector": "0x095ea7b3",
          "name": "approve(address,uint256)",
          "constraints": [
            {
              "type": "address-in",
              "argument": 0,
              "addresses": ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"]
            },
            { "type": "uint-max", "argument": 1, "value": "1000000000" }
          ]
        }
      ]
    }
  ]
}
```

The gate reads the selector and static ABI words directly from calldata. A label such as `approve(address,uint256)` is documentation only; it is never trusted as authorization input. See [Policy reference](docs/policies.md).

## Guard a wallet provider

```js
import { createGuardedProvider } from './src/wallet-guard.js';
import { createFileSequenceStore, createLiveStateSource } from './src/protocol-state.js';
import policy from './agent-policy.json' with { type: 'json' };

const agentProvider = createGuardedProvider({
  provider: walletProvider,
  policy,
  stateSource: createLiveStateSource({
    url: 'https://state.example/callscout.json',
    cachePath: '.cache/callscout/live-state.json',
  }),
  stateSequenceStore: createFileSequenceStore('/trusted/callscout/state-sequence.json'),
  onDecision: (receipt) => appendToAuditLog(receipt),
});

// Give agentProvider—not walletProvider—to the agent runtime.
```

Never expose the underlying wallet provider, signer, seed phrase, private key, session key, or raw-signing API to the agent. Integration requirements are in [Wallet integration](docs/integration.md).

## Full transaction simulation

Every transaction eligible for forwarding must pass the same exact-transaction simulation through a configured quorum of independent, trace-capable RPC endpoints. CallScout requires the proposed outer nonce to match each source's pending account nonce, then evaluates `eth_call`, `eth_estimateGas`, `callTracer` output with logs, and a `prestateTracer` diff using the same access list and envelope fields. It enforces internal call targets and types, call depth/count, gas, native outflow, ERC-20 transfers and approvals, touched accounts, storage writes, and unexpected code changes. Node errors, lag, nonce disagreement, trace disagreement, missing quorum, or malformed output deny.

EIP-7702 is default-deny. An opted-in type-4 transaction additionally requires an authorization signed by the guarded wallet, exact non-zero chain binding, the sender's next valid nonce, one allowlisted delegate with a pinned runtime code hash, and a state diff proving the expected delegation designator. Existing delegated EOAs are independently detected and require a separate opt-in. For both existing and newly installed delegates, every wallet-originated `CALL` and `STATICCALL` in the trace must pass exact contract, selector, calldata, value, and signed live-state rules; wallet-originated `DELEGATECALL` and `CALLCODE` deny. The full trace still applies. See [Full transaction simulation](docs/transaction-simulation.md).

## Live protocol veto

Policies require a fresh protocol-state bundle signed by at least two pinned Ed25519 keys with a threshold of at least two. The verifier checks signatures, issue and expiry times, maximum age, rollback sequence, protocol and chain identity, exact contract binding, and operational status. `degraded`, `paused`, `compromised`, `unknown`, missing, stale, and unauthenticated state all deny.

Fetching and caching never create trust; bundles remain untrusted until they pass inside the authorization path. See [Authenticated protocol state](docs/protocol-state.md).

## Deterministic on-chain monitors

CallScout collects protocol observations from at least two independent RPC endpoints before signing. Monitor configuration pins expected runtime bytecode hashes and can add exact storage-slot and view-call invariants. The secure monitor profile requires a quorum of at least two: matching sources produce `operational`, deterministic mismatches produce `compromised`, and disagreement or outages produce `degraded`.

```sh
export CALLSCOUT_RPC_PRIMARY='https://first-rpc.example'
export CALLSCOUT_RPC_SECONDARY='https://second-rpc.example'

callscout state collect protocol-monitor.json \
  --sequence 42 \
  --out state-payload.json
```

Collection remains separate from signing so RPC-facing monitor processes never need state-signing private keys. See [Protocol monitoring](docs/protocol-monitoring.md).

## Tamper-evident decisions

Authorization receipts can be written to a single-writer, hash-chained JSONL log and verified with `callscout audit verify`. Protect or externally anchor the chain head; hash chaining detects tampering but is not immutable storage by itself. See [Authorization audit log](docs/audit-log.md).

## Monitoring: static call discovery

CallScout can inventory Ethereum interactions in JavaScript and TypeScript. It uses the TypeScript parser and never executes scanned source code.

```sh
npx callscout scan src examples \
  --out reports/eth-calls.html \
  --json reports/eth-calls.json
```

It recognizes ethers `Contract` calls, viem actions, EIP-1193 `request`, provider `send`/`call`, and direct `fetch` JSON-RPC payloads. `--decode` can resolve raw calldata using a verified ABI or selector candidates.

Static discovery is evidence for policy authoring and review. It cannot prove runtime control flow, transaction ordering, protocol safety, or authorization. See [Monitoring](docs/monitoring.md).

## Registry and analyzer rulesets

The registry enriches monitoring reports with known tokens, protocols, and contract roles. It is separate from the executable wallet policy: a registry match is an identity hint, not permission and not proof of safety.

```sh
npx callscout registry sync all
npx callscout registry search uniswap
npm run ruleset:build
```

The standalone `ruleset.html` editor controls report mappings. It does not grant wallet access.

## Security posture

CallScout reduces the authority given to an AI agent; it does not make arbitrary contracts safe. In particular:

- an allowlisted contract can still contain economic or logic risk;
- a policy author can deliberately grant dangerous permissions;
- selectors can collide, so target address and chain are always part of the decision;
- static ABI-word constraints do not decode dynamic tuples or arrays;
- a compromised wallet implementation, host process, policy distribution path, or trusted live-state signer remains in the trusted computing base; and
- simulation cannot predict behavior under every future state, caller, block, or transaction ordering; persistent delegates and protocol contracts still require reviewed identity and conservative limits.

Report vulnerabilities through [SECURITY.md](SECURITY.md). Do not include private keys, seed phrases, production RPC credentials, or exploitable wallet details in public issues.

## Documentation

- [Architecture and trust boundaries](docs/architecture.md)
- [Security and threat model](docs/security-model.md)
- [Policy reference](docs/policies.md)
- [Authenticated live protocol state](docs/protocol-state.md)
- [Deterministic protocol monitoring](docs/protocol-monitoring.md)
- [Full transaction simulation and EIP-7702](docs/transaction-simulation.md)
- [Authorization audit log](docs/audit-log.md)
- [Wallet integration](docs/integration.md)
- [Monitoring and scanner](docs/monitoring.md)
- [Demo runbook](docs/demo.md)
- [Contributing](CONTRIBUTING.md)

## Project status

This is an ETHGlobal prototype under active security hardening. Use test wallets and test networks while evaluating it. A production deployment requires an independent security review of the policy engine, state-signing operations, wallet adapter, and release pipeline.

## Secu pull request review

The repository root `.secu` file is the version 1 JSON ruleset for source review. Its `scanPaths` field selects the files to compare; the current configuration targets `examples/`. On each pull request, the **Secu contract call review** workflow reads and validates `.secu` from the PR base revision, then runs the base revision's Rust parser and diff generator against both the base and proposed source. This keeps a PR from changing the rules or analyzer used to review itself. It publishes a Markdown diff with a risk score, a decision tag (`READY TO APPROVE`, `MAINTAINER REVIEW REQUIRED`, or `BLOCKED · BLACKLISTED / HIGH RISK`), summary, parsed call changes, protocols, and function signatures.

The scanner job has read-only repository permissions. A separate workflow, triggered only after the scan workflow completes, reads the text artifact and posts it as a pull request comment review using the repository token. It does not check out or execute pull request code. Actions are pinned to full commit SHAs.

To change the review scope, edit `scanPaths` in `.secu`; add blacklist/known addresses or registry mappings there to tune risk labels. The scanner compiles from `parser-rs/` via `npm run build:parser`; the JavaScript CLI and report renderer remain in `src/`.
