# Keybound

Deterministic wallet authorization and live protocol defense for AI agents.

AI agents are useful planners, but they should not be wallet security boundaries. Keybound lets an agent propose transactions through a restricted provider while ordinary code—not a prompt—decides whether the exact transaction may reach the wallet.

> **AI proposes. Policy decides. Wallet signs.**

Keybound combines four layers:

1. **Executable wallet policy** — exact chains, wallets, contracts, selectors, value and fee ceilings, expiries, and ABI-word constraints.
2. **Authenticated protocol state** — fresh, signed protocol health can veto a whitelisted target when it is degraded, paused, compromised, stale, or unknown.
3. **Full transaction simulation** — independent trace-capable RPCs must agree on call effects, logs, gas, state writes, code changes, and asset movement before forwarding.
4. **Monitoring and evidence** — static call discovery, registry mapping, calldata decoding, interactive reports, and policy-bound authorization receipts.

The call scanner in this repository is one monitoring feature. It does not authorize wallet access and is not the root of trust.

## Why this is different from an agent instruction file

Markdown instructions and system prompts are advisory. They can be ignored, misread, injected, or lost between model calls. Keybound policies are executable JSON evaluated outside the model at the EIP-1193 provider boundary.

The guarded provider:

- forwards a fixed set of read-only RPC methods;
- evaluates the exact `eth_sendTransaction` envelope—including explicit chain, outer nonce, access list, gas, fees, calldata, target, and value—immediately before forwarding;
- requires full call, trace, log, and state-diff simulation after policy and live-state checks;
- denies raw signing, typed-data signing, opaque raw transactions, wallet permission changes, chain switching, and unsupported batch methods;
- forwards a transaction only when every deterministic check passes; and
- emits a receipt containing policy and transaction hashes for audit.

Missing data, invalid policies, unknown targets, unknown selectors, malformed calldata, and failed checks deny by default.

Version 1 has a mandatory secure activation profile: an executable policy must be wallet-bound, expiring, gas-capped, protected by at least two live-state keys with a threshold of two, and configured with at least two simulation sources and a quorum of two. Drafts that do not yet satisfy activation can still be inspected with `keybound policy audit`, but they cannot authorize a wallet.

## Quick start

Requirements: Node.js 22 or newer. The real local-chain demo also requires [Foundry](https://book.getfoundry.sh/getting-started/installation) (`forge` and `anvil`).

```sh
npm ci

# Validate the executable policy structure.
npx keybound policy validate examples/wallet-policy.json

# Audit a threshold-protected live-state policy.
npx keybound policy audit examples/wallet-policy-live.json

# Run the complete allow/deny scenario demo without a real wallet or RPC.
npm run demo

# Start the judge-facing Next.js app, Gateway API, contracts, and both Anvil nodes.
npm run dev
# open http://127.0.0.1:3000
# click "Run the 2-transaction demo" to mine one safe trade and block one compromised trade

# In another terminal, exercise the external-agent API without a signer.
npm run agent:smoke -- --origin http://127.0.0.1:3000

# Or run all four real-chain scenarios non-interactively and exit.
npm run anvil:smoke

# Run every syntax check, security test, and the safe demo authorization.
npm run verify
```

An `allow` receipt covers only the normalized transaction hash and authenticated state hash printed in that receipt. The intent must carry its chain and pending outer nonce explicitly; Keybound never lets the wallet silently choose them after simulation. Production integrations must use the guarded provider so the copied request checked by Keybound is the request forwarded to the wallet.

## Product surfaces

The Next.js app serves the complete responsive demo from one origin:

- `/` — product story and architecture;
- `/runs` — guided two-transaction proof, custom agent tests, and persistent run history;
- `/runs/:id` — complete evidence for one decision;
- `/report` — interactive call-surface report;
- `/policy` — AI-assisted plain-language policy builder with an advanced zoomable block editor; and
- `/api/v1/agent/*` — the restricted interface used by an external AI agent.

`npm run dev` owns the full local lifecycle: it compiles the demo contracts, starts two independent Anvil execution sources, deploys identical fixtures, starts the wallet-policy Gateway, and serves Next.js at `http://127.0.0.1:3000`. Press `Ctrl+C` once to stop the app and both child nodes. Run `npm run demo:reset` only when you intentionally want to delete generated local run history before recording a clean demo.

The Policy Studio can translate a plain-language description into constrained rules and then into the visual graph. AI output is always an untrusted draft: server-side code resolves registry identities, rejects unsupported clauses, and runs the authoritative activation validator. Neither the prompt nor the canvas activates or enforces policy. Run `npx keybound policy validate <exported-policy.json>` before controlled activation. See the [policy reference](docs/policies.md), [Gateway API](docs/api.md), and [Vercel deployment](docs/deployment.md).

The current Vercel configuration builds the Next.js interface. The local Anvil Gateway is deliberately loopback-only and is not a production serverless backend. The later testnet beta requires authenticated agents, durable storage, independent remote RPC providers, and an isolated signer adapter before `/runs` can execute hosted transactions; the deployment guide states this boundary explicitly.

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

## Protection on by default

- **Attacker list:** `data/attacker-addresses.json` holds known attacker and exploiter addresses, always on. A transaction that would pay, approve or name one is denied. A [free API](docs/attacker-list.md) serves the latest list, and `npx keybound attackers update` downloads it.
- **Per-block spend limits:** set the most a wallet may send in one block. Going over denies the transaction and writes an alert. See [Per-block spend limits](docs/policies.md#per-block-spend-limits).
- **On-chain checks:** after a transaction lands, the guard confirms it matches what was approved. Failures go to an alert log you can read with `npx keybound alerts show`. See [Alerts and on-chain checks](docs/integration.md#alerts-and-on-chain-checks).
- **Default rule sets:** `npx keybound policy init` builds a policy for a general user, swapper, lender or payments wallet, with low limits you can change. See [Default rule sets](docs/policies.md#default-rule-sets).

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
    url: 'https://state.example/keybound.json',
    cachePath: '.cache/keybound/live-state.json',
  }),
  stateSequenceStore: createFileSequenceStore('/trusted/keybound/state-sequence.json'),
  onDecision: (receipt) => appendToAuditLog(receipt),
});

// Give agentProvider—not walletProvider—to the agent runtime.
```

Never expose the underlying wallet provider, signer, seed phrase, private key, session key, or raw-signing API to the agent. Integration requirements are in [Wallet integration](docs/integration.md).

## Full transaction simulation

Every transaction eligible for forwarding must pass the same exact-transaction simulation through a configured quorum of independent, trace-capable RPC endpoints. Keybound requires the proposed outer nonce to match each source's pending account nonce, then evaluates `eth_call`, `eth_estimateGas`, `callTracer` output with logs, and a `prestateTracer` diff using the same access list and envelope fields. It enforces internal call targets and types, call depth/count, gas, native outflow, ERC-20 transfers and approvals, touched accounts, storage writes, and unexpected code changes. Node errors, lag, nonce disagreement, trace disagreement, missing quorum, or malformed output deny.

EIP-7702 is default-deny. An opted-in type-4 transaction additionally requires an authorization signed by the guarded wallet, exact non-zero chain binding, the sender's next valid nonce, one allowlisted delegate with a pinned runtime code hash, and a state diff proving the expected delegation designator. Existing delegated EOAs are independently detected and require a separate opt-in. For both existing and newly installed delegates, every wallet-originated `CALL` and `STATICCALL` in the trace must pass exact contract, selector, calldata, value, and signed live-state rules; wallet-originated `DELEGATECALL` and `CALLCODE` deny. The full trace still applies. See [Full transaction simulation](docs/transaction-simulation.md).

Every allowed function also has its own gas limit, measured from real mainnet use of Uniswap, Aave and other listed protocols, so a valid call padded to waste gas is denied even when simulation finds nothing else wrong. Each rule carries a version tag and is pinned to the contract code it was measured on. After a protocol upgrade it stops denying, so outdated numbers do not block honest calls. See [Function gas limits](docs/policies.md#function-gas-limits).

## Live protocol veto

Policies require a fresh protocol-state bundle signed by at least two pinned Ed25519 keys with a threshold of at least two. The verifier checks signatures, issue and expiry times, maximum age, rollback sequence, protocol and chain identity, exact contract binding, and operational status. `degraded`, `paused`, `compromised`, `unknown`, missing, stale, and unauthenticated state all deny.

Fetching and caching never create trust; bundles remain untrusted until they pass inside the authorization path. See [Authenticated protocol state](docs/protocol-state.md).

## Deterministic on-chain monitors

Keybound collects protocol observations from at least two independent RPC endpoints before signing. Monitor configuration pins expected runtime bytecode hashes and can add exact storage-slot and view-call invariants. The secure monitor profile requires a quorum of at least two: matching sources produce `operational`, deterministic mismatches produce `compromised`, and disagreement or outages produce `degraded`.

```sh
export CALLSCOUT_RPC_PRIMARY='https://first-rpc.example'
export CALLSCOUT_RPC_SECONDARY='https://second-rpc.example'

keybound state collect protocol-monitor.json \
  --sequence 42 \
  --out state-payload.json
```

Collection remains separate from signing so RPC-facing monitor processes never need state-signing private keys. See [Protocol monitoring](docs/protocol-monitoring.md).

## Tamper-evident decisions

Authorization receipts can be written to a single-writer, hash-chained JSONL log and verified with `keybound audit verify`. Protect or externally anchor the chain head; hash chaining detects tampering but is not immutable storage by itself. See [Authorization audit log](docs/audit-log.md).

## Monitoring: static call discovery

Keybound can inventory Ethereum interactions in JavaScript and TypeScript. It uses the TypeScript parser and never executes scanned source code.

```sh
npx keybound scan src examples \
  --out reports/eth-calls.html \
  --json reports/eth-calls.json
```

It recognizes ethers `Contract` calls, viem actions, EIP-1193 `request`, provider `send`/`call`, and direct `fetch` JSON-RPC payloads. `--decode` can resolve raw calldata using a verified ABI or selector candidates.

Static discovery is evidence for policy authoring and review. It cannot prove runtime control flow, transaction ordering, protocol safety, or authorization. See [Monitoring](docs/monitoring.md).

## Registry and analyzer rulesets

The registry enriches monitoring reports with known tokens, protocols, and contract roles. It is separate from the executable wallet policy: a registry match is an identity hint, not permission and not proof of safety.

```sh
npx keybound registry sync all
npx keybound registry search uniswap
npm run ruleset:build
```

`npm run ruleset:build` generates two standalone artifacts. `ruleset.html` contains Policy Studio and its visual advanced editor; `pr-review-ruleset.html` controls PR Review Agent evidence and cannot grant wallet access. Plain-language generation calls the Next.js `/api/policy/compile-prompt` route, while the visual editor, import, export, and browser checks remain available in the standalone artifact. The app uses AI translation when `OPENAI_API_KEY` is configured and the strict canonical-rule fallback otherwise. A generated policy remains untrusted until the deterministic CLI validator and guarded provider accept it.

## Security posture

Keybound reduces the authority given to an AI agent; it does not make arbitrary contracts safe. In particular:

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
- [Gateway API](docs/api.md)
- [Attacker list and free API](docs/attacker-list.md)
- [Monitoring and scanner](docs/monitoring.md)
- [Live dual-Anvil runbook](docs/anvil-demo.md)
- [Demo and verification guide](docs/demo.md)
- [Vercel deployment](docs/deployment.md)
- [Contributing](CONTRIBUTING.md)

## Project status

This is an ETHGlobal prototype under active security hardening. Use test wallets and test networks while evaluating it. A production deployment requires an independent security review of the policy engine, state-signing operations, wallet adapter, and release pipeline.

## Secu pull request review

The repository root `.secu` file is the version 1 JSON ruleset for source review. Its `scanPaths` field selects the files to compare; the current configuration targets `examples/`. On each pull request, the **Secu contract call review** workflow reads and validates `.secu` from the PR base revision, then runs the base revision's Rust parser and diff generator against both the base and proposed source. This keeps a PR from changing the rules or analyzer used to review itself. It publishes a Markdown diff with a risk score, a decision tag (`READY TO APPROVE`, `MAINTAINER REVIEW REQUIRED`, or `BLOCKED · BLACKLISTED / HIGH RISK`), summary, parsed call changes, protocols, and function signatures.

The scanner job has read-only repository permissions. A separate workflow, triggered only after the scan workflow completes, reads the text artifact and posts it as a pull request comment review using the repository token. It does not check out or execute pull request code. Actions are pinned to full commit SHAs.

To change the review scope, edit `scanPaths` in `.secu`; add blacklist/known addresses or registry mappings there to tune risk labels. The scanner compiles from `parser-rs/` via `npm run build:parser`; the JavaScript CLI and report renderer remain in `src/`.
