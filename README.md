# CallScout

Deterministic wallet authorization and live protocol defense for AI agents.

AI agents are useful planners, but they should not be wallet security boundaries. CallScout lets an agent propose transactions through a restricted provider while ordinary code—not a prompt—decides whether the exact transaction may reach the wallet.

> **AI proposes. Policy decides. Wallet signs.**

CallScout combines three layers:

1. **Executable wallet policy** — exact chains, wallets, contracts, selectors, value and fee ceilings, expiries, and ABI-word constraints.
2. **Authenticated protocol state** — fresh, signed protocol health can veto a whitelisted target when it is degraded, paused, compromised, stale, or unknown.
3. **Monitoring and evidence** — static call discovery, registry mapping, calldata decoding, interactive reports, and policy-bound authorization receipts.

The call scanner in this repository is one monitoring feature. It does not authorize wallet access and is not the root of trust.

## Why this is different from an agent instruction file

Markdown instructions and system prompts are advisory. They can be ignored, misread, injected, or lost between model calls. CallScout policies are executable JSON evaluated outside the model at the EIP-1193 provider boundary.

The guarded provider:

- forwards a fixed set of read-only RPC methods;
- evaluates the exact `eth_sendTransaction` fields immediately before forwarding;
- denies raw signing, typed-data signing, opaque raw transactions, wallet permission changes, chain switching, and unsupported batch methods;
- forwards a transaction only when every deterministic check passes; and
- emits a receipt containing policy and transaction hashes for audit.

Missing data, invalid policies, unknown targets, unknown selectors, malformed calldata, and failed checks deny by default.

## Quick start

Requirements: Node.js 22 or newer.

```sh
npm ci

# Validate the executable policy structure.
npx callscout policy validate examples/wallet-policy.json

# Audit a threshold-protected live-state policy.
npx callscout policy audit examples/wallet-policy-live.json

# Run a fresh end-to-end threshold-signed authorization without a real wallet.
npm run demo:live

# Run every syntax check, security test, and the safe demo authorization.
npm run verify
```

An `allow` receipt covers only the normalized transaction hash and authenticated state hash printed in that receipt. Production integrations must use the guarded provider so the checked transaction is the transaction forwarded to the wallet.

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
  "invariants": {
    "maxNativeValueWei": "10000000000000000",
    "maxGas": "350000",
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

## Live protocol veto

Policies can require a fresh protocol-state bundle signed by a threshold of pinned Ed25519 keys. The verifier checks signatures, issue and expiry times, maximum age, rollback sequence, protocol and chain identity, exact contract binding, and operational status. `degraded`, `paused`, `compromised`, `unknown`, missing, stale, and unauthenticated state all deny.

Fetching and caching never create trust; bundles remain untrusted until they pass inside the authorization path. See [Authenticated protocol state](docs/protocol-state.md).

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
- simulation and monitoring are evidence, not authorization.

Report vulnerabilities through [SECURITY.md](SECURITY.md). Do not include private keys, seed phrases, production RPC credentials, or exploitable wallet details in public issues.

## Documentation

- [Architecture and trust boundaries](docs/architecture.md)
- [Security and threat model](docs/security-model.md)
- [Policy reference](docs/policies.md)
- [Authenticated live protocol state](docs/protocol-state.md)
- [Wallet integration](docs/integration.md)
- [Monitoring and scanner](docs/monitoring.md)
- [Demo runbook](docs/demo.md)
- [Contributing](CONTRIBUTING.md)

## Project status

This is an ETHGlobal prototype under active security hardening. Use test wallets and test networks while evaluating it. A production deployment requires an independent security review of the policy engine, state-signing operations, wallet adapter, and release pipeline.
