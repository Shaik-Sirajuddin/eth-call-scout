# Architecture and trust boundaries

CallScout is a least-authority bridge between an untrusted AI agent and a wallet. The model may propose actions and inspect public chain state, but it is not allowed to decide which transaction is safe or invoke arbitrary wallet capabilities.

## Decision path

1. The user gives a goal to an agent.
2. The agent constructs an EIP-1193 `eth_sendTransaction` proposal.
3. The guarded provider copies the JSON request and obtains the active chain from the underlying provider.
4. The policy engine requires and normalizes the exact transaction fields, including chain, outer nonce, type, access list, gas, fees, target, value, and calldata, then validates the policy.
5. Deterministic checks evaluate wallet, chain, target, selector, value, fees, expiry, and ABI-word constraints.
6. The live-state verifier evaluates an authenticated, fresh protocol-health snapshot bound to the target.
7. The simulator first requires every source to agree that the explicit outer nonce is pending, then sends the same normalized transaction to independent trace-capable RPC endpoints and evaluates call results, gas, full call trees and logs, state diffs, asset effects, and EIP-7702 state.
8. A quorum must agree on one passing trace fingerprint. Any policy-violation quorum, missing pass quorum, lag, malformed output, or RPC failure that prevents quorum produces `deny`.
9. Only an all-pass receipt permits the copied request that was evaluated to reach the underlying wallet.
10. The receipt, including simulation fingerprint and source summary, is written to an audit sink chosen by the integrator.

The agent never receives the underlying provider. This prevents it from bypassing the guard with `personal_sign`, typed-data signing, `eth_sendRawTransaction`, chain changes, wallet permission changes, or unsupported batch APIs.

## Components

### Guarded provider

`src/wallet-guard.js` is the capability boundary. It exposes a fixed list of read-only RPC methods and one guarded mutation path: `eth_sendTransaction`.

The guard must live in the same trusted process as the wallet adapter or in a smaller isolated service in front of it. Wrapping a provider is ineffective if the agent can also reach the original provider, signer, browser wallet object, session key, or RPC credential with signing authority.

### Policy engine

`src/policy.js` validates policies and evaluates transactions without model calls or network requests. Policies are default-deny and use exact chain IDs, addresses, selectors, and static ABI-word constraints. Activation additionally requires wallet binding, expiry, a gas cap, two-key live-state threshold protection, and a two-source simulation quorum; incomplete drafts can be audited but cannot authorize.

Canonical SHA-256 hashes bind each receipt to its policy and normalized transaction. These hashes support audit correlation; they are not signatures.

### Live protocol state

The live-state layer is a second veto. A target can be policy-allowed and still be denied because its authenticated state is stale, missing, degraded, paused, or compromised. State must be signed by keys pinned in policy and checked at authorization time.

The state layer cannot generically discover every exploit. Protocol-specific monitors and independent incident publishers improve coverage, while the wallet gate remains fail-closed when required state is unavailable.

The provider keeps the highest authenticated state sequence and can persist it through a trusted sequence store. A signed unsafe status advances this floor, preventing replay of an older operational snapshot. Persistence failures deny before wallet forwarding.

### Protocol monitor

`src/protocol-monitor.js` checks reviewed runtime bytecode hashes, storage slots, and view-call results through independent RPC sources. Duplicate endpoints and lagging nodes are excluded. Matching quorum produces an operational observation; mismatch quorum produces compromised; disagreement or source failure produces degraded. The collector has no signing key.

### Transaction simulator

`src/transaction-simulator.js` is a mandatory final gate, not an LLM tool. It binds the outer nonce with `eth_getTransactionCount(..., "pending")`, then runs the exact transaction with `eth_call`, `eth_estimateGas`, `debug_traceCall` call tracing with logs, and `debug_traceCall` pre/post state diffing. It rejects nonce disagreement, unapproved internal targets or call types, reverts, excessive depth, gas, writes, native outflow, token transfers or approvals, unexpected code changes, trace disagreement, and insufficient quorum.

The simulator reads the sender's current code before tracing. EIP-7702 authorization lists and already-delegated EOAs are default-deny. When explicitly enabled, authorization signature, authority, chain, nonce, delegate identity, runtime code hash, and the exact delegation code change are checked before the ordinary full-trace rules apply.

### Audit log

`src/audit-log.js` writes single-writer, hash-chained JSONL receipts. This makes modification and chain breaks evident when a trusted head is retained. It is not immutable storage and should be protected or anchored externally.

### Monitoring plane

The source scanner, ABI decoder, registry, and HTML report help humans inventory interactions and author policies. They are outside the authorization path. Scanner misses must not create wallet permissions, and registry matches must not imply safety.

## Data boundaries

| Input | Trusted? | Use |
| --- | --- | --- |
| Agent transaction proposal | No | Evaluated as hostile input |
| Function name or UI label | No | Display only |
| Raw calldata | No | Exact selector and word checks |
| Executable policy | Yes, after controlled distribution | Authorization constraints |
| Registry metadata | No for authorization | Monitoring labels only |
| Signed live-state payload | Conditionally | Trusted only after signature, threshold, freshness, and target checks |
| Simulation RPC output | No | Accepted only through structural checks, policy analysis, block-lag limits, and quorum consensus |
| Underlying wallet provider | Yes | Receives only allowed requests |

## Deployment recommendation

For a serious deployment, run the guard as a small service or wallet plugin with no model runtime dependencies. Use independent trace-capable RPC providers, pin policy and live-state trust roots through a reviewed release process, and protect EIP-7702 delegate approvals as security-critical configuration. Send immutable receipts to storage the agent cannot edit. Keep policy authoring and policy activation separate, ideally with human confirmation or multisig approval.
