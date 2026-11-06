# Architecture and trust boundaries

CallScout is a least-authority bridge between an untrusted AI agent and a wallet. The model may propose actions and inspect public chain state, but it is not allowed to decide which transaction is safe or invoke arbitrary wallet capabilities.

## Decision path

1. The user gives a goal to an agent.
2. The agent constructs an EIP-1193 `eth_sendTransaction` proposal.
3. The guarded provider copies the JSON request and obtains the active chain from the underlying provider.
4. The policy engine normalizes the exact transaction fields and validates the policy.
5. Deterministic checks evaluate wallet, chain, target, selector, value, fees, expiry, and ABI-word constraints.
6. The live-state verifier evaluates an authenticated, fresh protocol-health snapshot bound to the target.
7. Any missing or failed check produces `deny`. Only an all-pass receipt permits forwarding.
8. The copied request that was evaluated is forwarded to the underlying wallet.
9. The receipt is written to an audit sink chosen by the integrator.

The agent never receives the underlying provider. This prevents it from bypassing the guard with `personal_sign`, typed-data signing, `eth_sendRawTransaction`, chain changes, wallet permission changes, or unsupported batch APIs.

## Components

### Guarded provider

`src/wallet-guard.js` is the capability boundary. It exposes a fixed list of read-only RPC methods and one guarded mutation path: `eth_sendTransaction`.

The guard must live in the same trusted process as the wallet adapter or in a smaller isolated service in front of it. Wrapping a provider is ineffective if the agent can also reach the original provider, signer, browser wallet object, session key, or RPC credential with signing authority.

### Policy engine

`src/policy.js` validates policies and evaluates transactions without model calls or network requests. Policies are default-deny and use exact chain IDs, addresses, selectors, and static ABI-word constraints.

Canonical SHA-256 hashes bind each receipt to its policy and normalized transaction. These hashes support audit correlation; they are not signatures.

### Live protocol state

The live-state layer is a second veto. A target can be policy-allowed and still be denied because its authenticated state is stale, missing, degraded, paused, or compromised. State must be signed by keys pinned in policy and checked at authorization time.

The state layer cannot generically discover every exploit. Protocol-specific monitors and independent incident publishers improve coverage, while the wallet gate remains fail-closed when required state is unavailable.

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
| Underlying wallet provider | Yes | Receives only allowed requests |

## Deployment recommendation

For a serious deployment, run the guard as a small service or wallet plugin with no model runtime dependencies. Pin policy and live-state trust roots through a reviewed release process. Send immutable receipts to storage the agent cannot edit. Keep policy authoring and policy activation separate, ideally with human confirmation or multisig approval.
