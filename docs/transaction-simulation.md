# Full transaction simulation

CallScout requires simulation for every transaction that could be forwarded to a wallet. Simulation runs after deterministic policy and authenticated live-state checks and before `eth_sendTransaction`. It is ordinary code with strict parsers and quorum rules; no model output participates in the decision.

Transactions denied by an earlier check are not simulated because they can never reach the wallet. Read-only RPC calls do not enter the mutation path.

## What “full” means

For the exact normalized transaction, each configured source must provide:

1. `eth_chainId` for exact network binding and `eth_blockNumber` for lag filtering;
2. `eth_getTransactionCount(..., "pending")` to bind the explicit outer nonce;
3. `eth_getCode` for sender and any EIP-7702 delegate inspection;
4. `eth_call` for top-level execution and revert detection;
5. `eth_estimateGas` for the configured gas ceiling;
6. `debug_traceCall` with `callTracer` and logs for the complete internal call tree; and
7. `debug_traceCall` with `prestateTracer` in diff mode for account, storage, and code effects.

The analyzer first proves that the trace root exactly matches sender, target, calldata, and value. It then enforces call type, chain-bound internal target allowlists, maximum depth and count, native outflow, gas, touched accounts, storage writes, code changes, ERC-20 transfers, ERC-20 approvals, recipients, and spenders. ERC-721-style event shapes, ERC-1155 wallet outflows, and operator-wide approvals deny until purpose-built asset policies exist. It canonicalizes the observed effects into a fingerprint. At least `quorum` sources must agree on one passing fingerprint, and a violation quorum always vetoes.

The secure activation profile requires at least two sources and a passing quorum of at least two. RPC URLs must be HTTPS except for loopback development, may not contain credentials, must be distinct, and are subject to response size and timeout limits. Sources beyond `maxBlockSkew` are excluded. Trace errors and unsupported tracer behavior fail closed.

## Supported transaction envelopes

- omitted type, legacy/type `0`, and EIP-1559/type `2` use the normal policy, state, and simulation path, but must carry an explicit chain and outer nonce;
- type-2 access lists are strictly parsed, bounded, included in the transaction hash, and passed unchanged to every simulator; legacy access lists deny;
- EIP-7702/type `4` uses the additional controls below; and
- type `1`, type `3` blob transactions, raw signed transactions, opaque message signing, wallet batch APIs such as `wallet_sendCalls`, and other wallet mutation APIs deny until purpose-built parsers and equivalent simulation coverage exist.

Native transfers require an exact contract entry with `allowEmptyCalldata: true` and compatible global policy. A transaction type being supported does not make its target or method allowed.

## EIP-7702

EIP-7702 changes persistent account code, so exact-transaction simulation is necessary but not sufficient. A delegate can be dormant in the simulated path and behave differently for a future caller, block, storage value, or calldata. CallScout therefore combines simulation with code identity.

By default, both `allowAuthorizationList` and `allowDelegatedWallet` are `false`.

For an opted-in type-4 authorization list, CallScout requires:

- an explicit type-4 envelope with exactly one authorization;
- authorization chain equal to the transaction chain—chain ID zero is rejected;
- signature recovery to the exact guarded wallet;
- outer transaction nonce equal to the sender's pending nonce at every simulation source;
- authorization nonce equal to that exact outer nonce plus one, matching EIP-7702 processing for a self-authorization;
- a non-zero delegate chain/address pair present in policy;
- delegate runtime bytecode matching its pinned Keccak-256 hash at every agreeing source;
- no delegate-to-delegate chain; and
- a state diff that proves the wallet changed to exactly `0xef0100 || delegate` and contains no other unexpected code change.

The type-4 transaction then undergoes the same call-tree, log, state, gas, value, and asset checks as every other transaction. A reverted execution is denied; CallScout will not forward it. This is especially important because EIP-7702 authorization processing is persistent even when the later execution fails.

For an already-delegated EOA, CallScout reads its 23-byte delegation designator, requires the separate `allowDelegatedWallet` permission, resolves the delegate, and checks the same pinned runtime code hash before tracing. Unexpected sender code, an unapproved delegate, missing code, a hash mismatch, or a delegation chain denies.

### Batches from a delegated wallet

A delegated EOA can call itself through a batch function such as `execute(...)`. To allow this, add the wallet as a contract entry with its batch selector, and have signed protocol state name the wallet.

CallScout does not decode batch formats, because each delegate has its own. It reads the simulated call tree instead. Every call sent by the wallet must pass the same target, selector, approval, ABI-word, native-value, and live-state rules as a top-level transaction:

- This covers nested self-calls, so a batch cannot reach a wallet function such as `addOwner` unless policy lists that selector.
- Native value is summed per target across the batch before the contract limit is applied.
- `DELEGATECALL` and `CALLCODE` from the wallet deny, because they run other code with the wallet's authority. Delegates that are proxies are therefore not supported yet.
- `STATICCALL` from the wallet cannot change state, but still requires an exact contract entry, allowed selector/calldata, and operational signed protocol state. Read access to a compromised protocol is not silently exempted.
- `internalTargets` does not permit a call sent by the wallet. That call needs a full contract entry.

Each receipt lists these calls under `simulation.metrics.walletCalls`.

`wallet_sendCalls` stays denied. With that API the wallet chooses the final transaction, so CallScout cannot simulate the exact transaction it would forward.

The same trace rules apply when a type-4 transaction installs a delegate and invokes its batch path immediately; safety is not deferred until a later transaction.

## Gas limits per function

Passing simulation does not prove a call is cheap. An attacker can keep the same valid function and pad it, for example with extra swap hops, so funds stay safe and the wallet still pays for the waste.

After tracing, each source reads the code version of every contract with a measured gas rule, then applies the function's limit to the transaction `gas`, the estimate, and the root trace's `gasUsed`. Each call the wallet itself makes inside a batch is checked against its own function limit. A trace that omits `gasUsed` on its root or on a call the wallet makes is malformed, so that source fails. A rule whose pinned code version no longer matches stops denying, and the policy's contract limit or overall cap applies instead. A failed version read fails closed. See [Function gas limits](policies.md#function-gas-limits).

## Security boundary and limitations

Simulation describes one exact transaction against one sampled state. Between simulation and inclusion, balances, storage, prices, mempool ordering, block values, and protocol state may change. Independent RPC quorum reduces reliance on one provider but does not eliminate common client bugs or coordinated provider failure.

Use short-lived policies, conservative slippage and asset ceilings, fresh signed protocol state, protected delegate registries, and wallet-native confirmation for high-value actions. A passing simulation is an authorization requirement, not a guarantee of economic profit or future contract safety.
