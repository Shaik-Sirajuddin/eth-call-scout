# Security and threat model

## Goal

An AI agent may read public wallet and chain state and propose a narrow set of transactions. It must not be able to sign arbitrary messages, change its own policy, forge protocol health, or bypass checks on the exact transaction sent to the wallet.

## Adversaries considered

- a prompt-injected, compromised, or simply mistaken agent;
- malicious content returned by a website, protocol, tool, or RPC response;
- a transaction proposal with deceptive labels but hostile calldata;
- stale protocol metadata after an incident or emergency pause;
- a compromised single live-state publisher when a signature threshold is configured;
- replay of an old authorization receipt or old protocol-state snapshot; and
- configuration mistakes such as wildcard-like permissions, unbounded approvals, missing expiries, or policies not bound to a wallet.

## Security invariants

- The policy default is always deny.
- Authorization uses chain, target, selector, calldata, value, gas, and fee fields—not natural-language descriptions.
- Unknown chains, targets, selectors, and RPC mutation methods deny.
- Invalid or expired policies deny.
- A denied request is never forwarded.
- Unlimited ERC-20 approvals are blocked by the secure profile.
- Approval spender and amount limits can be enforced from ABI words.
- The active wallet chain is obtained independently from the transaction proposal.
- Read access does not imply signing access.
- Live protocol state is a veto and can never turn a policy denial into an allow.
- Receipt hashes identify the exact normalized policy and transaction evaluated.

## Trusted computing base

The current trusted computing base includes:

- the CallScout policy evaluator and guarded-provider code;
- the Node.js runtime and host operating system;
- the activated policy and its distribution path;
- the wallet implementation and its provider transport;
- configured live-state signing keys and the process that protects their private keys; and
- any audit storage relied upon for incident reconstruction.

The model runtime, prompt, source scanner, registry, function labels, report UI, and unsigned network data are not trusted for authorization.

## Known limitations

Version 1 constraints inspect static 32-byte ABI words. They do not interpret dynamic arrays, dynamic bytes, nested tuples, contract-internal calls, or runtime slippage. Complex protocols should expose purpose-built policy adapters or transaction simulations whose outputs are independently bound and verified.

An allowlisted upgradeable proxy can change behavior without changing its address. Live-state monitors should track implementation slots, code hashes, pause state, oracle health, and protocol-specific incident signals where applicable.

No automated system can guarantee a protocol is uncompromised. CallScout reduces blast radius and adds independent vetoes; it does not replace protocol audits, wallet security, incident response, or cautious limits.

## Fail-closed behavior

Every executable policy requires authenticated live state. Production policies should also require bounded expiry, wallet binding, and method constraints. Network errors, stale snapshots, invalid signatures, threshold failures, state that does not name the exact contract, rollback-store failures, or unsupported transaction forms deny.

## Reporting vulnerabilities

Follow the private reporting guidance in the repository's `SECURITY.md`. Never test with funds you cannot afford to lose.
