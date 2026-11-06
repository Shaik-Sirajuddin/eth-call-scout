# Contributing

CallScout sits on a wallet security boundary. Changes should be small, reviewable, default-deny, and covered by tests that prove both allowed and denied behavior.

## Development

```sh
npm ci
npm run verify
```

Use Node.js 22 or newer. Do not commit `.env`, cache files, generated reports, wallet data, private keys, or production RPC credentials.

## Security requirements

- Never use an LLM decision as an authorization signal.
- Never convert registry identity into permission.
- Reject unsupported transaction shapes instead of guessing.
- Preserve exact chain, target, calldata, and value through the authorization-to-forwarding boundary.
- Add a regression test for every deny condition and prove denied requests do not reach the underlying provider.
- Document new trusted inputs and changes to the trusted computing base.
- Treat new RPC mutation methods as new parsers and policy surfaces, not simple allowlist additions.
- Protocol-monitor changes must test pass quorum, mismatch quorum, source disagreement, lag, malformed RPC data, and endpoint restrictions.
- Transaction-simulator changes must test the complete trace and state-diff path, pass/violation quorum, disagreement, lag, reverts, malformed data, and denied-request non-forwarding.
- EIP-7702 changes must preserve default denial and test authorization recovery, authority/chain/nonce binding, delegate code-hash checks, existing delegation, expected code changes, malicious internal effects, and calls hidden inside delegated-wallet batches.

## Pull requests

Explain the threat addressed, security invariants changed, compatibility impact, and verification performed. Keep generated artifacts synchronized with their source. Changes to policy schemas or receipt formats require a versioning note.
