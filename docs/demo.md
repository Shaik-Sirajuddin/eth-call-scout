# Demo runbook

The demo exercises deterministic policy, threshold-signed fresh protocol state, rollback-aware wallet guarding, and monitoring without connecting a real wallet or sending a transaction.

## Setup

```sh
git clone https://github.com/Shaik-Sirajuddin/eth-call-scout.git
cd eth-call-scout
npm ci
```

## Full authorization path

```sh
npm run demo:live
```

The script creates two ephemeral Ed25519 signers, issues a five-minute protocol-state bundle, requires both signatures, evaluates a capped USDC approval, and forwards it to a mock wallet. The output contains an `allow` decision, canonical policy, intent, and state hashes, verified signer IDs, and every individual check.

No signing key is written to disk and no network transaction is sent.

## Demonstrate fail-closed behavior

Copy `examples/transaction-intent.json` and change any one of these fields:

- `to` to an unknown contract;
- the first four bytes of `data` to an unknown selector;
- the spender ABI word to another address;
- the amount ABI word above `1000000000`;
- `chainId` to another network; or
- `gas` above `350000`.

Then run:

```sh
npx callscout authorize changed-intent.json \
  --policy examples/wallet-policy.json
```

The command returns a deny receipt and exits with code `2`.

## Test the security boundary

```sh
npm run verify
```

The tests prove denied transactions are never forwarded to the mock wallet and that opaque signing methods are rejected.

## Monitoring demo

```sh
npx callscout scan examples/variations.ts \
  --out reports/eth-calls.html \
  --json reports/eth-calls.json
```

Open `reports/eth-calls.html`. Explain that this report is supporting evidence, while the executable policy and provider guard are the authorization boundary.
