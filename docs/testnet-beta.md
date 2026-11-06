# Sepolia beta rollout

WalletCordon's hosted beta uses Sepolia for real transaction execution. Anvil remains a local regression environment; it is never started inside Vercel.

## Deployment shape

```text
AI agent
  |  Bearer agent key
  v
Vercel /api/v1/agent/*
  |  private service credential; exact API only
  v
Persistent WalletCordon Gateway
  |-- executable policy and signed live-state threshold
  |-- two independent trace-capable Sepolia RPC providers
  |-- durable runs, idempotency, state sequence and audit receipts
  `-- isolated, low-value Sepolia signer
          |
          v
       Sepolia
```

The agent never receives a private key, signer, raw RPC relay, or unguarded provider. Vercel never receives the Sepolia private key. Its server-side Gateway credential can call only WalletCordon's narrow run API; it is not a signing credential.

## Rollout order

1. **Hosted trust boundary:** Vercel authenticates agents and proxies only the fixed Gateway methods. It requires HTTPS, pins chain ID `11155111`, requires the Gateway to report EIP-7702 as denied, and fails closed when configuration is missing.
2. **Persistent Sepolia Gateway:** run deterministic policy, authenticated live state, full two-provider simulation, durable idempotency and the isolated signer outside Vercel.
3. **Sepolia fixtures and policy:** deploy the demo token/router contracts, record reviewed addresses and code hashes, activate a wallet-bound, expiring, low-limit policy, and fund the disposable wallet with test ETH only.
4. **Hosted Control Room:** replace local scenario controls with real Sepolia proposals and show durable allow/deny history from the Gateway.
5. **Release proof:** run one policy-compliant transaction and one transaction denied for a deterministic security reason, verify both source traces, verify the mined allow receipt, and confirm the denied request never reaches the signer.

Each step is independently reviewable and must keep the existing dual-Anvil tests green.

## Vercel secrets

Set these as encrypted server-side environment variables for Preview and Production. Never prefix them with `NEXT_PUBLIC_`.

| Variable | Purpose |
| --- | --- |
| `WALLETCORDON_GATEWAY_URL` | HTTPS origin of the persistent Gateway |
| `WALLETCORDON_GATEWAY_TOKEN` | 32+ character Vercel-to-Gateway service credential |
| `WALLETCORDON_AGENT_API_KEYS` | one or more comma-separated 32+ character agent bearer keys |

The deployment refuses hosted execution when any required value is absent, the Gateway uses plain HTTP, its health response is not Sepolia, or EIP-7702 is not reported as `denied-by-policy`.

## Secrets that do not belong in Vercel

- wallet private key or mnemonic;
- protocol-state signing private keys;
- database administration credentials shared with the agent;
- unrestricted RPC credentials with signing authority; or
- policy activation credentials.

Those belong in the isolated Gateway's secret store. Use a fresh, disposable Sepolia wallet with minimal faucet funds; never reuse a mainnet or personal wallet key.

## Agent request

Hosted agent endpoints require the configured bearer key:

```sh
curl -sS https://YOUR_VERCEL_DOMAIN/api/v1/agent/capabilities \
  -H "Authorization: Bearer $WALLETCORDON_AGENT_API_KEY"
```

The public browser UI does not receive this key. Operator mutations will use a separate server-side path and separate rate limits.

## Build the persistent Gateway

The Gateway is a separate container with a persistent volume. It refuses to start when `VERCEL` is present. Its authenticated `/health` route must prove Sepolia, two named RPC sources, a valid active policy, live-state quorum, and an EIP-7702 deny posture before the Vercel proxy accepts it.

Prepare a fresh disposable wallet and two Ed25519 state-signing keys:

```sh
npm run contracts:build
npm run sepolia:prepare
```

The command writes `.env.sepolia.local` with mode `0600` and prints only the public wallet address. Fund that address with faucet Sepolia ETH—never mainnet ETH—then fill in two independent trace-capable RPC URLs. Each provider must support all of these methods on Sepolia:

- `eth_call` and `eth_estimateGas` for the exact type-2 request;
- `debug_traceCall` with `callTracer`, `tracerConfig.withLog: true`;
- `debug_traceCall` with `prestateTracer`, `diffMode: true`;
- pending nonce, code, block, receipt and transaction reads; and
- `debug_traceTransaction` for the post-mine verification path.

WalletCordon probes both debug tracers before deploying contracts. A public endpoint that exposes ordinary JSON-RPC but disables the debug namespace is not a simulation source and must not be used.

Deploy the safe router, the trace-denied router, tokens, and monitored fixtures:

```sh
npm run sepolia:deploy
```

The deployer writes `deployments/sepolia.json`. Review and commit that public manifest. It pins the wallet, both router addresses, runtime code hashes, monitor calls, signer public keys, policy expiry, value/gas/fee limits, two-source quorum, and the EIP-7702 denial. Private keys remain only in `.env.sepolia.local` and the Gateway host's secret store.

Run the service locally against Sepolia:

```sh
npm run sepolia:gateway
curl -sS http://127.0.0.1:8787/health \
  -H "Authorization: Bearer $WALLETCORDON_GATEWAY_TOKEN"
```

For hosting, build `Dockerfile.gateway`, mount a durable volume at `/data`, expose the platform-assigned `PORT`, and configure every variable from `.env.sepolia.local` as a secret. Run exactly one replica: the beta history, sequence floor, spend tracker, and hash-chain appenders are single-writer. The container runs as a non-root user and exposes only unauthenticated `/live`; every capability, run, history, and health endpoint requires the Gateway service token.

Do not deploy the Gateway without persistent storage. Run JSON, hash-chained audit receipts, alerts and the authenticated live-state sequence floor must survive restarts.

## Real two-transaction proof

The deployment creates two reviewed routers with identical runtime code:

1. The safe router performs the bounded swap. Policy, current two-signature state, both full traces and the exact signer envelope must pass before it is broadcast.
2. The trace-denied router is also an exact policy target, so a target allowlist alone would accept it. Its runtime state enables a call to `UnsafeTarget`. Both call trees expose that unapproved internal target, so WalletCordon denies before the signer sees the request.

This makes the failed example a real simulation finding, not a hard-coded address denial or UI fixture.
