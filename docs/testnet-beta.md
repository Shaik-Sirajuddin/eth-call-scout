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
