# Vercel deployment

The repository is a Next.js application. The checked-in `vercel.json` selects the Next.js framework and runs the same production build used locally.

## Import settings

In the Vercel dashboard, choose **Add New → Project**, import `x0rc1ph3r/eth-call-scout`, and use:

| Setting | Value |
| --- | --- |
| Framework Preset | Next.js |
| Root Directory | `.` |
| Install Command | `npm ci` |
| Build Command | `npm run build` |
| Output Directory | leave blank (Next.js default) |
| Development Command | leave blank |

The repository configuration supplies the framework, install, and build values. Do not set an output directory to `dist`; `dist/` contains generated monitoring artifacts, not the Next.js application output. The build uses the repository's JavaScript/TypeScript scanner for the bundled example report, so Vercel does not need Rust, Foundry, or Anvil.

## Policy Studio AI configuration

To enable free-form policy translation on Vercel, add these server-side environment variables under **Project Settings → Environment Variables** and redeploy:

| Variable | Required | Meaning |
| --- | --- | --- |
| `OPENAI_API_KEY` | Optional | Enables server-side AI translation for `/api/policy/compile-prompt` |
| `OPENAI_POLICY_MODEL` | Optional | Translation model; defaults to `gpt-6-astra` |

Do not prefix the key with `NEXT_PUBLIC_`; it must never be included in browser JavaScript. Without the key, Policy Studio remains usable through its strict canonical-rule fallback and visual editor. The model only proposes a draft and receives public registry names plus the user's description. It has no wallet key, signer, live-state signing key, active-policy write path, or transaction submission capability.

## Hosted execution boundary

The production build publishes the interface and acts as the authenticated public control plane. It never starts Anvil and never stores signing authority. Hosted transaction requests are sent over HTTPS to a persistent WalletCordon Sepolia Gateway; local development continues to use the loopback dual-Anvil Gateway.

Before the persistent Gateway is deployed and configured, hosted transaction execution fails closed. Configure these encrypted server-side Vercel variables:

| Variable | Value |
| --- | --- |
| `WALLETCORDON_GATEWAY_URL` | HTTPS origin of the isolated Gateway |
| `WALLETCORDON_GATEWAY_TOKEN` | random service secret, at least 32 characters |
| `WALLETCORDON_AGENT_API_KEYS` | one or more comma-separated random agent keys, each at least 32 characters |

Do not put a wallet key, mnemonic, protocol-state signing key, or unrestricted signing credential in Vercel. The testnet beta uses:

1. authenticated agent identities and per-agent policy assignment;
2. two independent remote testnet RPC providers for monitoring and simulation;
3. durable run, idempotency, audit, and sequence storage;
4. rate limits and request-size controls at the public edge;
5. an isolated signer or wallet adapter that receives only an already-authorized exact payload; and
6. server-side policy activation separated from the agent-facing API.

This separation is intentional: the agent never receives the signer or private key in either phase.

The complete sequence and operational checks are in [Sepolia beta rollout](testnet-beta.md).

## Make the judge URL public

The production URL must not require a Vercel account.

1. Open the project and select **Settings → Domains**.
2. Add or promote a production domain.
3. Open **Settings → Deployment Protection**.
4. Select **Standard Protection** (production domains remain public) or **None**. Do not use **All Deployments** for the judge build.
5. Open the production domain in a private browser window. It must load without redirecting to `vercel.com/login`.
6. Verify `/`, `/runs`, `/report`, and `/policy` at mobile and desktop widths.

## Release check

Before sharing the submission:

- `npm run verify` passes from a clean checkout with Node.js 22 and Foundry installed;
- `npm run anvil:smoke` proves one allowed and three denied real-chain scenarios;
- `npm run agent:smoke -- --origin http://127.0.0.1:3000` proves the external agent contract and idempotency;
- the local `/runs` control room completes the guided pair: one safe transaction is mined and one compromised-router transaction is denied before wallet forwarding;
- the Vercel production domain is public and all four product surfaces render responsively; and
- the presentation clearly labels live transaction execution as local Anvil until the testnet adapter is deployed.
