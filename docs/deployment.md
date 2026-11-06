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

## Phase boundary

The current production build publishes the responsive landing page, report, policy builder, and run-history interface. The live phase-one Gateway deliberately binds to localhost and owns two local Anvil child processes. Vercel serverless functions are not a safe or durable place to run that local chain, store signing authority, or persist the current filesystem-backed history.

Therefore:

- use `npm run dev` for the full live dual-Anvil transaction demo;
- do not present a Vercel `/runs` mutation as production wallet execution yet; and
- keep real keys, mnemonics, and privileged RPC credentials out of Vercel environment variables until the isolated signer design is implemented and reviewed.

The testnet beta keeps the same agent API shapes but replaces the local adapter with:

1. authenticated agent identities and per-agent policy assignment;
2. two independent remote testnet RPC providers for monitoring and simulation;
3. durable run, idempotency, audit, and sequence storage;
4. rate limits and request-size controls at the public edge;
5. an isolated signer or wallet adapter that receives only an already-authorized exact payload; and
6. server-side policy activation separated from the agent-facing API.

This separation is intentional: the agent never receives the signer or private key in either phase.

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
- the local `/runs` control room completes a fresh safe transaction and exposes the full evidence trail;
- the Vercel production domain is public and all four product surfaces render responsively; and
- the presentation clearly labels live transaction execution as local Anvil until the testnet adapter is deployed.
