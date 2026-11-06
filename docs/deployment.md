# Vercel deployment

The repository is self-configuring through `vercel.json`. Vercel should build the responsive static product site and publish `dist/`; it must not attempt to run Anvil in the hosted deployment.

## Import settings

In the Vercel dashboard, choose **Add New → Project**, import `x0rc1ph3r/eth-call-scout`, and use:

| Setting | Value |
| --- | --- |
| Framework Preset | Other |
| Root Directory | `.` |
| Install Command | `npm ci` |
| Build Command | `npm run site:build` |
| Output Directory | `dist` |
| Development Command | leave empty |

The checked-in `vercel.json` supplies the install, build, framework, and output values. Keep Root Directory at its repository default (`.`). No environment variables are required for the static showcase.

## Make the judge URL public

The production URL must not require a Vercel account.

1. Open the `call-scout` project and select **Settings → Domains**.
2. Add or promote a memorable production domain. A generated preview URL is not a public production domain.
3. Open **Settings → Deployment Protection**.
4. Select **Standard Protection** (production domains remain public) or **None**. Do not use **All Deployments** for the judge build.
5. Open the production domain in a private browser window. It must load the CallScout landing page without redirecting to `vercel.com/login`.
6. Verify `/demo.html`, `/report.html`, `/ruleset.html`, and `/pr-review-ruleset.html` on that same domain.

The hosted control room deliberately shows **EXAMPLE EVIDENCE**. The real execution demo runs locally because it starts two Anvil processes and deploys contracts. Run `npm run demo:serve` and open `http://127.0.0.1:4174/demo.html` for the green **LIVE DUAL-ANVIL** mode.

## Release check

Every push to `main` should produce a successful Vercel status on the commit. Before submitting to judges, confirm:

- the production domain is public;
- the landing page links to all four product surfaces;
- the hosted control room is clearly labeled as stored evidence;
- the local control room completes the safe and denied scenarios; and
- `npm run verify` passes.
