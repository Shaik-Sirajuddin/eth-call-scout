# Live dual-Anvil demo

The live demo turns a narrow natural-language trade request into an exact transaction and sends it through the same deterministic Keybound boundary used by integrations. The demo agent has no signer. Its proposal must pass executable policy, threshold-signed live protocol state, two independent full EVM simulations, and the guarded wallet provider.

## Runtime path

1. Two independent Anvil nodes start on ports `9545` and `9546` with identical deterministic deployments.
2. `WalletPolicyGateway` deploys dUSD, dETH, the local router, and an intentionally unsafe internal target to both nodes.
3. The demo agent parses one bounded `swapExactTokensForTokens` goal and fixes calldata, chain, nonce, gas, fees, and recipient.
4. Two monitor sources verify the router bytecode and its live pause state. Two Ed25519 signers authenticate that observation.
5. Both Anvil nodes execute `eth_call`, `eth_estimateGas`, `callTracer`, and `prestateTracer` for the exact proposal.
6. The guarded provider forwards only an all-pass request to the primary node. Every decision is appended to a hash-chained audit log under `demo/runtime/`.

The local wallet is Anvil account 1 from Foundry's public development mnemonic. Anvil keeps it as an unlocked test account inside the node process; no private-key file is created and no key is returned by the Gateway API. After an `allow`, the guarded adapter sends the already-checked exact `eth_sendTransaction` request to the primary node. A testnet deployment replaces this development-only adapter with an isolated signer service, while the agent still receives only the narrow proposal API.

The scenarios intentionally exercise different veto points:

- `safe`: both simulations agree and the wallet forwards exactly one transaction.
- `compromised`: the live pause invariant fails on both sources, so simulation is never reached.
- `hidden-call`: live state remains operational, but both traces reveal an unapproved internal target.
- `slippage`: the exact call reverts on both nodes and simulation fails closed.

## Commands

```sh
npm ci
npm run dev
# open http://127.0.0.1:3000/runs
```

`npm run dev` compiles the contracts, launches both Anvil nodes, deploys the deterministic market twice, starts the Gateway API, and serves the Next.js judge console. Choose a scenario, edit the trade goal if desired, and click **Run guarded trade**. The console polls the run as it progresses and preserves the complete prompt, structured agent intent, exact transaction envelope, policy checks, signed protocol evidence, simulation result, wallet outcome, and audit-chain receipt. Press `Ctrl+C` once to stop the server and both owned child nodes.

Use `npm run anvil:smoke` for a non-interactive smoke test that executes all four scenarios and exits after printing their receipts. The health endpoint is `http://127.0.0.1:3000/api/health`.

To prove the interface available to a separate AI agent, keep the app running and execute:

```sh
npm run agent:smoke -- --origin http://127.0.0.1:3000
```

The client discovers capabilities, ABI-encodes an exact proposal, submits it without any signer or private key, waits for two-source simulation consensus and a mined receipt, then retries the same idempotency key to prove the transaction was not duplicated. See [Gateway API](api.md) for the full contract.

Generated history survives an app restart under `demo/runtime/runs/`. For a clean recording, stop the app first and run `npm run demo:reset`; that command intentionally deletes only generated local history and recreates the restricted runtime directory.

The Vercel build serves the Next.js product interface, report, and policy builder. It does not spawn Anvil inside a serverless function. Hosted transaction execution is the separate testnet-beta phase described in [Vercel deployment](deployment.md).

The local chain uses Foundry's public development mnemonic and must never hold real assets. EIP-7702 remains explicitly denied by this demo policy.
