# Live dual-Anvil demo

The live demo turns a narrow natural-language trade request into an exact transaction and sends it through the same deterministic CallScout boundary used by integrations. The demo agent has no signer. Its proposal must pass executable policy, threshold-signed live protocol state, two independent full EVM simulations, and the guarded wallet provider.

## Runtime path

1. Two independent Anvil nodes start on ports `9545` and `9546` with identical deterministic deployments.
2. `DemoRuntime` deploys dUSD, dETH, the demo router, and an intentionally unsafe internal target to both nodes.
3. The demo agent parses one bounded `swapExactTokensForTokens` goal and fixes calldata, chain, nonce, gas, fees, and recipient.
4. Two monitor sources verify the router bytecode and its live pause state. Two Ed25519 signers authenticate that observation.
5. Both Anvil nodes execute `eth_call`, `eth_estimateGas`, `callTracer`, and `prestateTracer` for the exact proposal.
6. The guarded provider forwards only an all-pass request to the primary node. Every decision is appended to a hash-chained audit log under `demo/runtime/`.

The scenarios intentionally exercise different veto points:

- `safe`: both simulations agree and the wallet forwards exactly one transaction.
- `compromised`: the live pause invariant fails on both sources, so simulation is never reached.
- `hidden-call`: live state remains operational, but both traces reveal an unapproved internal target.
- `slippage`: the exact call reverts on both nodes and simulation fails closed.

## Commands

```sh
npm ci
npm run demo:serve
# open http://127.0.0.1:4174/demo.html
```

`npm run demo:serve` compiles the contracts, launches both Anvil nodes, deploys the deterministic market twice, starts the run API, and serves the judge console. Choose a scenario, edit the trade goal if desired, and click **Run guarded trade**. The console polls the run as it progresses and preserves the complete prompt, structured agent intent, exact transaction envelope, policy checks, signed protocol evidence, simulation result, wallet outcome, and audit-chain receipt. Press `Ctrl+C` once to stop the server and both child nodes.

Use `npm run demo:anvil` for a non-interactive smoke test that executes all four scenarios and exits after printing their receipts. The health endpoint is `http://127.0.0.1:4174/api/health`.

The deployed static page intentionally shows a yellow **EXAMPLE EVIDENCE** badge because Vercel or GitHub Pages does not run local Anvil. Only the locally served page shows the green **LIVE DUAL-ANVIL** badge and can execute fresh requests.

The local chain uses Foundry's public development mnemonic and must never hold real assets. EIP-7702 remains explicitly denied by this demo policy.
