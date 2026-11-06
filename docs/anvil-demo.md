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
npm install
npm run demo:build
npm run demo:anvil
```

`npm run demo:anvil` runs all four scenarios and exits after printing their receipts. `npm run demo:serve` starts the run API at `http://127.0.0.1:4174/api/health` and serves the product site. The live console is the next UI milestone built on this API.

The local chain uses Foundry's public development mnemonic and must never hold real assets. EIP-7702 remains explicitly denied by this demo policy.
