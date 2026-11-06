# Gateway API

The Gateway API is the only HTTP mutation surface intended for an AI agent. The agent can discover a narrow capability, submit one exact transaction proposal, and read the resulting evidence. It cannot access a signer, private key, raw wallet provider, policy administration, protocol-state signing keys, or an unguarded RPC method.

Local development runs with two Anvil nodes and must never be exposed to the public internet. In the hosted beta, Vercel requires an agent bearer token, then forwards the same narrow request shape to an authenticated persistent Sepolia Gateway. The Gateway owns durable storage and an isolated testnet signer; Vercel and the agent do not.

Default local origin: `http://127.0.0.1:3000`. Hosted origin: the public Vercel production domain.

All responses are JSON except the product pages. API responses set `Cache-Control: no-store`.

## Policy-authoring endpoint

### `POST /api/policy/compile-prompt`

This user-facing Policy Studio endpoint converts a description into an untrusted executable-policy draft. It is not part of the AI agent's wallet capability and cannot activate policy or submit transactions.

```json
{
  "prompt": "Let Uniswap approve at most 1,000 USDC from wallet 0x... on Ethereum until 2030-01-01. Keep 7702 disabled."
}
```

The server accepts at most 4,000 prompt characters. With `OPENAI_API_KEY` configured, it uses server-side AI Structured Outputs to translate the description into canonical rules. The key is never sent to the browser. Deterministic code then resolves registry addresses, converts amounts, rejects unsupported or broad permissions, builds the exact policy, and applies the full activation validator.

A valid response returns `200` with `authoringMode: "ai-assisted"`, the translation trace, recognized deterministic clauses, warnings, and the exact `policy`. A rejected draft returns `422` with clause-level errors. Without an API key, the endpoint uses `authoringMode: "deterministic-fallback"` and accepts only canonical rule phrases. AI-provider or structured-output failure returns `502` and no policy is changed.

The response does not mean the policy is active. The operator must review the generated graph/JSON and use a separate controlled activation workflow.

After starting the local app, exercise the complete external-agent contract without a signer:

```bash
npm run agent:smoke -- --origin http://127.0.0.1:3000
```

The smoke client discovers capabilities, ABI-encodes an exact proposal, waits for the deterministic decision, verifies two-source simulation consensus and a mined transaction, then retries the same idempotency key and proves that it did not enqueue a second transaction.

## Agent-facing endpoints

Hosted requests must include `Authorization: Bearer <agent-key>`. Local Anvil requests remain unauthenticated unless `WALLETCORDON_REQUIRE_AGENT_AUTH=1` is set. Missing or invalid hosted credentials fail before the Gateway is called.

### `GET /api/v1/agent/capabilities`

Returns the public information an agent needs to construct an exact proposal:

- chain ID and guarded wallet address;
- next pending wallet nonce, confirmed across both local sources;
- local contract addresses;
- supported action signatures and selectors;
- supported transaction envelope types;
- policy identity and expiry;
- methods that are always denied.

```bash
curl -sS http://127.0.0.1:3000/api/v1/agent/capabilities
```

Example response:

```json
{
  "apiVersion": "v1",
  "chainId": 31337,
  "wallet": "0x...",
  "nextNonce": "1",
  "contracts": {
    "tokenIn": "0x...",
    "tokenOut": "0x...",
    "router": "0x...",
    "unsafeTarget": "0x..."
  },
  "actions": [
    {
      "name": "swapExactTokensForTokens",
      "target": "0x...",
      "selector": "0x...",
      "signature": "swapExactTokensForTokens(uint256,uint256,address)"
    }
  ],
  "transactionTypes": ["2"],
  "deniedMethods": [
    "eth_sign",
    "personal_sign",
    "eth_signTypedData_v4",
    "eth_sendRawTransaction",
    "wallet_switchEthereumChain"
  ],
  "policy": {
    "name": "Local trading policy",
    "hash": "...",
    "expiresAt": "..."
  },
  "eip7702": "denied-by-policy"
}
```

Capabilities are descriptive, not authorization. A returned contract or action still has to pass the active policy, signed live state, full simulation quorum, and final wallet-bound request comparison.

### `POST /api/v1/agent/runs`

Submits one exact EIP-1559 transaction proposal. A successful HTTP response means the run was accepted for evaluation, not that the transaction was authorized or sent.

```json
{
  "requestId": "agent-order-00000001",
  "goal": "Swap 100 dUSD for at least 190 dETH to my wallet",
  "proposal": {
    "chainId": 31337,
    "from": "0x...",
    "to": "0x...",
    "data": "0x...",
    "value": "0",
    "gas": "0x55730",
    "maxFeePerGas": "0x2540be400",
    "maxPriorityFeePerGas": "0x3b9aca00",
    "nonce": "1",
    "type": "2"
  }
}
```

Required properties:

| Field | Requirement |
| --- | --- |
| `requestId` | 8–128 URL-safe characters. It is the idempotency key. |
| `goal` | Human-readable context, 1–500 characters. It is evidence only and cannot grant authority. |
| `proposal.chainId` | Must equal the active wallet chain and policy chain. |
| `proposal.from` | Must equal the policy-bound wallet. |
| `proposal.to` | Exact contract target. |
| `proposal.data` | Exact calldata, including selector and ABI words. |
| `proposal.value` | Decimal integer string in wei. |
| `proposal.gas` | Decimal integer string within the policy ceiling. |
| `proposal.maxFeePerGas` | Decimal integer string within the policy ceiling. |
| `proposal.maxPriorityFeePerGas` | Decimal integer string within the policy ceiling. |
| `proposal.nonce` | Explicit pending outer nonce. The wallet never fills it after simulation. |
| `proposal.type` | `"2"` in the local phase. EIP-7702 remains policy-denied. |

The first request with a new `requestId` returns `202 Accepted`. Retrying the same `requestId` returns the original run with `200 OK`; it does not enqueue another transaction.

The response is the complete run snapshot. Its first state is normally `queued` or `running`. Poll the run endpoint for a terminal state.

### `GET /api/v1/agent/runs`

Lists summaries for runs submitted through the agent API. Browser-created local test scenarios are excluded.

```bash
curl -sS http://127.0.0.1:3000/api/v1/agent/runs
```

### `GET /api/v1/agent/runs/:id`

Returns a complete agent run, including:

- original goal and exact proposal;
- normalized agent metadata;
- ordered decision events;
- executable policy checks;
- threshold-signed live protocol evidence;
- simulation source agreement, fingerprint, trace metrics, failures, and post-state evidence;
- final allow/deny receipt;
- wallet forwarding outcome and chain receipt when allowed;
- hash-chain audit verification.

Terminal states are `complete` and `error`. A `complete` run has a decision of `allow` or `deny`. An `error` run failed closed and must not be treated as authorization.

## Operator and Control Room endpoints

### `GET /api/health`

Returns Gateway readiness, local chain ID, independent RPC sources, wallet and contract addresses, policy identity, protocol monitor quorum, history mode, and EIP-7702 posture.

### `GET /api/runs`

Lists all persisted run summaries, whether created by the bundled intent planner or the agent API.

### `POST /api/runs/demo`

Local Anvil presentation endpoint. It atomically queues the fixed two-transaction story and returns both run records in execution order:

1. `safe` — a legitimate swap expected to be authorized and mined;
2. `hidden-call` — a normal-looking swap executed against the compromised fixture, expected to be denied when both traces expose an unauthorized internal target.

```sh
curl -sS -X POST http://127.0.0.1:3000/api/runs/demo
```

The response contains a shared demo ID plus two independently persisted runs. Each run carries `demo.id`, `demo.step`, `demo.total`, its expected verdict, and the human-readable reason. The Gateway serializes them so step 1 completes before step 2 begins. This endpoint is presentation-fixture control, not an agent-facing production API.

### `POST /api/runs`

Local Anvil test harness only. It lets the Control Room turn a prompt into a proposal with the bundled deterministic intent planner.

```json
{
  "prompt": "Swap 100 dUSD for at least 190 dETH to my wallet",
  "scenario": "safe"
}
```

Allowed local scenarios:

- `safe` — all gates pass and exactly one transaction is mined;
- `compromised` — signed live protocol state vetoes before simulation or wallet access;
- `hidden-call` — full traces reveal an unapproved internal target;
- `slippage` — the exact call reverts on both execution sources.

The `scenario` switch is local test-fixture control. It is not part of the agent-facing API and will not exist in the testnet beta.

### `GET /api/runs/:id`

Returns the complete persisted run used by the Control Room and its shareable `/runs/:id` page.

## Run lifecycle

```text
queued
  → request recorded
  → local chain state prepared
  → exact agent proposal fixed
  → signed live protocol state collected
  → executable policy evaluated
  → full simulation quorum evaluated
  → allow: exact payload forwarded once to wallet adapter
     deny: wallet adapter never called
  → audit receipt appended
  → complete
```

The Gateway serializes local executions because each Anvil scenario restores a deterministic snapshot. Run history is stored as atomic `0600` JSON snapshots under `demo/runtime/runs/` and reloaded across app restarts. A run interrupted during shutdown is recovered as `error`, never as `allow`.

## Error format

```json
{
  "error": "Human-readable fail-closed reason."
}
```

Common status codes:

- `200` — read succeeded or an idempotent agent request returned its existing run;
- `202` — a new run was accepted for evaluation;
- `400` — malformed JSON, missing fields, invalid scenario, or invalid proposal shape;
- `404` — run does not exist or is not visible on the requested API surface;
- `413` — request body is too large;
- `503` — the local chain adapter or Gateway is not ready.

## Security boundary

The API intentionally has no endpoint for raw signing, message signing, typed-data signing, raw transaction submission, wallet permissions, chain changes, policy weakening, live-state signing, or direct RPC forwarding. Adding a new mutation requires a purpose-built parser, executable policy rules, live-state binding, full simulation support, audit evidence, and tests. A generic pass-through endpoint would defeat the architecture.

## Attacker list endpoints

Free, public and read-only. See [Attacker list](attacker-list.md). Unlike the endpoints above, these are safe to expose and are cached.

- `GET /api/v1/attackers`: the whole list.
- `GET /api/v1/attackers?view=meta`: version, hash, count and sources.
- `GET /api/v1/attackers?view=addresses`: a plain array of addresses.
- `GET /api/v1/attackers/{address}`: whether one address is listed, and why.

Gas and fee fields in a proposal must be `0x` hex strings.

## Runs with more than one attempt

A run can forward one transaction and deny the next. `attempts` lists each one with its own `decision`, `transactionHash`, `chainReceipt`, `verification` and `receipt`. `transactionHash`, `chainReceipt` and `verification` on the run describe the first forwarded attempt, and `decision` and `receipt` describe the last attempt.
