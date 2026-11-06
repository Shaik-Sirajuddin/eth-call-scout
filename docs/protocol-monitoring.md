# Deterministic protocol monitoring

The protocol monitor turns on-chain observations into an unsigned state payload. It does not use an LLM and it does not sign its own output. Isolated state publishers review or automatically sign that payload according to their operating policy.

## Supported invariants

Each monitored contract requires an expected Keccak-256 runtime bytecode hash. It may also require:

- exact storage-slot values, including proxy implementation or admin slots; and
- read-only `eth_call` results using exact equality, inequality, unsigned maximum, or unsigned minimum checks.

Checks are performed against every configured RPC source. A protocol is:

- `operational` when at least `rpcQuorum` sources satisfy every invariant;
- `compromised` when at least `rpcQuorum` sources return deterministic invariant mismatches; or
- `degraded` when neither result reaches quorum because sources disagree or fail.

Only `operational` can pass wallet authorization after the payload is signed and verified.

Protocol monitoring is a pre-transaction veto, not a substitute for simulation. A fresh `operational` observation says the configured live invariants matched; the exact proposed transaction must still pass [full transaction simulation](transaction-simulation.md). Conversely, a passing simulation cannot override `degraded`, `compromised`, stale, or unavailable protocol state.

## Configuration

See `schema/protocol-monitor.schema.json` and `examples/protocol-monitor.demo.json`.

```json
{
  "version": 1,
  "chainId": 1,
  "stateTtlSeconds": 300,
  "rpcQuorum": 2,
  "maxBlockSkew": 5,
  "sources": [
    { "id": "primary", "env": "CALLSCOUT_RPC_PRIMARY" },
    { "id": "secondary", "env": "CALLSCOUT_RPC_SECONDARY" }
  ],
  "protocols": [
    {
      "id": "project",
      "contracts": [
        {
          "address": "0x0000000000000000000000000000000000000001",
          "codeHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
          "storage": [],
          "calls": []
        }
      ]
    }
  ]
}
```

The checked-in demo values are synthetic and must not be reused for production. Derive code hashes, proxy slots, expected values, and view calls from reviewed deployments and protocol incident documentation.

## Collect and sign

```sh
export CALLSCOUT_RPC_PRIMARY='https://first-independent-rpc.example'
export CALLSCOUT_RPC_SECONDARY='https://second-independent-rpc.example'

callscout state collect protocol-monitor.json \
  --sequence 42 \
  --out state-payload.json

# Sign in separate operational and security environments.
callscout state sign state-payload.json \
  --key operations.pem --key-id operations \
  --out state-one-signature.json

callscout state sign state-payload.json \
  --key security.pem --key-id security \
  --append state-one-signature.json \
  --out state-quorum.json
```

RPC endpoints must use HTTPS, except loopback HTTP for local development. Credentials embedded in URLs are rejected. Put endpoint values in environment variables rather than committed monitor configuration.

## Operations and limitations

- Use RPC providers with independent infrastructure and failure domains.
- Reject duplicate endpoint URLs and keep `maxBlockSkew` low enough that lagging nodes cannot satisfy quorum.
- Advance the sequence for every published payload, including compromised or degraded states.
- Keep TTL short enough for incident response and long enough for publisher availability.
- Monitor upgradeable proxies with both proxy bytecode and implementation/admin storage slots.
- Add protocol-specific pause, oracle, reserve, or invariant view calls where stable and meaningful.
- Treat a mismatch as a fail-closed incident requiring investigation; a legitimate upgrade still changes the trusted invariant.
- A passing monitor cannot prove absence of all exploits. It proves only that configured deterministic invariants matched through the configured quorum.
- Add reviewed EIP-7702 delegate implementations to deterministic monitoring when they are approved for production use; simulation still checks the runtime code hash on every transaction.
