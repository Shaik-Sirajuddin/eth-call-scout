# Authenticated live protocol state

A contract being allowlisted does not mean it is safe now. Keybound treats protocol state as an independent, fail-closed veto evaluated immediately before wallet forwarding.

## Signed bundle

A version 1 bundle contains a canonical JSON payload and one or more Ed25519 signatures. The payload has a monotonically increasing sequence, issue and expiry times, and protocol observations bound to exact chain IDs and contract addresses.

Each observation has one of five statuses:

- `operational` may pass when every other check succeeds;
- `degraded`, `paused`, `compromised`, and `unknown` deny.

The schema is at `schema/protocol-state.schema.json`. Unknown fields are rejected so an operator cannot mistakenly depend on a field the verifier ignores.

## Trust policy

The executable wallet policy pins at least two trusted public keys and requires a signature threshold of at least two:

```json
{
  "protocolState": {
    "required": true,
    "maxAgeSeconds": 300,
    "maxClockSkewSeconds": 15,
    "minimumSequence": 1,
    "threshold": 2,
    "trustedKeys": [
      {
        "id": "operations",
        "algorithm": "ed25519",
        "publicKey": "<base64 SPKI DER>"
      },
      {
        "id": "security",
        "algorithm": "ed25519",
        "publicKey": "<base64 SPKI DER>"
      }
    ]
  }
}
```

Use independent publishers and protect private keys outside the agent process. For production, sign through an isolated service or HSM and separate monitor operation from policy administration.

## Authorization checks

The verifier requires:

1. valid version 1 structure;
2. the configured threshold of unique trusted signatures;
3. `issuedAt` not in the future beyond allowed clock skew;
4. `expiresAt` later than the authorization time;
5. payload and observation ages within `maxAgeSeconds`;
6. sequence at or above policy and runtime rollback floors;
7. exact protocol ID and chain binding;
8. exact target contract binding; and
9. `operational` status.

State can only veto. It cannot turn a transaction denied by wallet policy into an allow.

An `operational` state is also not the final allow: the exact transaction must subsequently pass simulation quorum. Live state answers “is this reviewed target healthy now?” while simulation answers “what does this exact transaction do against the sampled state?”

## Rollback protection

The guarded provider remembers the highest authenticated sequence, including a signed `compromised` observation. This prevents an attacker from replacing it with an older operational bundle during the process lifetime.

Production integrations should also pass `createFileSequenceStore()` or another trusted persistent store. If the store cannot be read or updated, authorization denies. Keep this file outside directories the agent can write or delete.

## Live fetching and cache

`createLiveStateSource()` fetches state only over HTTPS, rejects redirects and oversized responses, and can cache the last response atomically. The response and cache are untrusted: signatures, freshness, status, and bindings are always checked later inside authorization. A cached bundle can be used during an outage only while it remains fresh and unexpired.

## Offline signing commands

```sh
keybound state sign payload.json \
  --key operations-private.pem \
  --key-id operations \
  --out state-one-signature.json

keybound state sign payload.json \
  --key security-private.pem \
  --key-id security \
  --append state-one-signature.json \
  --out state-quorum.json

keybound state verify state-quorum.json \
  --policy wallet-policy.json \
  --intent transaction-intent.json
```

Never place signing private keys in the repository, agent environment, browser bundle, wallet-policy file, or simulation process.

## What produces status

Signature verification proves who published a status, not whether the status is correct. Publishers should combine protocol-specific evidence such as implementation-slot and bytecode checks, pause state, oracle freshness, official incident signals, and independent RPC observations. Keybound's [deterministic protocol monitor](protocol-monitoring.md) collects bytecode, storage, and view-call invariants through an RPC quorum before signing.
