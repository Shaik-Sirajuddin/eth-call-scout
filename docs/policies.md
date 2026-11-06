# Executable policy reference

Wallet policies are machine-enforced JSON, not prompts. The runtime validator in `src/policy.js` is authoritative; `schema/wallet-policy.schema.json` supports editors and review tooling.

## Top-level fields

| Field | Required | Meaning |
| --- | --- | --- |
| `version` | Yes | Must be `1` |
| `name` | Yes | Human-readable policy identity |
| `defaultAction` | Yes | Must be `deny` |
| `chains` | Yes | Exact allowed numeric chain IDs |
| `wallets` | Recommended | Exact allowed sender addresses |
| `validUntil` | Recommended | ISO-8601 expiry checked at authorization time |
| `protocolState` | Yes | Signature threshold, freshness, and rollback trust policy |
| `invariants` | Yes | Global transaction ceilings |
| `contracts` | Yes | Exact chain/address/method allowlist |

All integer limits are unsigned base-10 strings. This avoids JSON number precision loss. Transaction intents may supply standard hexadecimal RPC quantities.

## Global invariants

- `maxNativeValueWei` is required and caps transaction value.
- `maxGas` requires a gas limit and caps it when present in policy.
- `maxFeePerGasWei` and `maxPriorityFeePerGasWei` require and cap EIP-1559 fee fields.
- `requireCalldata` denies empty calldata.
- `denyUnlimitedApproval` cannot be disabled in the secure profile.

## Contract entries

A contract entry is identified by exact `chainId` and `address`. `protocolId` connects the target to authenticated live state. `maxNativeValueWei` can be stricter than the global limit. `allowEmptyCalldata` must be explicit.

Each method entry names an exact four-byte selector. The optional `name` is display-only.

## Static ABI-word constraints

The selector occupies the first four calldata bytes. `argument: 0` addresses the first 32-byte ABI word after it.

Supported constraints:

- `address-in`: word must be a canonical ABI address and match one of the listed exact addresses.
- `uint-max`: unsigned word must be less than or equal to the decimal limit.
- `uint-min`: unsigned word must be greater than or equal to the decimal limit.
- `uint-equals`: unsigned word must equal the decimal value.
- `bytes32-equals`: word must equal the exact 32-byte hex value.

Dynamic ABI values are intentionally unsupported in version 1. The engine denies malformed or missing words rather than guessing.

## Validation, audit, and authorization

```sh
npx callscout policy validate policy.json
npx callscout policy audit policy.json
npx callscout authorize intent.json --policy policy.json --out receipt.json
```

Validation rejects non-executable or unsafe policy structures. Audit highlights broad but valid permissions, such as missing wallet binding, missing expiry, unconstrained methods, or approval rules without spender and amount constraints.

Authorization exit codes are `0` for allow, `2` for deny, and `1` for command/configuration errors.

Policies that require live state must pin at least one Ed25519 public key, configure a valid threshold, and assign `protocolId` to every allowed contract. The audit command reports missing live state as high severity. See [Authenticated protocol state](protocol-state.md).

## Policy operations

Treat policy activation as a privileged operation. Keep authoring separate from activation, review policy hashes, use version control or signed releases, and do not let the agent write its own active policy. A policy change should generate an operational audit event independent of transaction receipts.
