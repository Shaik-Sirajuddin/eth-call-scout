# Executable policy reference

Wallet policies are machine-enforced JSON, not prompts. The runtime validator in `src/policy.js` is authoritative; `schema/wallet-policy.schema.json` supports editors and review tooling.

## Top-level fields

| Field | Required | Meaning |
| --- | --- | --- |
| `version` | Yes | Must be `1` |
| `name` | Yes | Human-readable policy identity |
| `defaultAction` | Yes | Must be `deny` |
| `chains` | Yes | Exact allowed numeric chain IDs |
| `wallets` | Yes | Exact allowed sender addresses; at least one is required for activation |
| `validUntil` | Yes | ISO-8601 expiry checked at authorization time |
| `protocolState` | Yes | Signature threshold, freshness, and rollback trust policy |
| `simulation` | Yes | Full-trace quorum, effect ceilings, source bindings, and EIP-7702 policy |
| `invariants` | Yes | Global transaction ceilings |
| `contracts` | Yes | Exact chain/address/method allowlist |

All integer policy limits are unsigned base-10 strings. This avoids JSON number precision loss. Transaction intents may supply standard hexadecimal RPC quantities.

## Exact transaction envelope

Every intent requires an explicit `chainId` and outer `nonce`, plus target, sender, calldata/value, gas, and exactly one supported fee model. The wallet's active chain must equal the intent chain, and the simulation quorum must observe the same pending nonce before execution. This prevents a wallet or adapter from filling security-relevant envelope fields after authorization.

EIP-1559 type-2 and EIP-7702 type-4 intents may include an EIP-2930 `accessList`. Entries require exact addresses and 32-byte storage keys; duplicate addresses/keys, unknown entry fields, more than 256 addresses, or more than 4096 keys deny. Legacy/type-0 access lists deny. The normalized access list is included in the receipt hash and sent unchanged to every simulation source.

## Global invariants

- `maxNativeValueWei` is required and caps transaction value.
- `maxGas` is required, requires an explicit transaction gas limit, and caps it.
- `maxGasPriceWei` is required whenever a legacy `gasPrice` transaction is proposed and caps that exact field.
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

## Mandatory simulation policy

`simulation.required` must be `true`. Secure activation requires at least two independent RPC sources and a quorum of at least two. The policy binds trace execution to `latest` or `pending`, names sources by environment variable, sets a maximum block skew, and caps gas estimate, call depth/count, touched accounts, and storage writes. `denyCodeChanges` must remain enabled.

`allowedCallTypes`, chain-bound `internalTargets`, and the contract/token addresses already present in policy determine which internal calls may occur. `assetLimits` are also chain-bound and apply exact ERC-20-specific maximum outflow and approval amounts plus recipient and spender allowlists. A token event emitted from the guarded wallet for a token without an asset rule on that chain is denied. NFT transfers and operator-wide approvals are not silently interpreted as fungible-token events; they deny until separately supported.

The simulator must obtain a quorum for one identical passing effect fingerprint. A policy-violation quorum, conflicting passing traces, insufficient trace support, endpoint lag, malformed output, or unavailable quorum denies. See [Full transaction simulation](transaction-simulation.md).

## EIP-7702 policy

EIP-7702 is explicit and default-deny:

```json
{
  "eip7702": {
    "allowAuthorizationList": false,
    "allowDelegatedWallet": false,
    "maxAuthorizations": 1,
    "delegates": []
  }
}
```

`allowAuthorizationList` permits a new type-4 delegation only after signature recovery proves the guarded wallet is the authority, the authorization chain exactly matches the transaction chain, the authorization uses the sender's next valid nonce, and the delegate matches one configured chain, address, and runtime `codeHash`. Chain ID zero, multiple authorizations, other authorities, zero-address revocation, delegate chains, and unpinned code deny in the secure profile.

`allowDelegatedWallet` is a separate permission for sending from an EOA that is already delegated. The simulator resolves the `0xef0100 || address` designator and checks the referenced code hash through every simulation source. The normal full trace and all policy limits still apply in both cases.

To let a delegated wallet send batches, also list the wallet as a contract with its batch selector. Signed protocol state must name the wallet under the same `protocolId`:

```json
{
  "chainId": 1,
  "address": "0xYourWallet",
  "protocolId": "agent-wallet",
  "maxNativeValueWei": "0",
  "methods": [{ "selector": "0xe9ae5c53", "name": "execute(bytes32,bytes)" }]
}
```

The batch selector needs no ABI constraints, because every call inside the batch is checked against its own contract entry using the simulated call tree. See [Batches from a delegated wallet](transaction-simulation.md#batches-from-a-delegated-wallet).

Enabling `allowAuthorizationList` alone locks the wallet after it upgrades, because later transactions come from a delegated wallet. Audit reports this as `eip7702-wallet-lockout`.

Pinned code identity does not replace simulation, and simulation does not replace review of persistent delegate code. Production tooling should populate approved delegate identities from reviewed, authenticated state rather than asking users to copy hashes manually.

## Validation, audit, and authorization

```sh
npx callscout policy validate policy.json
npx callscout policy audit policy.json
CALLSCOUT_SIM_PRIMARY='https://trace-a.example' \
CALLSCOUT_SIM_SECONDARY='https://trace-b.example' \
npx callscout authorize intent.json --policy policy.json --state state.json --out receipt.json
```

`policy validate` applies the full secure activation profile and rejects incomplete drafts. `policy audit` performs structural validation and reports activation gaps, such as missing wallet binding, expiry, signer threshold, RPC quorum, or gas cap, so a draft can be reviewed before it is capable of authorizing a wallet.

Authorization exit codes are `0` for allow, `2` for deny, and `1` for command/configuration errors. An `allow` requires both authenticated live state and simulation quorum.

Executable policies must pin at least two Ed25519 public keys, configure a signature threshold of at least two, and assign `protocolId` to every allowed contract. The audit command reports weaker draft settings as high severity. See [Authenticated protocol state](protocol-state.md).

## Policy operations

Treat policy activation as a privileged operation. Keep authoring separate from activation, review policy hashes, use version control or signed releases, and do not let the agent write its own active policy. A policy change should generate an operational audit event independent of transaction receipts.
