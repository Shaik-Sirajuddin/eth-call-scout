# Monitoring and static call discovery

The scanner inventories likely Ethereum interactions in JavaScript and TypeScript. It helps reviewers discover addresses and methods that may need policy entries. It is not in the wallet authorization path.

## Run a scan

```sh
npx callscout scan src examples \
  --out reports/eth-calls.html \
  --json reports/eth-calls.json
```

Supported extensions are `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, and `.cts`. Directory scans exclude common generated and dependency folders, while explicit file entry points follow transitive JavaScript and TypeScript imports using the nearest `tsconfig.json`.

## Detectors

- ethers `Contract` calls;
- viem `readContract`, `writeContract`, and `simulateContract`;
- EIP-1193 `request({ method, params })`;
- provider `send`, `sendAsync`, and `{ to, data }` calls;
- direct `fetch` JSON-RPC payloads; and
- selected non-contract Ethereum RPC calls.

The scanner resolves literals and nearby variables up to a small bounded depth. Dynamic values may remain unresolved.

## Calldata decoding

`--decode` checks an Etherscan verified ABI when `ETHERSCAN_API_KEY` is configured, follows a verified proxy implementation when necessary, then tries Sourcify and selector candidates. ABI and selector responses are cached under `.cache/eth-call-scout/abi`.

Selector matches can be ambiguous. Only verified ABI decoding should be treated as strong identity evidence, and neither form grants authorization.

## Registry enrichment

The registry merges curated mappings with optional token, protocol, volume, and Aave address-book data. Registry matches add names, roles, and logos to reports. They are not security endorsements.

```sh
npx callscout registry sync all
npx callscout registry list contracts
npx callscout registry search aave
```

## Report interpretation

The HTML report groups calls by source function and line order. This is not proof that calls execute together or in that order. Its exposure score measures mapped versus unknown addresses; it is not a vulnerability or protocol-safety score.

Use findings to narrow policy review. Never automatically convert every detected call into an allow rule.

Static source discovery is distinct from [deterministic protocol monitoring](protocol-monitoring.md), which checks live bytecode, storage, and view-call invariants through an RPC quorum and produces data for signed protocol-state attestations.

Both monitoring systems are also distinct from [full transaction simulation](transaction-simulation.md). Static discovery helps author policy, protocol monitoring determines whether an allowlisted deployment is healthy now, and transaction simulation evaluates the exact proposed state-changing transaction. None can silently grant permission on behalf of the others.
