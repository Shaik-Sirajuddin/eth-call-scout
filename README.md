## Ethereum call scanner

This repository also contains `eth-call-scout`, a static-analysis CLI for finding Ethereum contract interactions and JSON-RPC calls in JavaScript and TypeScript. It uses the TypeScript compiler parser, so it can parse both `.js` and `.ts` source without compiling TypeScript first.

It recognizes common ethers `Contract` calls, viem actions (`readContract`, `writeContract`, `simulateContract`), EIP-1193 `request({ method, params })`, provider `send('eth_call', ...)`, direct `fetch` JSON-RPC payloads, and `{ to, data }` provider calls. The review report includes source locations, snippets, resolved literal addresses, function names when visible, arguments/calldata, RPC methods, and confidence notes.

Passing a source file follows its transitive JavaScript/TypeScript imports, including installed package source resolved through TypeScript and the nearest `tsconfig.json`. Passing a directory scans its source files recursively (excluding common generated and dependency directories), then follows imports from those files. `.d.ts` declaration files are excluded.

```sh
npm install
npm run scan -- src examples --out reports/eth-calls.html --json reports/eth-calls.json
```

Run `npm run scan -- --help` for CLI options. `examples/variations.ts` demonstrates the supported call styles.

### Token and protocol registry

The scanner includes a curated Ethereum token/protocol directory, ETHGlobal Cannes 2026 sponsor integrations, and volume tracker platforms. It can refresh token names and logo URIs from Uniswap and Sushi token lists, protocol names/logos and DEX volume from DefiLlama, and Aave V3 Ethereum contract addresses from Aave's published address book. Live data is merged into a local cache under `.cache/eth-call-scout/registry.json`; the curated list remains available offline. Curated Uniswap router deployments and the synced Aave address book map contract addresses to their protocol entries.

```sh
npm run scan -- registry sync all
npm run scan -- registry list tokens
npm run scan -- registry list protocols
npm run scan -- registry search uniswap
```

### Decode native calldata

Pass `--decode` to query a verified ABI for each raw calldata target, decode the selector and arguments locally, and cache the ABI. When `ETHERSCAN_API_KEY` is set in the environment or a local `.env`, it checks Etherscan first, follows a verified proxy implementation when the proxy ABI does not contain the selector, then checks Sourcify. If neither source has a usable ABI, it looks up candidate signatures in Sourcify's 4byte database. Use `--chain-id` when scanning another EVM network.

```sh
npm run scan -- src --decode --chain-id 1 --out reports/decoded.html
```

Do not commit `.env`. Raw selectors may have collisions; the report marks ambiguous signature matches. Unverified contracts, dynamic addresses, and unsupported or unknown chain IDs can still remain undecoded. The scanner never executes scanned source code.

The HTML report loads registry logos from their published HTTPS/IPFS URIs and displays a separate function-role badge inferred from the function name (for example, `swap`, `flash loan`, `lending`, `bridge`, or `token`). These role badges describe the call name and are not proof of the contract's verified purpose.

### Interactive call map and custom rulesets

The HTML review is an interactive vertical call map rather than a table. Protocol and token boxes use stable colors, and calls from the same source function share an outlined group ordered by source line. Static scanning cannot prove runtime transaction boundaries or timing. The left panel reports registry coverage exposure: unknown addresses increase the score and unresolved targets count as partial exposure. This is not a security audit.

Build or open the standalone ruleset editor:

```sh
npm run ruleset:build
# Open ruleset.html directly in a browser
```

The editor starts from `data/registry.static.json`, searches and filters the premapped tokens, protocols, and contracts, supports including/excluding defaults, and lets you add custom mappings. Download its JSON ruleset and apply it during analysis:

```sh
npm run scan -- src/index.ts --ruleset eth-call-scout.ruleset.json \\
  --out reports/calls.html --json reports/calls.json
```

Rulesets use version 1 JSON. Set `includeDefaults` to false to use only custom mappings, or use `excludeAddresses` / `excludeProtocolIds` for selected exclusions. `tokens`, `protocols`, and `contracts` hold custom mappings; entries can have `enabled: false` to keep them in the file without applying them.
