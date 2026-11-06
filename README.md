## Ethereum call scanner

This repository also contains `eth-call-scout`, a static-analysis CLI for finding Ethereum contract interactions and JSON-RPC calls in JavaScript and TypeScript. Its source parser and dependency traversal are implemented in Rust with Tree-sitter JavaScript and TypeScript grammars; the CLI keeps registry enrichment, ABI decoding, and HTML report generation in JavaScript.

It recognizes common ethers `Contract` calls, viem actions (`readContract`, `writeContract`, `simulateContract`), EIP-1193 `request({ method, params })`, provider `send('eth_call', ...)`, direct `fetch` JSON-RPC payloads, and `{ to, data }` provider calls. The review report includes source locations, snippets, resolved literal addresses, function names when visible, arguments/calldata, RPC methods, and confidence notes.

Passing a source file follows its transitive JavaScript/TypeScript imports, including installed package source resolved through TypeScript and the nearest `tsconfig.json`. Passing a directory scans its source files recursively (excluding common generated and dependency directories), then follows imports from those files. `.d.ts` declaration files are excluded.

```sh
npm install
# Rust/Cargo is needed the first time; npm run scan builds the parser automatically.
npm run scan -- src examples --out reports/eth-calls.html --json reports/eth-calls.json
```

Run `npm run scan -- --help` for CLI options. `examples/variations.ts` demonstrates the supported call styles.

Build the standalone Rust scanner explicitly with `npm run build:parser`. It walks supplied directories and follows relative imports and installed package entrypoints from file inputs, then returns findings as JSON to the JavaScript CLI.

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

### Pull request risk diffs

The repository uses `.secu` as a JSON ruleset file. Its `scanPaths` list selects which project areas run in CI; the checked-in config targets `examples/`. The `Secu contract call review` workflow scans those paths at the PR base and head revisions with the same Rust analyzer and emits a Markdown diff containing risk scores, parsed call-site changes, protocols, and function names/signatures.

The scan job has read-only permissions. A separate `workflow_run` workflow, defined on the default branch, posts the generated Markdown as a PR review comment with `GITHUB_TOKEN`; it reads the artifact as text and does not check out or run PR code. Actions are pinned to full commit SHAs. The current example PRs add native JSON-RPC Aave and Uniswap call sites.

### Interactive review and custom terms

The generated HTML is a self-contained dashboard with three independently toggleable areas: a risk summary, switchable tables, and a zoomable graph. The graph lays calls out left to right inside outlined groups and uses stable colors per protocol or token. The tables cover inferred transaction groups, protocols, tokens, and addresses; each table keeps its own search and sort settings, and the table area can expand over the graph.

The CLI detects source code, so it cannot establish that calls execute in the same on-chain transaction or recover runtime timestamps. It groups calls by source function unless a transaction hash is supplied in the finding data; those groups are explicitly labeled as inferred. Call source is marked `static` for source-code detections and `runtime` only when runtime evidence is present.

Address ratings follow the active terms registry: blacklisted addresses are high risk, known addresses are low risk, and unknown addresses are low-mid risk. The overall score summarizes the highest observed weighted address and parameter exposure. A registry match is an identity hint, not a safety guarantee; this is not a security audit. Static slippage checks only flag recognizable values exposed in call parameters.

Build or open the standalone ruleset editor:

```sh
npm run ruleset:build
# Open ruleset.html directly in a browser
```

The editor starts from `data/registry.static.json`, searches and filters the premapped tokens, protocols, and contracts, supports including/excluding defaults, and lets you add custom mappings, blacklist addresses, and set a high-slippage threshold in basis points. Download its JSON ruleset and apply it during analysis:

```sh
npm run scan -- src/index.ts --ruleset eth-call-scout.ruleset.json \\
  --out reports/calls.html --json reports/calls.json
```

Rulesets use version 1 JSON. Set `includeDefaults` to false to use only custom mappings, or use `excludeAddresses` / `excludeProtocolIds` for selected exclusions. `blacklistAddresses` identifies high-risk addresses; `knownAddresses` can add trusted address identities; `trustedFunctions` marks exact function names in the report; and `highSlippageBps` controls the static slippage warning threshold (default 500). `tokens`, `protocols`, and `contracts` hold custom mappings; entries can have `enabled: false` to keep them in the file without applying them.
