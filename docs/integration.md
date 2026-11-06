# Wallet integration

The guarded provider must be the agent's only path to wallet authority.

```js
import fs from 'node:fs';
import { createAuditLog } from '../src/audit-log.js';
import { createGuardedProvider } from '../src/wallet-guard.js';
import { createFileSequenceStore, createLiveStateSource } from '../src/protocol-state.js';

const policy = JSON.parse(fs.readFileSync('wallet-policy.json', 'utf8'));
const audit = createAuditLog('/trusted/keybound/receipts.jsonl');
const guardedProvider = createGuardedProvider({
  provider: walletProvider,
  policy,
  stateSource: createLiveStateSource({
    url: 'https://state.example/keybound.json',
    cachePath: '/trusted/cache/keybound-state.json',
  }),
  stateSequenceStore: createFileSequenceStore('/trusted/keybound-sequence.json'),
  onDecision: async (receipt) => {
    await audit.append(receipt);
  },
});

agentTools.register('ethereum', guardedProvider);
```

## Integration rules

1. Do not pass `walletProvider`, a signer, a private key, a seed phrase, or a wallet session object to the model runtime.
2. Do not expose filesystem or environment access that lets the agent recover wallet secrets or replace the active policy.
3. Put the guard immediately next to the wallet boundary. A preflight check in a separate tool is insufficient because the eventual transaction can differ.
4. Supply explicit `chainId` and pending `nonce` fields, send the gas limit as a hex `gas` field within the function's [gas limit](policies.md#function-gas-limits), then preserve the exact request object evaluated by the guard. Do not let another component rewrite calldata, target, value, nonce, access list, gas, fees, type, or chain after authorization.
5. Store receipts somewhere the agent cannot modify or delete.
6. Keep native wallet confirmation enabled for high-risk policies. Keybound is compatible with human approval and multisig flows.
7. Use short-lived policies and low value/approval ceilings for unattended operation.
8. Protect the persistent state-sequence store from agent writes and deletion.
9. Configure at least two independent trace-capable simulation RPCs with quorum of at least two through the environment variables named by policy. Do not reuse one URL under multiple source IDs.
10. Keep EIP-7702 disabled unless the integration can maintain a reviewed delegate allowlist and pinned runtime code hashes.

## RPC surface

The guard exposes common read-only Ethereum methods. It supports one mutation path: `eth_sendTransaction` after policy authorization, authenticated live-state verification, and full transaction simulation.

Legacy/type-0 and EIP-1559/type-2 requests are supported. Every request must include an explicit chain ID and outer nonce; every simulation source must report that nonce as pending. Type-2 access lists are strictly parsed, bounded, normalized, and simulated unchanged. Type-4 EIP-7702 requests are default-deny and require explicit policy opt-in plus signature, chain, outer/authorization nonce binding, delegate code-hash, and state-diff checks. A delegated wallet can send batches through a self-call; every wallet-originated call is checked against exact contract policy and signed live state from the simulated call tree. Type-1, type-3 blob, and all other transaction envelopes deny until explicitly implemented. Every supported transaction that could be forwarded must reach simulation quorum; an earlier deterministic denial stops without wallet access.

It denies raw signing, message signing, typed-data signing, raw transaction submission, wallet permissions, chain switching/addition, and unsupported batch APIs. Supporting a new mutation method requires a purpose-built parser and policy evaluator; adding it to an allowlist is not enough.

Pass a custom gas rule set, built by `createGasRules`, as `gasRules` to `createGuardedProvider`. One set is chosen when the guard is created. Authorization and simulation both use it, it is part of the decision fingerprint, and each receipt records its version and hash under `gasRules`. A simulation that used a different set is denied.

## Audit sink

`onDecision` receives allow and deny receipts. A receipt includes the evaluation timestamp, canonical policy hash, normalized transaction hash, authenticated state summary, simulation fingerprint and source summary, decision, and every check result. Receipt storage should be append-only and should record the eventual transaction hash returned by the wallet alongside the authorization receipt.

The built-in hash-chained JSONL sink is single-writer and tamper-evident. It is not immutable storage; protect its path from the agent and anchor its head hash separately for stronger deletion/replacement evidence.

## Error handling

Denied calls throw `WalletGuardError` with EIP-1193-style code `4100` and a `receipt` property. Present the failed check to the user without silently broadening policy, weakening quorum, changing an approved delegate, or retrying through an unguarded provider.

## Alerts and on-chain checks

Once a transaction lands, the guard checks it against the chain in the background, without holding up the agent. It reads through a simulation source, not the wallet it is checking.

| Check | Fails when |
|---|---|
| `onchain:status` | The transaction reverted |
| `onchain:transaction-match` | The wallet sent a different sender, target, calldata, value or nonce than was approved |
| `onchain:attacker` | A listed attacker received value or approval |
| `onchain:asset-limits` | Tokens left beyond the policy's limits or to an unapproved address |
| `onchain:block-limit` | The real block went over a per-block limit |
| `onchain:gas` | More gas was used than the function allows |
| `onchain:matches-simulation` | More left the wallet than simulation showed |
| `onchain:all-transactions-approved` | The wallet sent a transaction that did not go through the guard |

Failures do not undo anything, because the transaction has already happened. They are written as alerts for you to read:

```js
import { createAlertLog } from './src/alerts.js';
import { createAuditLog } from './src/audit-log.js';

const audit = createAuditLog('/trusted/keybound/receipts.jsonl');
const agentProvider = createGuardedProvider({
  provider: walletProvider,
  policy,
  stateSource,
  alerts: createAlertLog('/trusted/keybound/alerts.jsonl'),
  onDecision: (receipt) => audit.append(receipt),
  onVerification: (result) => audit.append(result),
});
```

```sh
npx keybound alerts show /trusted/keybound/alerts.jsonl
npx keybound alerts show /trusted/keybound/alerts.jsonl --severity critical
npx keybound alerts verify /trusted/keybound/alerts.jsonl
```

Without `alerts`, they go to stderr. The log is hash-chained, so edits can be detected. Keep it where the agent cannot write. Set `verification: false` to turn the on-chain check off, or pass `verification: { request, timeoutMs, pollMs }` to choose how it reads the chain. It also turns off by itself when no simulation source URL is set.

The check for transactions sent around the guard only sees nonces after the guard started, so it does not cover earlier history.
