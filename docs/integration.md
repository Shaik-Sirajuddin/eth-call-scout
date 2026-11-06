# Wallet integration

The guarded provider must be the agent's only path to wallet authority.

```js
import fs from 'node:fs';
import { createAuditLog } from '../src/audit-log.js';
import { createGuardedProvider } from '../src/wallet-guard.js';
import { createFileSequenceStore, createLiveStateSource } from '../src/protocol-state.js';

const policy = JSON.parse(fs.readFileSync('wallet-policy.json', 'utf8'));
const audit = createAuditLog('/trusted/callscout/receipts.jsonl');
const guardedProvider = createGuardedProvider({
  provider: walletProvider,
  policy,
  stateSource: createLiveStateSource({
    url: 'https://state.example/callscout.json',
    cachePath: '/trusted/cache/callscout-state.json',
  }),
  stateSequenceStore: createFileSequenceStore('/trusted/callscout-sequence.json'),
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
4. Preserve the exact request object evaluated by the guard. Do not let another component rewrite calldata, target, value, fees, or chain after authorization.
5. Store receipts somewhere the agent cannot modify or delete.
6. Keep native wallet confirmation enabled for high-risk policies. CallScout is compatible with human approval and multisig flows.
7. Use short-lived policies and low value/approval ceilings for unattended operation.
8. Protect the persistent state-sequence store from agent writes and deletion.
9. Configure independent trace-capable simulation RPCs through the environment variables named by policy. Do not reuse one URL under multiple source IDs.
10. Keep EIP-7702 disabled unless the integration can maintain a reviewed delegate allowlist and pinned runtime code hashes.

## RPC surface

The guard exposes common read-only Ethereum methods. It supports one mutation path: `eth_sendTransaction` after policy authorization, authenticated live-state verification, and full transaction simulation.

Legacy/type-0 and EIP-1559/type-2 requests are supported. Type-4 EIP-7702 requests are default-deny and require explicit policy opt-in plus signature, chain, nonce, delegate code-hash, and state-diff checks. A delegated wallet can send batches through a self-call; every call it sends is checked against policy using the simulated call tree. Type-1, type-3 blob, and all other transaction envelopes deny until explicitly implemented. Every supported transaction that could be forwarded must reach simulation quorum; an earlier deterministic denial stops without wallet access.

It denies raw signing, message signing, typed-data signing, raw transaction submission, wallet permissions, chain switching/addition, and unsupported batch APIs. Supporting a new mutation method requires a purpose-built parser and policy evaluator; adding it to an allowlist is not enough.

## Audit sink

`onDecision` receives allow and deny receipts. A receipt includes the evaluation timestamp, canonical policy hash, normalized transaction hash, authenticated state summary, simulation fingerprint and source summary, decision, and every check result. Receipt storage should be append-only and should record the eventual transaction hash returned by the wallet alongside the authorization receipt.

The built-in hash-chained JSONL sink is single-writer and tamper-evident. It is not immutable storage; protect its path from the agent and anchor its head hash separately for stronger deletion/replacement evidence.

## Error handling

Denied calls throw `WalletGuardError` with EIP-1193-style code `4100` and a `receipt` property. Present the failed check to the user without silently broadening policy, weakening quorum, changing an approved delegate, or retrying through an unguarded provider.
