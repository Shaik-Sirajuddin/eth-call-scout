# Authorization audit log

Every wallet decision should be retained outside the agent's authority. `createAuditLog()` writes one JSON receipt per line and links each record to the previous record with SHA-256.

```js
import { createAuditLog } from './src/audit-log.js';

const audit = createAuditLog('/trusted/callscout/receipts.jsonl');
const guarded = createGuardedProvider({
  provider: walletProvider,
  policy,
  stateSource,
  onDecision: (receipt) => audit.append(receipt),
});
```

Verify the chain at startup, during monitoring, or after an incident:

```sh
callscout audit verify /trusted/callscout/receipts.jsonl
```

The log detects modification, deletion in the middle, reordering, and insertion when a trusted head hash is retained. Hash chaining is tamper-evident, not immutable storage: an attacker who can replace the whole file and its expected head can rewrite history. Protect the file and periodically anchor or export its head hash to a separate trusted system.

The built-in sink is single-writer. Use a transactional database or append-only service for concurrent production instances.
