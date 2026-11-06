import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createAuditLog, verifyAuditLog } from '../src/audit-log.js';

test('writes and verifies a hash-chained receipt log', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'callscout-audit-'));
  const file = path.join(directory, 'receipts.jsonl');
  try {
    const log = createAuditLog(file);
    const first = await log.append({ decision: 'deny', intent: { hash: 'a' } });
    const second = await log.append({ decision: 'allow', intent: { hash: 'b' } });
    assert.equal(first.index, 1);
    assert.equal(second.previousHash, first.hash);
    assert.deepEqual(await log.verify(), { valid: true, count: 2, headHash: second.hash, errors: [] });
  } finally {
    await fs.rm(directory, { recursive: true });
  }
});

test('detects receipt modification and refuses to append', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'callscout-audit-'));
  const file = path.join(directory, 'receipts.jsonl');
  try {
    const log = createAuditLog(file);
    await log.append({ decision: 'deny', checks: [] });
    const text = await fs.readFile(file, 'utf8');
    await fs.writeFile(file, text.replace('"deny"', '"allow"'));
    const result = await verifyAuditLog(file);
    assert.equal(result.valid, false);
    assert.match(result.errors[0].message, /hash/);
    await assert.rejects(log.append({ decision: 'deny' }), /corrupted/);
  } finally {
    await fs.rm(directory, { recursive: true });
  }
});
