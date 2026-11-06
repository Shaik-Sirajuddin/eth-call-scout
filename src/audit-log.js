import fs from 'node:fs/promises';
import path from 'node:path';
import { sha256 } from './canonical.js';

const GENESIS = '0'.repeat(64);

export async function verifyAuditLog(file) {
  let text;
  try { text = await fs.readFile(file, 'utf8'); }
  catch (error) {
    if (error.code === 'ENOENT') return { valid: true, count: 0, headHash: GENESIS, errors: [] };
    throw error;
  }
  const lines = text.split(/\r?\n/).filter(Boolean);
  const errors = [];
  let previousHash = GENESIS;
  for (let index = 0; index < lines.length; index++) {
    let record;
    try { record = JSON.parse(lines[index]); }
    catch { errors.push({ line: index + 1, message: 'Invalid JSON.' }); continue; }
    if (record.version !== 1) errors.push({ line: index + 1, message: 'Unsupported audit record version.' });
    if (record.index !== index + 1) errors.push({ line: index + 1, message: `Expected index ${index + 1}.` });
    if (record.previousHash !== previousHash) errors.push({ line: index + 1, message: 'Previous hash does not match the chain head.' });
    const expected = sha256({ version: record.version, index: record.index, previousHash: record.previousHash, receipt: record.receipt });
    if (record.hash !== expected) errors.push({ line: index + 1, message: 'Record hash does not match its contents.' });
    previousHash = record.hash;
  }
  return { valid: errors.length === 0, count: lines.length, headHash: previousHash, errors };
}

/** Single-writer, hash-chained JSONL sink. Keep its path outside the agent's authority. */
export function createAuditLog(file) {
  const target = path.resolve(file);
  return Object.freeze({
    async append(receipt) {
      const status = await verifyAuditLog(target);
      if (!status.valid) throw new Error('Refusing to append to a corrupted audit log.');
      const body = { version: 1, index: status.count + 1, previousHash: status.headHash, receipt };
      const record = { ...body, hash: sha256(body) };
      await fs.mkdir(path.dirname(target), { recursive: true });
      const handle = await fs.open(target, 'a', 0o600);
      try { await handle.writeFile(`${JSON.stringify(record)}\n`); await handle.sync(); }
      finally { await handle.close(); }
      return record;
    },
    verify() { return verifyAuditLog(target); },
  });
}
