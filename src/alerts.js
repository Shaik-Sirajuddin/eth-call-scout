import fs from 'node:fs/promises';
import path from 'node:path';
import { createAuditLog, verifyAuditLog } from './audit-log.js';

export const ALERT_SEVERITIES = Object.freeze(['critical', 'warning', 'info']);

/** Alerts raised before a transaction reaches the wallet, and after it lands on-chain. */
export const ALERT_CODES = Object.freeze({
  ATTACKER_BLOCKED: 'attacker-blocked',
  BLOCK_LIMIT_REACHED: 'block-limit-reached',
  ONCHAIN_REVERTED: 'onchain-reverted',
  ONCHAIN_MISMATCH: 'onchain-mismatch',
  ONCHAIN_ATTACKER: 'onchain-attacker',
  ONCHAIN_LIMIT_EXCEEDED: 'onchain-limit-exceeded',
  ONCHAIN_GAS_EXCEEDED: 'onchain-gas-exceeded',
  ONCHAIN_DIFFERS_FROM_SIMULATION: 'onchain-differs-from-simulation',
  ONCHAIN_NOT_MINED: 'onchain-not-mined',
  ONCHAIN_TRACE_UNAVAILABLE: 'onchain-trace-unavailable',
  ONCHAIN_SWAP_OUTPUT: 'onchain-swap-output',
  ONCHAIN_UNAVAILABLE: 'onchain-unavailable',
  UNAPPROVED_TRANSACTION: 'unapproved-transaction',
});

function describe(alert) {
  return `[keybound ${alert.severity}] ${alert.code}: ${alert.message}${alert.transactionHash ? ` (tx ${alert.transactionHash})` : ''}`;
}

/** Writes alerts to stderr only. Used when no alert log is configured, so nothing is lost silently. */
export function createConsoleAlerts() {
  return Object.freeze({ async append(alert) { process.stderr.write(`${describe(alert)}\n`); return alert; } });
}

/**
 * Hash-chained alert log for an operator who runs Keybound themselves and reads the logs.
 * Appends run one at a time, because each record links to the one before it.
 */
export function createAlertLog(file, { echo = true } = {}) {
  const target = path.resolve(file);
  const log = createAuditLog(target);
  let tail = Promise.resolve();
  return Object.freeze({
    file: target,
    append(alert) {
      const write = tail.then(async () => {
        if (echo) process.stderr.write(`${describe(alert)}\n`);
        return log.append(alert);
      });
      tail = write.catch(() => {});
      return write;
    },
    verify: () => verifyAuditLog(target),
    read: () => readAlerts(target),
  });
}

/** Read an alert file, newest last. A missing file means no alerts have been raised. */
export async function readAlerts(file) {
  let text;
  try { text = await fs.readFile(path.resolve(file), 'utf8'); }
  catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  return text.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line).receipt);
}

export function formatAlert(alert) {
  return `${alert.at}  ${alert.severity.toUpperCase().padEnd(8)}  ${alert.code.padEnd(32)}  ${alert.message}${alert.transactionHash ? `  tx=${alert.transactionHash}` : ''}`;
}

/** Never let a failing log change a security decision. Report the failure and carry on. */
export async function raiseAlert(sink, { severity = 'warning', code, message, transactionHash = null, blockNumber = null, details = null }, now = () => new Date()) {
  const alert = { version: 1, at: new Date(now()).toISOString(), severity, code, message, transactionHash, blockNumber, details };
  try { await sink.append(alert); }
  catch (error) { process.stderr.write(`[keybound] Could not write alert: ${error.message}. ${describe(alert)}\n`); }
  return alert;
}
