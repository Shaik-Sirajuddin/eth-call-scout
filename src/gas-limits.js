import fs from 'node:fs';
import { sha256 } from './canonical.js';
import { codeVersionChange } from './code-version.js';

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const SELECTOR = /^0x[a-f0-9]{8}$/;
const POSITIVE_UINT = /^[1-9][0-9]*$/;
const HASH = /^0x[a-f0-9]{64}$/;

function validPin(pin) {
  if (!pin || !HASH.test(String(pin.codeHash))) return false;
  if (pin.implementation == null) return true;
  const { kind, slot, address } = pin.implementation;
  return ADDRESS.test(String(address)) && (kind === 'call' || (kind === 'slot' && HASH.test(String(slot))));
}

/** Build a rule set. Bad data throws, so a damaged file can never silently remove limits. */
export function createGasRules(document) {
  if (document?.version !== 1 || typeof document.rulesVersion !== 'string' || !Number.isFinite(Date.parse(document.validUntil)) || !Array.isArray(document.rules)) throw new Error('Invalid gas rule set.');
  const rules = new Map();
  for (const rule of document.rules) {
    const valid = Number.isSafeInteger(rule.chainId) && ADDRESS.test(String(rule.address)) && SELECTOR.test(String(rule.selector))
      && POSITIVE_UINT.test(String(rule.maxGas)) && typeof rule.versionTag === 'string' && rule.versionTag.length > 0 && validPin(rule.codeVersion);
    if (!valid) throw new Error(`Invalid gas rule for ${rule.address} ${rule.selector}.`);
    rules.set(`${rule.chainId}:${rule.address.toLowerCase()}:${rule.selector}`, Object.freeze({ ...rule }));
  }
  return Object.freeze({
    version: document.rulesVersion,
    validUntil: document.validUntil,
    hash: sha256(document),
    find: (chainId, address, selector) => rules.get(`${chainId}:${String(address).toLowerCase()}:${String(selector).toLowerCase()}`) ?? null,
  });
}

export const GAS_RULES = createGasRules(JSON.parse(fs.readFileSync(new URL('../data/gas-limits.json', import.meta.url), 'utf8')));

/**
 * Decide which rules still describe the live contracts. An outdated rule must not deny honest calls,
 * because an upgrade can legitimately change what a function costs.
 */
export async function checkGasRuleVersions(ruleSet, rules, rpc, { blockTag = 'latest', now = new Date() } = {}) {
  const statuses = new Map();
  const expired = Date.parse(ruleSet.validUntil) <= new Date(now).getTime();
  const changes = new Map();
  for (const rule of rules) {
    if (statuses.has(rule)) continue;
    if (expired) { statuses.set(rule, { current: false, reason: `the rule set expired on ${ruleSet.validUntil}` }); continue; }
    if (!changes.has(rule.address)) changes.set(rule.address, await codeVersionChange(rpc, rule.address, rule.codeVersion, blockTag));
    const reason = changes.get(rule.address);
    statuses.set(rule, { current: reason == null, reason });
  }
  return statuses;
}
