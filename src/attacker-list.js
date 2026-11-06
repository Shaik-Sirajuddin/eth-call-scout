import fs from 'node:fs';
import { id } from 'ethers';
import { sha256 } from './canonical.js';
import { assertAttackerDocument, localAttackerListPath, mergeAttackerDocuments } from './attacker-feed.js';

const ADDRESS = /^0x[0-9a-f]{40}$/;
const genuineLists = new WeakSet();
const TRANSFER_TOPIC = id('Transfer(address,address,uint256)').toLowerCase();
const APPROVAL_TOPIC = id('Approval(address,address,uint256)').toLowerCase();
const APPROVAL_FOR_ALL_TOPIC = id('ApprovalForAll(address,address,bool)').toLowerCase();
const TRANSFER_SINGLE_TOPIC = id('TransferSingle(address,address,address,uint256,uint256)').toLowerCase();
const TRANSFER_BATCH_TOPIC = id('TransferBatch(address,address,address,uint256[],uint256[])').toLowerCase();

function topicAddress(topic) {
  return /^0x[0-9a-fA-F]{64}$/.test(String(topic)) ? `0x${topic.slice(-40).toLowerCase()}` : null;
}

/** Build a list. Bad data throws, so a damaged file can never silently remove an attacker. */
export function createAttackerList(document) {
  if (document?.version !== 1 || typeof document.listVersion !== 'string' || !document.entries || typeof document.entries !== 'object' || Array.isArray(document.entries)) {
    throw new Error('Invalid attacker list.');
  }
  const entries = new Map();
  for (const [address, entry] of Object.entries(document.entries)) {
    if (!ADDRESS.test(address) || !entry || !Array.isArray(entry.sources) || !entry.sources.length) throw new Error(`Invalid attacker list entry ${address}.`);
    entries.set(address, Object.freeze({ address, label: entry.label ?? 'Known attacker address', sources: Object.freeze([...entry.sources]), reference: entry.reference ?? null }));
  }
  const list = Object.freeze({
    version: document.listVersion,
    hash: sha256(document),
    count: entries.size,
    find: (address) => entries.get(String(address ?? '').toLowerCase()) ?? null,
  });
  genuineLists.add(list);
  return list;
}

/** Only a list built by createAttackerList has a hash that really describes its contents. */
export function assertAttackerList(list) {
  if (!genuineLists.has(list)) throw new TypeError('attackerList must be created by createAttackerList.');
  return list;
}

/** What a receipt records, so it always names the list that made the decision. */
export function attackerListIdentity(list) {
  return { version: list.version, hash: list.hash, count: list.count };
}

/**
 * The shipped list, plus anything added by `keybound attackers update`. A damaged local file is reported
 * and ignored, so it can never leave the guard with less than the shipped list.
 */
function loadAttackerDocument() {
  const shipped = assertAttackerDocument(JSON.parse(fs.readFileSync(new URL('../data/attacker-addresses.json', import.meta.url), 'utf8')));
  const file = localAttackerListPath();
  let local;
  try { local = JSON.parse(fs.readFileSync(/*turbopackIgnore: true*/ file, 'utf8')); }
  catch (error) {
    if (error.code !== 'ENOENT') process.stderr.write(`[keybound] Ignoring the attacker list at ${file}: ${error.message}\n`);
    return shipped;
  }
  try { return mergeAttackerDocuments(shipped, local).document; }
  catch (error) {
    process.stderr.write(`[keybound] Ignoring the attacker list at ${file}: ${error.message}\n`);
    return shipped;
  }
}

export const ATTACKER_DOCUMENT = Object.freeze(loadAttackerDocument());
export const ATTACKER_LIST = createAttackerList(ATTACKER_DOCUMENT);

/** The shipped list always applies. A policy can only add to it through blockedAddresses. */
export function attackerLookup(list, policy = null) {
  const added = new Set((Array.isArray(policy?.blockedAddresses) ? policy.blockedAddresses : []).map((address) => String(address).toLowerCase()));
  return (address) => {
    const lower = String(address ?? '').toLowerCase();
    if (added.has(lower)) return { address: lower, label: 'Blocked by this policy', sources: ['policy'], reference: null };
    return list.find(lower);
  };
}

/**
 * Find listed addresses anywhere in hex data. Checking every byte offset also covers packed encodings
 * such as swap paths. A chance match on 20 random bytes is not a practical concern.
 */
export function findAttackersInHex(hex, lookup) {
  const data = String(hex ?? '').replace(/^0x/i, '').toLowerCase();
  const found = new Map();
  for (let index = 0; index + 40 <= data.length; index += 2) {
    const candidate = `0x${data.slice(index, index + 40)}`;
    const match = lookup(candidate);
    if (match) found.set(match.address, match);
  }
  return [...found.values()];
}

/** The addresses that receive tokens, approvals or operator rights in a set of logs. */
export function logBeneficiaries(logs) {
  const found = [];
  for (const log of logs ?? []) {
    const topics = log?.topics ?? [];
    const topic = String(topics[0] ?? '').toLowerCase();
    if (topic === TRANSFER_TOPIC || topic === APPROVAL_TOPIC || topic === APPROVAL_FOR_ALL_TOPIC) found.push({ address: topicAddress(topics[2]), token: log.address, kind: topic === TRANSFER_TOPIC ? 'recipient' : 'spender' });
    else if (topic === TRANSFER_SINGLE_TOPIC || topic === TRANSFER_BATCH_TOPIC) found.push({ address: topicAddress(topics[3]), token: log.address, kind: 'recipient' });
  }
  return found.filter((entry) => entry.address);
}

/** Check what a transaction really did: who was called, who received value, and who was named in any call. */
export function findAttackersInEffects({ calls = [], logs = [], accounts = [] }, lookup) {
  const hits = new Map();
  const record = (match, reason) => {
    if (!match) return;
    const existing = hits.get(match.address) ?? { address: match.address, label: match.label, sources: match.sources, reasons: [] };
    if (!existing.reasons.includes(reason)) existing.reasons.push(reason);
    hits.set(match.address, existing);
  };
  for (const call of calls) {
    record(lookup(call.to), 'called or paid by this transaction');
    for (const match of findAttackersInHex(call.input, lookup)) record(match, 'named in call data');
  }
  for (const beneficiary of logBeneficiaries(logs)) {
    record(lookup(beneficiary.address), beneficiary.kind === 'recipient' ? `receives tokens from ${beneficiary.token}` : `gets approval on ${beneficiary.token}`);
  }
  for (const account of accounts) record(lookup(account), 'state changed by this transaction');
  return [...hits.values()];
}

export function describeAttacker(match) {
  return `${match.address} (${match.label})`;
}
