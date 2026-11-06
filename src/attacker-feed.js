import fs from 'node:fs';
import path from 'node:path';
import { sha256 } from './canonical.js';

const ADDRESS = /^0x[0-9a-f]{40}$/;
const MAX_DOCUMENT_BYTES = 50_000_000;
const MAX_ENTRIES = 1_000_000;

/** Free and needs no key. Users can point at their own copy or the hosted API instead. */
export const DEFAULT_ATTACKER_LIST_URL = process.env.KEYBOUND_ATTACKER_LIST_URL ?? 'https://raw.githubusercontent.com/x0rc1ph3r/eth-call-scout/main/data/attacker-addresses.json';

export function localAttackerListPath() {
  // The ignore comments stop the Next.js bundler from tracing the whole project through these runtime paths.
  return process.env.KEYBOUND_ATTACKER_LIST_FILE ?? path.join(/*turbopackIgnore: true*/ process.cwd(), '.keybound', 'attacker-addresses.json');
}

/**
 * Addresses an update may never add: the zero and burn addresses, precompiles, and every contract
 * this project relies on. Otherwise one bad feed row could stop every honest swap.
 */
export function protectedAddresses() {
  const found = new Set(['0x0000000000000000000000000000000000000000', '0x000000000000000000000000000000000000dead']);
  for (let index = 1; index <= 0x11; index++) found.add(`0x${index.toString(16).padStart(40, '0')}`);
  for (const file of [new URL('../data/registry.static.json', import.meta.url), new URL('../data/gas-limits.json', import.meta.url), new URL('../data/rule-sets/general.json', import.meta.url)]) {
    let text;
    try { text = fs.readFileSync(/*turbopackIgnore: true*/ file, 'utf8'); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    for (const match of text.matchAll(/0x[0-9a-fA-F]{40}(?![0-9a-fA-F])/g)) found.add(match[0].toLowerCase());
  }
  return found;
}

/** Refuse anything that is not a list, so a broken response can never be saved as one. */
export function assertAttackerDocument(document) {
  if (document?.version !== 1 || typeof document.listVersion !== 'string' || !document.entries || typeof document.entries !== 'object' || Array.isArray(document.entries)) {
    throw new Error('This is not an attacker list.');
  }
  const addresses = Object.keys(document.entries);
  if (addresses.length > MAX_ENTRIES) throw new Error(`Attacker list has ${addresses.length} entries, more than the limit of ${MAX_ENTRIES}.`);
  for (const address of addresses) {
    const entry = document.entries[address];
    if (!ADDRESS.test(address) || !entry || !Array.isArray(entry.sources) || !entry.sources.length) throw new Error(`Invalid attacker list entry ${address}.`);
  }
  return document;
}

/**
 * Add an update to a list. An update can only add addresses, so a hacked or broken list server can
 * never remove an attacker. Protected addresses are dropped and reported back.
 */
export function mergeAttackerDocuments(base, update, { protect = protectedAddresses() } = {}) {
  assertAttackerDocument(base);
  assertAttackerDocument(update);
  const entries = { ...base.entries };
  const added = [];
  const refused = [];
  for (const [address, entry] of Object.entries(update.entries)) {
    if (protect.has(address)) { if (!base.entries[address]) refused.push(address); continue; }
    if (!entries[address]) added.push(address);
    entries[address] = entries[address] ?? entry;
  }
  const sources = [...new Map([...(base.sources ?? []), ...(update.sources ?? [])].map((source) => [source.id, source])).values()];
  const sorted = Object.fromEntries(Object.entries(entries).sort(([a], [b]) => (a < b ? -1 : 1)));
  return {
    document: {
      version: 1,
      listVersion: update.listVersion > base.listVersion ? update.listVersion : base.listVersion,
      generatedAt: update.generatedAt ?? base.generatedAt ?? null,
      sources,
      excludedBecauseProtocolOrSystemAddress: [...new Set([...(base.excludedBecauseProtocolOrSystemAddress ?? []), ...refused])].sort(),
      entries: sorted,
    },
    added,
    refused,
  };
}

/** Download a list and check it arrived intact when the server states its hash. */
export async function fetchAttackerDocument(url = DEFAULT_ATTACKER_LIST_URL, { fetchImpl = fetch, timeoutMs = 60_000 } = {}) {
  const parsed = new URL(url);
  const local = parsed.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !local) throw new Error('The attacker list must be downloaded over HTTPS.');
  const response = await fetchImpl(parsed, { headers: { accept: 'application/json', 'user-agent': 'keybound-attacker-list/0.1' }, signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) throw new Error(`The attacker list server returned HTTP ${response.status}.`);
  const text = await response.text();
  if (text.length > MAX_DOCUMENT_BYTES) throw new Error('The attacker list is too large.');
  const document = assertAttackerDocument(JSON.parse(text));
  const stated = response.headers?.get?.('x-keybound-list-hash');
  if (stated && stated !== sha256(document)) throw new Error('The attacker list does not match the hash the server stated.');
  return document;
}

/** Download the latest list, add it to what is on disk, and save it where the guard loads it from. */
export async function updateLocalAttackerList(base, { url = DEFAULT_ATTACKER_LIST_URL, file = localAttackerListPath(), fetchImpl = fetch } = {}) {
  const update = await fetchAttackerDocument(url, { fetchImpl });
  const merged = mergeAttackerDocuments(base, update);
  const target = path.resolve(/*turbopackIgnore: true*/ file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(merged.document)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, target);
  return { file: target, url: String(url), added: merged.added.length, refused: merged.refused, count: Object.keys(merged.document.entries).length, listVersion: merged.document.listVersion, hash: sha256(merged.document) };
}
