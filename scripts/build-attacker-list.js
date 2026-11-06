#!/usr/bin/env node
// Builds data/attacker-addresses.json from public feeds plus the hand-checked list.
// Run with: npm run attackers:sync
//
// A wrong entry can only deny a call, never allow one. Addresses this project relies on are still removed,
// so a bad feed row cannot stop the protocols in the registry and gas rules from working.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { protectedAddresses } from '../src/attacker-feed.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const OUTPUT = path.join(ROOT, 'data', 'attacker-addresses.json');
const CURATED = path.join(ROOT, 'data', 'attacker-addresses.curated.json');
const ADDRESS = /^0x[0-9a-f]{40}$/;
const FORTA = 'https://raw.githubusercontent.com/forta-network/labelled-datasets/main/labels/1';
const MALICIOUS_CREATOR = /exploit|hack|attack|phish|drain|scam/i;

function parseCsv(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    const cells = [];
    let cell = '';
    let quoted = false;
    for (const character of line) {
      if (character === '"') quoted = !quoted;
      else if (character === ',' && !quoted) { cells.push(cell); cell = ''; } else cell += character;
    }
    cells.push(cell);
    rows.push(cells);
  }
  const [header, ...body] = rows;
  return body.map((cells) => Object.fromEntries(header.map((name, index) => [name, cells[index] ?? ''])));
}

const FEEDS = [
  {
    id: 'ofac-sdn',
    url: 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt',
    license: 'MIT',
    parse: (text) => text.split(/\r?\n/).map((address) => ({ address, label: 'OFAC sanctioned address' })),
  },
  {
    id: 'forta-malicious-contracts',
    url: `${FORTA}/malicious_smart_contracts.csv`,
    license: 'MIT',
    parse: (text) => parseCsv(text).flatMap((row) => [
      { address: row.contract_address, label: row.contract_tag },
      ...(MALICIOUS_CREATOR.test(row.contract_creator_tag) ? [{ address: row.contract_creator, label: row.contract_creator_tag }] : []),
    ]),
  },
  {
    id: 'forta-phishing',
    url: `${FORTA}/phishing_scams.csv`,
    license: 'MIT',
    parse: (text) => parseCsv(text).map((row) => ({ address: row.address, label: row.etherscan_tag })),
  },
  {
    id: 'forta-etherscan-malicious',
    url: `${FORTA}/etherscan_malicious_labels.csv`,
    license: 'MIT',
    parse: (text) => parseCsv(text).map((row) => ({ address: row.banned_address ?? row.address, label: row.etherscan_tag ?? row.wallet_tag ?? '' })),
  },
];

// GPL-3.0 data, so it stays out of the shipped file unless the person running this asks for it.
const OPTIONAL_FEEDS = {
  '--with-scamsniffer': {
    id: 'scamsniffer',
    url: 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json',
    license: 'GPL-3.0',
    parse: (text) => JSON.parse(text).map((address) => ({ address, label: 'ScamSniffer blacklist' })),
  },
};

async function download(feed) {
  const response = await fetch(feed.url, { headers: { 'user-agent': 'keybound-attacker-list/0.1' }, signal: AbortSignal.timeout(60_000) });
  if (!response.ok) throw new Error(`${feed.id}: HTTP ${response.status}`);
  return response.text();
}

async function main() {
  const flags = process.argv.slice(2).filter((flag) => flag !== '--force');
  const force = process.argv.includes('--force');
  const feeds = [...FEEDS, ...flags.map((flag) => OPTIONAL_FEEDS[flag] ?? (() => { throw new Error(`Unknown option ${flag}`); })())];
  const safe = protectedAddresses();
  const entries = new Map();
  const excluded = [];
  const sources = [];
  const add = (address, source, label, reference) => {
    const lower = String(address ?? '').trim().toLowerCase();
    if (!ADDRESS.test(lower)) return false;
    if (safe.has(lower)) { excluded.push(lower); return false; }
    if (entries.has(lower)) {
      const existing = entries.get(lower);
      if (!existing.sources.includes(source)) existing.sources.push(source);
      return true;
    }
    entries.set(lower, { sources: [source], ...(label ? { label: String(label).trim().slice(0, 120) } : {}), ...(reference ? { reference } : {}) });
    return true;
  };

  // Hand-checked entries go first, so their labels win.
  const curated = JSON.parse(fs.readFileSync(CURATED, 'utf8'));
  for (const entry of curated.entries) if (!add(entry.address, 'curated', entry.label, entry.reference)) throw new Error(`Curated address was refused: ${entry.address}`);
  sources.push({ id: 'curated', url: 'data/attacker-addresses.curated.json', license: 'project', rows: curated.entries.length });

  for (const feed of feeds) {
    const rows = feed.parse(await download(feed));
    const accepted = rows.filter((row) => add(row.address, feed.id, row.label)).length;
    if (!accepted) throw new Error(`${feed.id} produced no addresses, so its format may have changed.`);
    sources.push({ id: feed.id, url: feed.url, license: feed.license, rows: accepted });
    console.log(`${feed.id.padEnd(28)} ${String(accepted).padStart(6)} addresses`);
  }

  const sorted = [...entries.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  // Keep the file unchanged when no address changed, so the scheduled update only opens a PR for real news.
  if (!force && fs.existsSync(OUTPUT)) {
    const existing = JSON.parse(fs.readFileSync(OUTPUT, 'utf8'));
    if (JSON.stringify(Object.keys(existing.entries)) === JSON.stringify(sorted.map(([address]) => address))) {
      console.log(`\nNo new addresses. data/attacker-addresses.json still has ${sorted.length}.`);
      return;
    }
  }
  const generatedAt = new Date().toISOString();
  const document = {
    version: 1,
    listVersion: generatedAt.slice(0, 10),
    generatedAt,
    sources,
    excludedBecauseProtocolOrSystemAddress: [...new Set(excluded)].sort(),
    entries: Object.fromEntries(sorted),
  };
  fs.writeFileSync(OUTPUT, `${JSON.stringify(document)}\n`);
  console.log(`\n${sorted.length} attacker addresses written to data/attacker-addresses.json. Refused ${document.excludedBecauseProtocolOrSystemAddress.length} protocol or system addresses.`);
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
