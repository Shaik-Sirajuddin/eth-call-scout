import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const STATIC_PATH = path.join(ROOT, 'data', 'registry.static.json');
const DEFAULT_CACHE = path.join(ROOT, '.cache', 'eth-call-scout', 'registry.json');
const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
function addressesIn(value, out = []) {
  if (typeof value === 'string' && ADDRESS.test(value)) out.push(value);
  else if (Array.isArray(value)) value.forEach((x) => addressesIn(x, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((x) => addressesIn(x, out));
  return [...new Set(out)];
}

export const REGISTRY_SOURCES = {
  'uniswap-token-list': { url: 'https://tokens.uniswap.org', kind: 'tokens' },
  'sushi-token-list': { url: 'https://raw.githubusercontent.com/sushiswap/default-token-list/master/tokens/mainnet.json', kind: 'tokens' },
  'defillama-protocols': { url: 'https://api.llama.fi/protocols', kind: 'protocols' },
  'defillama-ethereum-dex-volume': { url: 'https://api.llama.fi/overview/dexs/Ethereum', kind: 'volume' },
  'aave-ethereum-address-book': { url: 'https://assets.aave.com/address-book/releases/latest/modules/AaveV3Ethereum.json', kind: 'contracts' },
};

async function readJson(file, fallback) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return fallback; throw error; }
}
async function writeJsonAtomic(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(temp, `${JSON.stringify(value, null, 2)}\n`);
  await fs.rename(temp, file);
}
function addrKey(token) { return `${token.chainId}:${token.address.toLowerCase()}`; }
function dedupeTokens(tokens) {
  const map = new Map();
  for (const t of tokens) {
    if (!Number.isInteger(Number(t.chainId)) || !ADDRESS.test(String(t.address ?? ''))) continue;
    const key = addrKey(t); const old = map.get(key);
    map.set(key, old ? { ...old, ...t, sources: [...new Set([...(old.sources ?? []), ...(t.sources ?? [])])] } : { ...t, address: `0x${t.address.slice(2)}` });
  }
  return [...map.values()].sort((a, b) => a.symbol.localeCompare(b.symbol) || a.address.localeCompare(b.address));
}
function normalizeTokenList(payload, sourceId) {
  const list = Array.isArray(payload) ? payload : payload?.tokens;
  if (!Array.isArray(list)) throw new Error(`${sourceId} returned an unsupported token-list shape`);
  return list.filter((x) => Number(x.chainId) === 1 && ADDRESS.test(String(x.address ?? ''))).map((x) => ({
    chainId: 1, address: x.address, name: x.name ?? '', symbol: x.symbol ?? '', decimals: Number.isInteger(x.decimals) ? x.decimals : null,
    logoURI: x.logoURI ?? null, sources: [sourceId],
  }));
}
function normalizeProtocol(p, sourceId) {
  const hasToken = Boolean(p.symbol && ADDRESS.test(String(p.address ?? '')));
  return {
    id: String(p.slug ?? p.defillamaId ?? p.name ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
    name: p.name ?? p.displayName ?? p.slug ?? 'Unknown', symbol: p.symbol ?? null, category: p.category ?? p.protocolType ?? 'unknown',
    chains: Array.isArray(p.chains) ? p.chains : p.chain ? [p.chain] : [], url: p.url ?? null,
    address: !hasToken && ADDRESS.test(String(p.address ?? '')) ? p.address : null,
    tokenAddress: hasToken ? p.address : null, logo: p.logo ?? null,
    tvl: Number.isFinite(p.tvl) ? p.tvl : null,
    volume24h: Number.isFinite(p.total24h) ? p.total24h : null,
    volume7d: Number.isFinite(p.total7d) ? p.total7d : null,
    source: sourceId,
  };
}
function mergeProtocols(...groups) {
  const map = new Map();
  for (const p of groups.flat()) {
    if (!p.id) continue;
    const old = map.get(p.id) ?? {};
    map.set(p.id, { ...old, ...p, sources: [...new Set([...(old.sources ?? (old.source ? [old.source] : [])), ...(p.sources ?? (p.source ? [p.source] : []))])] });
  }
  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export async function loadRegistry({ cachePath = process.env.ETH_CALL_SCOUT_REGISTRY_CACHE ?? DEFAULT_CACHE } = {}) {
  const curated = await readJson(STATIC_PATH, { version: 1, tokens: [], protocols: [], volumeTrackers: [], sources: [] });
  const cached = await readJson(cachePath, { tokens: [], protocols: [], volume: [], contracts: [], syncedAt: null, sources: {} });
  let protocols = mergeProtocols(curated.protocols ?? [], cached.protocols ?? [], (cached.volume ?? []).map((x) => ({
    id: String(x.name ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''), name: x.name,
    category: 'dex', chains: ['Ethereum'], volume24h: x.total24h ?? null, volume7d: x.total7d ?? null,
    sources: ['defillama-ethereum-dex-volume'],
  })));
  const logos = protocols.filter((p) => p.logo);
  const normalizeName = (x) => String(x ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
  protocols = protocols.map((p) => {
    if (p.logo) return p;
    const normalized = normalizeName(p.name);
    const candidate = logos.find((x) => {
      const other = normalizeName(x.name);
      return normalized.length >= 4 && (other === normalized || other.startsWith(normalized) || normalized.startsWith(other));
    });
    return candidate ? { ...p, logo: candidate.logo } : p;
  });
  return { ...curated, tokens: dedupeTokens([...(curated.tokens ?? []), ...(cached.tokens ?? [])]), protocols, contracts: [...(curated.contracts ?? []), ...(cached.contracts ?? [])], liveVolume: cached.volume ?? [], syncedAt: cached.syncedAt ?? null, cachePath };
}

export function applyRuleset(registry, ruleset = {}) {
  const includeDefaults = ruleset.includeDefaults !== false;
  const excluded = new Set((ruleset.excludeAddresses ?? []).filter((x) => ADDRESS.test(String(x))).map((x) => x.toLowerCase()));
  const excludedProtocols = new Set((ruleset.excludeProtocolIds ?? []).map((x) => String(x).toLowerCase()));
  const keep = (entry) => !excluded.has(String(entry.address ?? '').toLowerCase());
  const tokens = [
    ...(includeDefaults ? registry.tokens : []),
    ...(ruleset.tokens ?? []).filter((x) => x.enabled !== false),
  ].filter(keep);
  const protocols = mergeProtocols(
    ...(includeDefaults ? [registry.protocols] : []),
    (ruleset.protocols ?? []).filter((x) => x.enabled !== false),
  ).filter((entry) => keep(entry) && !excludedProtocols.has(String(entry.id ?? '').toLowerCase()));
  const contracts = [
    ...(includeDefaults ? registry.contracts ?? [] : []),
    ...(ruleset.contracts ?? []).filter((x) => x.enabled !== false),
  ].filter((x) => ADDRESS.test(String(x.address ?? '')) && keep(x));
  return {
    ...registry,
    tokens: dedupeTokens(tokens),
    protocols,
    contracts: [...new Map(contracts.map((x) => [`${x.chainId ?? 1}:${x.address.toLowerCase()}`, { chainId: 1, ...x }])).values()],
    riskPolicy: {
      blacklistAddresses: [...new Set((ruleset.blacklistAddresses ?? []).filter((x) => ADDRESS.test(String(x))).map((x) => x.toLowerCase()))],
      knownAddresses: [...new Set((ruleset.knownAddresses ?? []).filter((x) => ADDRESS.test(String(x))).map((x) => x.toLowerCase()))],
      trustedFunctions: [...new Set((ruleset.trustedFunctions ?? []).map((x) => String(x).trim().toLowerCase()).filter(Boolean))],
      highSlippageBps: Number.isFinite(Number(ruleset.highSlippageBps)) ? Math.max(1, Number(ruleset.highSlippageBps)) : 500,
    },
  };
}

export async function syncRegistry({ kind = 'all', cachePath = process.env.ETH_CALL_SCOUT_REGISTRY_CACHE ?? DEFAULT_CACHE, fetchImpl = fetch } = {}) {
  const current = await readJson(cachePath, { version: 1, tokens: [], protocols: [], volume: [], contracts: [], syncedAt: null, sources: {} });
  const wanted = kind === 'all' ? ['tokens', 'protocols', 'volume', 'contracts'] : kind === 'protocols' ? ['protocols', 'contracts'] : [kind];
  if (wanted.some((x) => !['tokens', 'protocols', 'volume', 'contracts'].includes(x))) throw new Error(`Unknown registry kind: ${kind}`);
  const sourceStatus = { ...(current.sources ?? {}) };
  const fetchSource = async (id) => {
    const config = REGISTRY_SOURCES[id];
    const response = await fetchImpl(config.url, { headers: { accept: 'application/json', 'user-agent': 'eth-call-scout/0.1 (+https://github.com/)' }, signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`${id} responded HTTP ${response.status}`);
    return response.json();
  };
  const failures = [];
  if (wanted.includes('tokens')) {
    const got = [];
    for (const id of ['uniswap-token-list', 'sushi-token-list']) {
      try { got.push(...normalizeTokenList(await fetchSource(id), id)); sourceStatus[id] = { status: 'ok', syncedAt: new Date().toISOString() }; }
      catch (error) { failures.push(`${id}: ${error.message}`); sourceStatus[id] = { status: 'error', syncedAt: new Date().toISOString(), error: error.message }; }
    }
    if (got.length) current.tokens = dedupeTokens([...(current.tokens ?? []), ...got]);
  }
  if (wanted.includes('protocols')) {
    try {
      const data = await fetchSource('defillama-protocols');
      if (!Array.isArray(data)) throw new Error('Expected an array of protocols');
      const ethereum = data.filter((p) => Array.isArray(p.chains) && p.chains.some((c) => /^(ethereum|mainnet)$/i.test(c))).map((p) => normalizeProtocol(p, 'defillama-protocols'));
      current.protocols = mergeProtocols(current.protocols ?? [], ethereum);
      sourceStatus['defillama-protocols'] = { status: 'ok', syncedAt: new Date().toISOString(), records: ethereum.length };
    } catch (error) { failures.push(`defillama-protocols: ${error.message}`); sourceStatus['defillama-protocols'] = { status: 'error', syncedAt: new Date().toISOString(), error: error.message }; }
  }
  if (wanted.includes('volume')) {
    try {
      const data = await fetchSource('defillama-ethereum-dex-volume');
      if (!Array.isArray(data.protocols)) throw new Error('Expected a protocols array in volume response');
      current.volume = data.protocols.map((p) => normalizeProtocol(p, 'defillama-ethereum-dex-volume')).sort((a, b) => (b.volume24h ?? 0) - (a.volume24h ?? 0));
      sourceStatus['defillama-ethereum-dex-volume'] = { status: 'ok', syncedAt: new Date().toISOString(), records: current.volume.length, total24h: data.total24h ?? null };
    } catch (error) { failures.push(`defillama-ethereum-dex-volume: ${error.message}`); sourceStatus['defillama-ethereum-dex-volume'] = { status: 'error', syncedAt: new Date().toISOString(), error: error.message }; }
  }
  if (wanted.includes('contracts')) {
    try {
      const data = await fetchSource('aave-ethereum-address-book');
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Expected the Aave Ethereum address-book object');
      const records = Object.entries(data).filter(([, address]) => ADDRESS.test(String(address))).map(([name, address]) => ({
        chainId: 1, address, name: `Aave V3 ${name}`, protocolId: 'aave', role: /POOL/.test(name) ? 'lending-pool' : /ORACLE/.test(name) ? 'oracle' : /TOKEN|ASSET/.test(name) ? 'token-contract' : /SWAP/.test(name) ? 'swap-adapter' : 'protocol-contract', source: 'aave-ethereum-address-book',
      }));
      current.contracts = [...new Map([...(current.contracts ?? []).filter((x) => x.source !== 'aave-ethereum-address-book'), ...records].map((x) => [`${x.chainId}:${x.address.toLowerCase()}`, x])).values()];
      sourceStatus['aave-ethereum-address-book'] = { status: 'ok', syncedAt: new Date().toISOString(), records: records.length };
    } catch (error) { failures.push(`aave-ethereum-address-book: ${error.message}`); sourceStatus['aave-ethereum-address-book'] = { status: 'error', syncedAt: new Date().toISOString(), error: error.message }; }
  }
  current.version = 1; current.sources = sourceStatus; current.syncedAt = new Date().toISOString();
  await writeJsonAtomic(cachePath, current);
  return { registry: await loadRegistry({ cachePath }), failures, cachePath };
}

export function enrichFindings(findings, registry) {
  const tokenMap = new Map(registry.tokens.map((x) => [`${x.chainId}:${x.address.toLowerCase()}`, x]));
  const contractMap = new Map((registry.contracts ?? []).map((x) => [`${x.chainId}:${x.address.toLowerCase()}`, x]));
  const protocolMap = new Map(registry.protocols.filter((x) => x.address).map((x) => [`1:${x.address.toLowerCase()}`, x]));
  const blacklist = new Set((registry.riskPolicy?.blacklistAddresses ?? []).map((x) => x.toLowerCase()));
  const knownAddresses = new Set((registry.riskPolicy?.knownAddresses ?? []).map((x) => x.toLowerCase()));
  for (const item of [...registry.tokens, ...(registry.contracts ?? []), ...registry.protocols]) if (ADDRESS.test(String(item.address ?? ''))) knownAddresses.add(item.address.toLowerCase());
  return findings.map((f) => {
    const involvedAddresses = addressesIn([f.address, f.parameters, f.transaction?.to, f.transaction?.from]).map((address) => {
      const key = `1:${address.toLowerCase()}`;
      const token = tokenMap.get(key);
      const contract = contractMap.get(key);
      const protocol = contract ? registry.protocols.find((x) => x.id === contract.protocolId) : protocolMap.get(key);
      const isBlacklisted = blacklist.has(address.toLowerCase());
      const known = knownAddresses.has(address.toLowerCase()) || Boolean(token || contract || protocol);
      return { address, known, blacklisted: isBlacklisted, kind: token ? 'token' : contract || protocol ? 'protocol' : 'unmapped', name: token?.name ?? contract?.name ?? protocol?.name ?? null, symbol: token?.symbol ?? null, logo: token?.logoURI ?? protocol?.logo ?? null, risk: isBlacklisted ? 'high' : known ? 'low' : 'low-mid' };
    });
    const staticSource = f.source === 'runtime' ? 'runtime' : 'static';
    const riskFlags = [...(f.riskFlags ?? [])];
    const actionName = String(f.functionName ?? '').toLowerCase();
    const threshold = registry.riskPolicy?.highSlippageBps ?? 500;
    const functionKnown = (registry.riskPolicy?.trustedFunctions ?? []).includes(actionName);
    if (/swap|exactinput|exactoutput/.test(actionName)) {
      const slippageValues = (value, key = '') => {
        if (Array.isArray(value)) return value.flatMap((item) => slippageValues(item, key));
        if (value && typeof value === 'object') return Object.entries(value).flatMap(([childKey, item]) => slippageValues(item, childKey));
        if (!/slippage|tolerance/i.test(key)) return [];
        const numeric = Number(value);
        return Number.isFinite(numeric) ? [numeric] : [];
      };
      const values = slippageValues(f.parameters);
      if (values.some((value) => value > threshold || (value > 0 && value < 1 && value * 10_000 > threshold))) riskFlags.push({ kind: 'high-slippage', severity: 'mid', detail: `Configured slippage exceeds ${threshold} bps.` });
    }
    if (!f.address) return { ...f, source: staticSource, functionKnown, riskFlags, involvedAddresses };
    const token = tokenMap.get(`1:${f.address.toLowerCase()}`);
    const contract = contractMap.get(`1:${f.address.toLowerCase()}`);
    const protocol = contract ? registry.protocols.find((x) => x.id === contract.protocolId) : protocolMap.get(`1:${f.address.toLowerCase()}`);
    const registryMatch = contract ? {
      type: 'protocol contract', id: protocol?.id ?? contract.protocolId, protocolId: contract.protocolId, name: protocol?.name ?? contract.name, category: protocol?.category ?? contract.role,
      logo: protocol?.logo, contractName: contract.name, role: contract.role,
    } : token ? { type: 'token', name: token.name, symbol: token.symbol, logo: token.logoURI } : protocol ? {
      type: 'protocol contract', name: protocol.name, category: protocol.category, logo: protocol.logo, contractName: protocol.name,
    } : null;
    return { ...f, source: staticSource, functionKnown, registryMatch, riskFlags, involvedAddresses };
  });
}

export function searchRegistry(registry, query) {
  const q = query.toLowerCase();
  return {
    tokens: registry.tokens.filter((x) => [x.name, x.symbol, x.address].some((v) => String(v ?? '').toLowerCase().includes(q))),
    protocols: registry.protocols.filter((x) => [x.name, x.id, x.category, x.address].some((v) => String(v ?? '').toLowerCase().includes(q))),
    contracts: (registry.contracts ?? []).filter((x) => [x.name, x.address, x.role, x.protocolId].some((v) => String(v ?? '').toLowerCase().includes(q))),
    volumeTrackers: (registry.volumeTrackers ?? []).filter((x) => [x.name, x.kind].some((v) => String(v ?? '').toLowerCase().includes(q))),
  };
}
