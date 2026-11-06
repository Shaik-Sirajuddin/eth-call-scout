import fs from 'node:fs/promises';
import path from 'node:path';
import { Interface } from 'ethers';

const DEFAULT_CACHE = path.resolve('.cache/eth-call-scout/abi');
const SOURCIFY = 'https://sourcify.dev/server/v2/contract';
const SIGNATURES = 'https://api.4byte.sourcify.dev/signature-database/v1/lookup';
const ETHERSCAN = 'https://api.etherscan.io/v2/api';

async function getEtherscanKey() {
  if (process.env.ETHERSCAN_API_KEY) return process.env.ETHERSCAN_API_KEY;
  try {
    const envText = await fs.readFile(path.resolve('.env'), 'utf8');
    for (const line of envText.split(/\r?\n/)) {
      const match = line.match(/^\s*(?:export\s+)?ETHERSCAN_API_KEY\s*=\s*(.*?)\s*$/);
      if (match) return match[1].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* .env is optional */ }
  return null;
}

async function getCached(file) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
async function putCached(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(temp, JSON.stringify(value));
  await fs.rename(temp, file);
}
function normalize(value) {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, normalize(v)]));
  return value;
}
function isAbi(value) { return Array.isArray(value) && value.some((x) => x && (x.type === 'function' || x.type === 'fallback' || x.type === 'receive')); }
function decodeWithAbi(abi, calldata) {
  try {
    const tx = new Interface(abi).parseTransaction({ data: calldata });
    if (!tx) return null;
    return { functionName: tx.name, signature: tx.signature, parameters: normalize(Array.from(tx.args)), source: 'verified ABI' };
  } catch { return null; }
}
async function fetchJson(url, fetchImpl) {
  const response = await fetchImpl(url, { headers: { accept: 'application/json', 'user-agent': 'eth-call-scout/0.1 (+https://github.com/)' }, signal: AbortSignal.timeout(20_000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

export async function decodeCall(finding, { chainId = 1, cacheDir = DEFAULT_CACHE, fetchImpl = fetch, etherscanApiKey } = {}) {
  const data = finding.calldata ?? (typeof finding.parameters === 'string' && /^0x[0-9a-fA-F]{8}/.test(finding.parameters) ? finding.parameters : null);
  if (!finding.address || !data || !/^0x[0-9a-fA-F]{8}/.test(data)) return finding;
  const key = `${chainId}-${finding.address.toLowerCase()}`;
  const abiPath = path.join(cacheDir, `${key}.abi.json`);
  const cache = await getCached(abiPath);
  const cacheFresh = cache && Date.now() - Date.parse(cache.fetchedAt) < 30 * 24 * 60 * 60 * 1000;
  let abi = cacheFresh && isAbi(cache.abi) ? cache.abi : null;
  let abiSource = cacheFresh ? cache.source : null;
  let lookupNotes = [];

  const apiKey = etherscanApiKey ?? await getEtherscanKey();
  if (!abi && apiKey) {
    try {
      const url = new URL(ETHERSCAN);
      url.searchParams.set('chainid', String(chainId)); url.searchParams.set('module', 'contract');
      url.searchParams.set('action', 'getabi'); url.searchParams.set('address', finding.address); url.searchParams.set('apikey', apiKey);
      const result = await fetchJson(url, fetchImpl);
      if (result.status === '1' && typeof result.result === 'string') {
        const parsed = JSON.parse(result.result);
        if (isAbi(parsed) && decodeWithAbi(parsed, data)) { abi = parsed; abiSource = 'Etherscan verified ABI'; }
        else if (isAbi(parsed)) {
          const sourceUrl = new URL(ETHERSCAN);
          for (const [k, v] of Object.entries({ chainid: String(chainId), module: 'contract', action: 'getsourcecode', address: finding.address, apikey: apiKey })) sourceUrl.searchParams.set(k, v);
          const sourceResult = await fetchJson(sourceUrl, fetchImpl);
          const implementation = sourceResult.result?.[0]?.Implementation;
          if (sourceResult.status === '1' && /^0x[a-fA-F0-9]{40}$/.test(String(implementation)) && implementation.toLowerCase() !== finding.address.toLowerCase()) {
            const implUrl = new URL(ETHERSCAN);
            for (const [k, v] of Object.entries({ chainid: String(chainId), module: 'contract', action: 'getabi', address: implementation, apikey: apiKey })) implUrl.searchParams.set(k, v);
            const implResult = await fetchJson(implUrl, fetchImpl);
            if (implResult.status === '1' && typeof implResult.result === 'string') {
              const implAbi = JSON.parse(implResult.result);
              if (isAbi(implAbi) && decodeWithAbi(implAbi, data)) { abi = implAbi; abiSource = 'Etherscan verified proxy implementation ABI'; }
            }
          } else { abi = parsed; abiSource = 'Etherscan verified ABI'; }
        }
      } else if (result.message && !/not verified|no data/i.test(`${result.message} ${result.result}`)) lookupNotes.push(`Etherscan ABI lookup: ${result.message}`);
    } catch (error) { lookupNotes.push(`Etherscan ABI lookup: ${error.message}`); }
  }
  if (!abi) {
    try {
      const result = await fetchJson(`${SOURCIFY}/${chainId}/${finding.address}?fields=abi`, fetchImpl);
      if (isAbi(result.abi)) { abi = result.abi; abiSource = 'Sourcify verified ABI'; }
    } catch (error) { lookupNotes.push(`Sourcify ABI lookup: ${error.message}`); }
  }
  if (abi) {
    const decoded = decodeWithAbi(abi, data);
    if (decoded) {
      decoded.source = abiSource;
      if (!cacheFresh || cache.source !== abiSource) await putCached(abiPath, { abi, source: abiSource, fetchedAt: new Date().toISOString() });
      return { ...finding, functionName: decoded.functionName, parameters: decoded.parameters, calldata: data,
        decoded: { ...decoded, confidence: 'verified ABI' }, notes: [...(finding.notes ?? []).filter((note) => !/Raw calldata captured; function name and decoded arguments require the matching ABI\./.test(note)), ...lookupNotes] };
    }
  }

  const selector = data.slice(0, 10).toLowerCase();
  const sigPath = path.join(cacheDir, 'selectors', `${selector}.json`);
  let sigCache = await getCached(sigPath);
  let candidates = sigCache && Date.now() - Date.parse(sigCache.fetchedAt) < 30 * 24 * 60 * 60 * 1000 ? sigCache.signatures : null;
  if (!candidates) {
    try {
      const result = await fetchJson(`${SIGNATURES}?function=${encodeURIComponent(selector)}`, fetchImpl);
      candidates = result?.result?.function?.[selector]?.map((x) => x.name).filter((x) => typeof x === 'string') ?? [];
      await putCached(sigPath, { signatures: candidates, fetchedAt: new Date().toISOString() });
    } catch (error) { lookupNotes.push(`Selector lookup: ${error.message}`); candidates = []; }
  }
  const matches = [];
  for (const signature of candidates) {
    const decoded = decodeWithAbi([`function ${signature}`], data);
    if (decoded) matches.push({ ...decoded, source: 'Sourcify 4byte selector database' });
  }
  if (matches.length) {
    const unique = [...new Map(matches.map((x) => [x.signature, x])).values()];
    const decoded = unique[0];
    return { ...finding, functionName: decoded.functionName, parameters: decoded.parameters, calldata: data,
      decoded: { ...decoded, confidence: unique.length === 1 ? 'selector match' : 'ambiguous selector', candidates: unique.map((x) => x.signature) },
      notes: [...(finding.notes ?? []).filter((note) => !/Raw calldata captured; function name and decoded arguments require the matching ABI\./.test(note)), ...(unique.length > 1 ? [`Selector has ${unique.length} decodable candidate signatures; first candidate shown.`] : []), ...lookupNotes] };
  }
  return { ...finding, calldata: data, decoded: null, notes: [...(finding.notes ?? []), 'No verified ABI or matching selector signature was found.', ...lookupNotes] };
}

export async function decodeFindings(findings, options = {}) {
  const output = [];
  for (const finding of findings) {
    if (finding.calldata || (typeof finding.parameters === 'string' && /^0x[0-9a-fA-F]{8}/.test(finding.parameters))) {
      output.push(await decodeCall(finding, options));
    } else output.push(finding);
  }
  return output;
}
