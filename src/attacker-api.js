import { ATTACKER_DOCUMENT, ATTACKER_LIST } from './attacker-list.js';

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

// Public, read-only data. Open to any origin, and cached so that serving it stays free.
const COMMON_HEADERS = {
  'access-control-allow-origin': '*',
  'cache-control': 'public, max-age=300, s-maxage=3600',
  'x-content-type-options': 'nosniff',
};

function listHeaders(list) {
  return { ...COMMON_HEADERS, etag: `"${list.hash}"`, 'x-keybound-list-hash': list.hash, 'x-keybound-list-version': list.version };
}

/**
 * GET /api/v1/attackers           the full list, as the same JSON the guard loads
 * GET /api/v1/attackers?view=meta version, hash and count, to check for changes cheaply
 * GET /api/v1/attackers?view=addresses  a plain array of addresses
 */
export function attackerListResponse(request, { document = ATTACKER_DOCUMENT, list = ATTACKER_LIST } = {}) {
  const url = new URL(request.url);
  const view = url.searchParams.get('view') ?? 'full';
  const headers = listHeaders(list);
  if (!['full', 'meta', 'addresses'].includes(view)) return Response.json({ error: 'view must be full, meta or addresses.' }, { status: 400, headers: COMMON_HEADERS });
  if (request.headers.get('if-none-match') === headers.etag && view !== 'meta') return new Response(null, { status: 304, headers });
  if (view === 'meta') {
    return Response.json({
      listVersion: list.version,
      hash: list.hash,
      count: list.count,
      generatedAt: document.generatedAt ?? null,
      sources: document.sources ?? [],
      license: 'Each source keeps its own license, shown under sources.',
    }, { headers });
  }
  if (view === 'addresses') {
    return Response.json({ listVersion: list.version, hash: list.hash, count: list.count, addresses: Object.keys(document.entries) }, { headers });
  }
  return Response.json(document, { headers });
}

/** GET /api/v1/attackers/0x... says whether one address is listed, and why. */
export function attackerLookupResponse(address, { list = ATTACKER_LIST } = {}) {
  if (!ADDRESS.test(String(address))) return Response.json({ error: 'Expected a 20-byte 0x address.' }, { status: 400, headers: COMMON_HEADERS });
  const match = list.find(address);
  return Response.json({
    address: String(address).toLowerCase(),
    listed: Boolean(match),
    label: match?.label ?? null,
    sources: match?.sources ?? [],
    reference: match?.reference ?? null,
    listVersion: list.version,
    listHash: list.hash,
  }, { headers: listHeaders(list) });
}
