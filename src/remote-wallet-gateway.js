const SEPOLIA_CHAIN_ID = 11_155_111;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function cleanError(payload, fallback) {
  const message = typeof payload?.error === 'string' ? payload.error.trim() : '';
  return message && message.length <= 500 ? message : fallback;
}

function assertGatewayUrl(value, { hosted = false } = {}) {
  if (!value) throw new Error('WALLETCORDON_GATEWAY_URL is required for the hosted testnet beta.');
  let url;
  try { url = new URL(value); }
  catch { throw new Error('WALLETCORDON_GATEWAY_URL must be an absolute URL.'); }
  if (url.username || url.password || url.search || url.hash) throw new Error('Gateway URL must not contain credentials, query parameters, or a fragment.');
  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(url.hostname);
  if (url.protocol !== 'https:' && (hosted || !loopback)) throw new Error('The remote WalletCordon Gateway must use HTTPS.');
  url.pathname = url.pathname.replace(/\/+$/, '');
  return url;
}

function assertServiceToken(value) {
  if (typeof value !== 'string' || value.length < 32) {
    throw new Error('WALLETCORDON_GATEWAY_TOKEN must be a secret with at least 32 characters.');
  }
  return value;
}

function assertRunId(id) {
  if (!RUN_ID.test(String(id ?? ''))) throw new Error('Invalid run id.');
  return encodeURIComponent(id);
}

export class RemoteWalletGateway {
  constructor({ baseUrl, token, fetchImpl = globalThis.fetch, hosted = false, timeoutMs = 15_000 } = {}) {
    this.baseUrl = assertGatewayUrl(baseUrl, { hosted });
    this.token = assertServiceToken(token);
    if (typeof fetchImpl !== 'function') throw new Error('Remote Gateway requires fetch.');
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.started = false;
    this.descriptor = { ready: false, mode: 'sepolia-beta', chainId: SEPOLIA_CHAIN_ID };
  }

  async request(path, { method = 'GET', body } = {}) {
    const response = await this.fetchImpl(new URL(`${this.baseUrl.pathname}${path}`, this.baseUrl), {
      method,
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${this.token}`,
        ...(body == null ? {} : { 'content-type': 'application/json' }),
      },
      body: body == null ? undefined : JSON.stringify(body),
      cache: 'no-store',
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) throw new Error('Remote Gateway response exceeded 4 MB.');
    let payload;
    try { payload = text ? JSON.parse(text) : {}; }
    catch { throw new Error('Remote Gateway returned invalid JSON.'); }
    if (!response.ok) throw new Error(cleanError(payload, `Remote Gateway returned HTTP ${response.status}.`));
    return payload;
  }

  assertSepolia(payload, label) {
    if (Number(payload?.chainId) !== SEPOLIA_CHAIN_ID) throw new Error(`${label} did not attest to Sepolia chain 11155111.`);
    if (payload?.eip7702 !== 'denied-by-policy') throw new Error(`${label} did not attest to the required EIP-7702 deny posture.`);
    return payload;
  }

  async start() {
    const descriptor = this.assertSepolia(await this.request('/health'), 'Remote Gateway');
    if (descriptor.ready !== true) throw new Error('Remote Gateway is not ready.');
    this.descriptor = { ...descriptor, mode: 'sepolia-beta', history: descriptor.history ?? 'durable-remote' };
    this.started = true;
    return this.describe();
  }

  describe() {
    return structuredClone(this.descriptor);
  }

  async capabilities() {
    return this.assertSepolia(await this.request('/v1/agent/capabilities'), 'Remote Gateway capabilities');
  }

  async listRuns() {
    const payload = await this.request('/v1/operator/runs');
    if (!Array.isArray(payload?.runs)) throw new Error('Remote Gateway returned an invalid run list.');
    return payload.runs;
  }

  async getRun(id) {
    return this.request(`/v1/operator/runs/${assertRunId(id)}`);
  }

  async createRun(prompt, { scenario } = {}) {
    return this.request('/v1/operator/runs', { method: 'POST', body: { prompt, scenario } });
  }

  async createTwoTransactionDemo() {
    return this.request('/v1/operator/runs/demo', { method: 'POST' });
  }

  async createAgentRun({ requestId, goal, proposal }) {
    return this.request('/v1/agent/runs', { method: 'POST', body: { requestId, goal, proposal } });
  }
}

export function remoteGatewayFromEnvironment({ fetchImpl } = {}) {
  return new RemoteWalletGateway({
    baseUrl: process.env.WALLETCORDON_GATEWAY_URL,
    token: process.env.WALLETCORDON_GATEWAY_TOKEN,
    hosted: Boolean(process.env.VERCEL),
    fetchImpl,
  });
}

export const TESTNET_CHAIN_ID = SEPOLIA_CHAIN_ID;
