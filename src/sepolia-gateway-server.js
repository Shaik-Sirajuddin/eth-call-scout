import crypto from 'node:crypto';
import http from 'node:http';

const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_BODY_BYTES = 32_768;

function digest(value) { return crypto.createHash('sha256').update(value).digest(); }

function json(response, status, payload, extraHeaders = {}) {
  const body = `${JSON.stringify(payload)}\n`;
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'",
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  response.end(body);
}

function bearerToken(request) {
  const match = /^Bearer ([^\s]+)$/.exec(request.headers.authorization ?? '');
  return match?.[1] ?? null;
}

function authorized(request, token) {
  const candidate = bearerToken(request);
  return candidate ? crypto.timingSafeEqual(digest(candidate), digest(token)) : false;
}

async function readJson(request) {
  const declared = Number(request.headers['content-length'] ?? 0);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw Object.assign(new Error('Request body exceeds 32 KB.'), { status: 413 });
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw Object.assign(new Error('Request body exceeds 32 KB.'), { status: 413 });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('Request body must be valid JSON.'), { status: 400 }); }
}

function createLimiter({ maximum, windowMs, minimumIntervalMs = 0 }) {
  const events = [];
  let last = 0;
  return function take(now = Date.now()) {
    while (events.length && events[0] <= now - windowMs) events.shift();
    if (events.length >= maximum || now - last < minimumIntervalMs) return false;
    events.push(now); last = now; return true;
  };
}

export function createSepoliaGatewayHandler({ gateway, serviceToken, operatorMinimumIntervalMs = 15_000 }) {
  const takeAgent = createLimiter({ maximum: 120, windowMs: 60 * 60 * 1000 });
  const takeOperator = createLimiter({ maximum: 30, windowMs: 60 * 60 * 1000, minimumIntervalMs: operatorMinimumIntervalMs });
  return async function handle(request, response) {
    try {
      const url = new URL(request.url, 'http://gateway.internal');
      if (request.method === 'GET' && url.pathname === '/live') return json(response, 200, { alive: true });
      if (!authorized(request, serviceToken)) return json(response, 401, { error: 'A valid Gateway service credential is required.' }, { 'www-authenticate': 'Bearer realm="WalletCordon Gateway"' });
      if (request.method === 'GET' && url.pathname === '/health') return json(response, 200, gateway.describe());
      if (request.method === 'GET' && url.pathname === '/v1/agent/capabilities') return json(response, 200, await gateway.capabilities());
      if (request.method === 'GET' && url.pathname === '/v1/agent/runs') return json(response, 200, { runs: gateway.listRuns().filter((run) => run.source === 'agent-api') });
      if (request.method === 'POST' && url.pathname === '/v1/agent/runs') {
        if (!takeAgent()) return json(response, 429, { error: 'Agent run rate limit reached. Retry later.' }, { 'retry-after': '60' });
        const body = await readJson(request);
        const existing = body.requestId ? gateway.findByRequestId(body.requestId) : null;
        return json(response, existing ? 200 : 202, gateway.createAgentRun(body));
      }
      const agentMatch = /^\/v1\/agent\/runs\/([^/]+)$/.exec(url.pathname);
      if (request.method === 'GET' && agentMatch && RUN_ID.test(agentMatch[1])) {
        const run = gateway.getRun(agentMatch[1]);
        return run?.source === 'agent-api' ? json(response, 200, run) : json(response, 404, { error: 'Agent run not found.' });
      }
      if (request.method === 'GET' && url.pathname === '/v1/operator/runs') return json(response, 200, { runs: gateway.listRuns() });
      if (request.method === 'POST' && url.pathname === '/v1/operator/runs') {
        if (!takeOperator()) return json(response, 429, { error: 'Demo rate limit reached. Wait before starting another transaction.' }, { 'retry-after': String(Math.ceil(operatorMinimumIntervalMs / 1000)) });
        const body = await readJson(request);
        return json(response, 202, gateway.createRun(body.prompt, { scenario: body.scenario, source: 'operator' }));
      }
      if (request.method === 'POST' && url.pathname === '/v1/operator/runs/demo') {
        if (!takeOperator()) return json(response, 429, { error: 'Demo rate limit reached. Wait before starting another transaction.' }, { 'retry-after': String(Math.ceil(operatorMinimumIntervalMs / 1000)) });
        return json(response, 202, gateway.createTwoTransactionDemo());
      }
      const operatorMatch = /^\/v1\/operator\/runs\/([^/]+)$/.exec(url.pathname);
      if (request.method === 'GET' && operatorMatch && RUN_ID.test(operatorMatch[1])) {
        const run = gateway.getRun(operatorMatch[1]);
        return run ? json(response, 200, run) : json(response, 404, { error: 'Run not found.' });
      }
      return json(response, 404, { error: 'Endpoint not found.' });
    } catch (error) {
      const status = Number.isInteger(error.status) ? error.status : 400;
      return json(response, status, { error: error.message });
    }
  };
}

export function listenSepoliaGateway({ gateway, serviceToken, port = Number(process.env.PORT ?? 8787), host = '0.0.0.0' }) {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error('Gateway PORT must be between 1 and 65535.');
  const handler = createSepoliaGatewayHandler({ gateway, serviceToken, operatorMinimumIntervalMs: Number(process.env.WALLETCORDON_OPERATOR_MIN_INTERVAL_MS ?? 15_000) });
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { server.off('error', reject); resolve(server); });
  });
}
