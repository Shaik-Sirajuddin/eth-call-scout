import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createSepoliaGatewayHandler } from '../src/sepolia-gateway-server.js';

const TOKEN = 'gateway-service-token-with-at-least-32-characters';

function stubGateway() {
  const runs = [];
  return {
    describe: () => ({ ready: true, chainId: 11_155_111, eip7702: 'denied-by-policy' }),
    capabilities: async () => ({ chainId: 11_155_111, eip7702: 'denied-by-policy' }),
    listRuns: () => runs,
    findByRequestId: (requestId) => runs.find((run) => run.requestId === requestId),
    getRun: (id) => runs.find((run) => run.id === id) ?? null,
    createAgentRun: (body) => {
      const existing = runs.find((run) => run.requestId === body.requestId);
      if (existing) return existing;
      const run = { id: `run_agent_${runs.length + 1}`, source: 'agent-api', requestId: body.requestId, status: 'queued' };
      runs.push(run); return run;
    },
    createRun: () => { const run = { id: `run_operator_${runs.length + 1}`, source: 'operator', status: 'queued' }; runs.push(run); return run; },
    createTwoTransactionDemo: () => ({ id: 'demo_1', runs: [] }),
  };
}

function invoke(handler, { method = 'GET', path = '/', headers = {}, body = '' } = {}) {
  const request = Readable.from(body ? [Buffer.from(body)] : []);
  request.method = method;
  request.url = path;
  request.headers = { ...headers, ...(body ? { 'content-length': String(Buffer.byteLength(body)) } : {}) };
  return new Promise((resolve, reject) => {
    const response = {
      writeHead(status, responseHeaders) { this.status = status; this.headers = responseHeaders; },
      end(value) { resolve({ status: this.status, headers: this.headers, body: JSON.parse(String(value)) }); },
    };
    handler(request, response).catch(reject);
  });
}

async function withHandler(callback) {
  const gateway = stubGateway();
  const handler = createSepoliaGatewayHandler({ gateway, serviceToken: TOKEN, operatorMinimumIntervalMs: 1_000 });
  await callback({ handler, gateway });
}

test('Sepolia Gateway exposes only liveness without its service credential', async () => {
  await withHandler(async ({ handler }) => {
    assert.equal((await invoke(handler, { path: '/live' })).status, 200);
    const response = await invoke(handler, { path: '/health' });
    assert.equal(response.status, 401);
    assert.match(response.headers['www-authenticate'], /WalletCordon Gateway/);
  });
});

test('Sepolia Gateway authenticates and idempotently accepts exact agent runs', async () => {
  await withHandler(async ({ handler }) => {
    const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };
    const health = await invoke(handler, { path: '/health', headers });
    assert.equal(health.status, 200);
    assert.equal(health.body.chainId, 11_155_111);
    const body = JSON.stringify({ requestId: 'agent-order-0001', goal: 'test', proposal: {} });
    const first = await invoke(handler, { method: 'POST', path: '/v1/agent/runs', headers, body });
    assert.equal(first.status, 202);
    const second = await invoke(handler, { method: 'POST', path: '/v1/agent/runs', headers, body });
    assert.equal(second.status, 200);
    assert.equal(first.body.id, second.body.id);
  });
});

test('Sepolia Gateway rate-limits public demo mutations behind the Vercel proxy', async () => {
  await withHandler(async ({ handler }) => {
    const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };
    const first = await invoke(handler, { method: 'POST', path: '/v1/operator/runs', headers, body: JSON.stringify({ prompt: 'test', scenario: 'safe' }) });
    assert.equal(first.status, 202);
    const second = await invoke(handler, { method: 'POST', path: '/v1/operator/runs/demo', headers });
    assert.equal(second.status, 429);
  });
});
