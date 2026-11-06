import assert from 'node:assert/strict';
import test from 'node:test';
import { GET as getHealth } from '../app/api/health/route.js';
import { GET as getRuns } from '../app/api/runs/route.js';

async function withHostedEnvironment(run) {
  const previousVercel = process.env.VERCEL;
  const previousUrl = process.env.WALLETCORDON_GATEWAY_URL;
  const previousToken = process.env.WALLETCORDON_GATEWAY_TOKEN;
  process.env.VERCEL = '1';
  delete process.env.WALLETCORDON_GATEWAY_URL;
  delete process.env.WALLETCORDON_GATEWAY_TOKEN;
  try { return await run(); }
  finally {
    if (previousVercel == null) delete process.env.VERCEL; else process.env.VERCEL = previousVercel;
    if (previousUrl == null) delete process.env.WALLETCORDON_GATEWAY_URL; else process.env.WALLETCORDON_GATEWAY_URL = previousUrl;
    if (previousToken == null) delete process.env.WALLETCORDON_GATEWAY_TOKEN; else process.env.WALLETCORDON_GATEWAY_TOKEN = previousToken;
  }
}

test('hosted readiness stays explicitly Sepolia when the Gateway is unconfigured', async () => {
  await withHostedEnvironment(async () => {
    const response = await getHealth();
    const payload = await response.json();
    assert.equal(response.status, 503);
    assert.equal(payload.ready, false);
    assert.equal(payload.mode, 'sepolia-beta');
    assert.equal(payload.chainId, 11_155_111);
    assert.equal(payload.history, 'durable-remote');
    assert.equal(payload.eip7702, 'denied-by-policy');
    assert.match(payload.error, /WALLETCORDON_GATEWAY_URL is required/);
  });
});

test('hosted run history failures remain JSON instead of framework error pages', async () => {
  await withHostedEnvironment(async () => {
    const response = await getRuns();
    const payload = await response.json();
    assert.equal(response.status, 503);
    assert.match(response.headers.get('content-type'), /application\/json/);
    assert.match(payload.error, /WALLETCORDON_GATEWAY_URL is required/);
  });
});
