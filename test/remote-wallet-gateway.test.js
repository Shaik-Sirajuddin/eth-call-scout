import test from 'node:test';
import assert from 'node:assert/strict';
import { RemoteWalletGateway } from '../src/remote-wallet-gateway.js';

const TOKEN = 'service-secret-with-at-least-32-characters';

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } });
}

test('hosted remote gateway requires HTTPS and a strong service token', () => {
  assert.throws(() => new RemoteWalletGateway({ baseUrl: 'http://gateway.example', token: TOKEN, hosted: true }), /must use HTTPS/);
  assert.throws(() => new RemoteWalletGateway({ baseUrl: 'https://gateway.example', token: 'short', hosted: true }), /at least 32/);
});

test('remote gateway authenticates upstream requests and pins Sepolia posture', async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), options });
    return jsonResponse({ ready: true, chainId: 11_155_111, eip7702: 'denied-by-policy', history: 'durable-remote' });
  };
  const gateway = new RemoteWalletGateway({ baseUrl: 'https://gateway.example/internal', token: TOKEN, hosted: true, fetchImpl });
  const descriptor = await gateway.start();
  assert.equal(descriptor.mode, 'sepolia-beta');
  assert.equal(calls[0].url, 'https://gateway.example/internal/health');
  assert.equal(calls[0].options.headers.authorization, `Bearer ${TOKEN}`);
  assert.equal(calls[0].options.cache, 'no-store');
});

test('remote gateway rejects the wrong chain or permissive EIP-7702 posture', async () => {
  const wrongChain = new RemoteWalletGateway({
    baseUrl: 'https://gateway.example', token: TOKEN, hosted: true,
    fetchImpl: async () => jsonResponse({ ready: true, chainId: 1, eip7702: 'denied-by-policy' }),
  });
  await assert.rejects(wrongChain.start(), /did not attest to Sepolia/);

  const permissive = new RemoteWalletGateway({
    baseUrl: 'https://gateway.example', token: TOKEN, hosted: true,
    fetchImpl: async () => jsonResponse({ ready: true, chainId: 11_155_111, eip7702: 'allowed' }),
  });
  await assert.rejects(permissive.start(), /EIP-7702 deny posture/);
});

test('remote gateway keeps a narrow API and validates run ids', async () => {
  const gateway = new RemoteWalletGateway({
    baseUrl: 'http://127.0.0.1:8787', token: TOKEN,
    fetchImpl: async (url) => String(url).endsWith('/v1/operator/runs')
      ? jsonResponse({ runs: [] })
      : jsonResponse({ id: 'run_12345678' }),
  });
  assert.deepEqual(await gateway.listRuns(), []);
  await assert.rejects(gateway.getRun('../health'), /Invalid run id/);
});
