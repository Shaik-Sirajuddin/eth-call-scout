import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createGuardedProvider, WalletGuardError } from '../src/wallet-guard.js';

const policy = JSON.parse(fs.readFileSync(new URL('../examples/wallet-policy.json', import.meta.url), 'utf8'));
const intent = JSON.parse(fs.readFileSync(new URL('../examples/transaction-intent.json', import.meta.url), 'utf8'));

function mockProvider() {
  const requests = [];
  return {
    requests,
    async request(request) {
      requests.push(structuredClone(request));
      if (request.method === 'eth_chainId') return '0x1';
      if (request.method === 'eth_sendTransaction') return '0xtransactionhash';
      return 'read-result';
    },
  };
}

test('passes read-only methods through unchanged', async () => {
  const provider = mockProvider();
  const guard = createGuardedProvider({ provider, policy });
  const request = { method: 'eth_getBalance', params: [intent.from, 'latest'] };
  assert.equal(await guard.request(request), 'read-result');
  assert.deepEqual(provider.requests, [request]);
});

test('authorizes then forwards the exact transaction', async () => {
  const provider = mockProvider();
  const decisions = [];
  const guard = createGuardedProvider({ provider, policy, now: new Date('2026-12-01T00:00:00.000Z'), onDecision: (receipt) => decisions.push(receipt) });
  const request = { method: 'eth_sendTransaction', params: [intent] };
  assert.equal(await guard.request(request), '0xtransactionhash');
  assert.deepEqual(provider.requests, [{ method: 'eth_chainId', params: [] }, request]);
  assert.equal(decisions[0].decision, 'allow');
});

test('never forwards a transaction denied by policy', async () => {
  const provider = mockProvider();
  const denied = structuredClone(intent);
  denied.to = '0x2222222222222222222222222222222222222222';
  const guard = createGuardedProvider({ provider, policy, now: new Date('2026-12-01T00:00:00.000Z') });
  await assert.rejects(
    guard.request({ method: 'eth_sendTransaction', params: [denied] }),
    (error) => error instanceof WalletGuardError && error.code === 4100 && error.receipt.decision === 'deny',
  );
  assert.deepEqual(provider.requests, [{ method: 'eth_chainId', params: [] }]);
});

test('blocks opaque signing and wallet mutation methods', async () => {
  const provider = mockProvider();
  const guard = createGuardedProvider({ provider, policy });
  for (const method of ['personal_sign', 'eth_signTypedData_v4', 'eth_sendRawTransaction', 'wallet_sendCalls', 'wallet_switchEthereumChain']) {
    await assert.rejects(guard.request({ method, params: [] }), WalletGuardError);
  }
  assert.deepEqual(provider.requests, []);
});

test('fails closed when active chain cannot be established', async () => {
  const provider = { async request() { throw new Error('offline'); } };
  const guard = createGuardedProvider({ provider, policy });
  await assert.rejects(guard.request({ method: 'eth_sendTransaction', params: [intent] }), WalletGuardError);
});
