import test from 'node:test';
import assert from 'node:assert/strict';
import { getWalletGateway } from '../src/wallet-gateway-service.js';

test('hosted UI fails closed instead of spawning a local Anvil wallet gateway', async () => {
  const previous = process.env.VERCEL;
  process.env.VERCEL = '1';
  try {
    await assert.rejects(
      getWalletGateway(),
      /Live wallet execution is disabled on the hosted UI/,
    );
  } finally {
    if (previous == null) delete process.env.VERCEL;
    else process.env.VERCEL = previous;
  }
});
