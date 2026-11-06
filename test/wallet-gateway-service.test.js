import test from 'node:test';
import assert from 'node:assert/strict';
import { getWalletGateway } from '../src/wallet-gateway-service.js';

test('hosted UI fails closed instead of spawning a local Anvil wallet gateway', async () => {
  const previous = {
    vercel: process.env.VERCEL,
    url: process.env.WALLETCORDON_GATEWAY_URL,
    token: process.env.WALLETCORDON_GATEWAY_TOKEN,
  };
  process.env.VERCEL = '1';
  delete process.env.WALLETCORDON_GATEWAY_URL;
  delete process.env.WALLETCORDON_GATEWAY_TOKEN;
  try {
    await assert.rejects(
      getWalletGateway(),
      /WALLETCORDON_GATEWAY_URL is required/,
    );
  } finally {
    for (const [name, value] of Object.entries({
      VERCEL: previous.vercel,
      WALLETCORDON_GATEWAY_URL: previous.url,
      WALLETCORDON_GATEWAY_TOKEN: previous.token,
    })) {
      if (value == null) delete process.env[name];
      else process.env[name] = value;
    }
  }
});
