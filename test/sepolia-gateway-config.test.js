import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { exportEd25519PrivateKey, exportEd25519PublicKey, loadSepoliaGatewayEnvironment } from '../src/sepolia-gateway-config.js';

test('Sepolia state signer exports round-trip as pinned Ed25519 keys', () => {
  const pair = crypto.generateKeyPairSync('ed25519');
  const restored = crypto.createPrivateKey({ key: Buffer.from(exportEd25519PrivateKey(pair.privateKey), 'base64'), format: 'der', type: 'pkcs8' });
  assert.equal(exportEd25519PublicKey(restored), exportEd25519PublicKey(pair.privateKey));
});

test('isolated Sepolia signer Gateway refuses to run inside Vercel', async () => {
  const previous = process.env.VERCEL;
  process.env.VERCEL = '1';
  try { await assert.rejects(loadSepoliaGatewayEnvironment(), /must not run inside Vercel/); }
  finally {
    if (previous == null) delete process.env.VERCEL;
    else process.env.VERCEL = previous;
  }
});
