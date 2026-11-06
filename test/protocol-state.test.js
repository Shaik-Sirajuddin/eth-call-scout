import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { authorizeIntent, auditPolicy, validatePolicy } from '../src/policy.js';
import { addProtocolStateSignature, createFileSequenceStore, createLiveStateSource, evaluateProtocolState, signProtocolState, validateProtocolState } from '../src/protocol-state.js';
import { createGuardedProvider, WalletGuardError } from '../src/wallet-guard.js';

const basePolicy = JSON.parse(fs.readFileSync(new URL('../examples/wallet-policy.json', import.meta.url), 'utf8'));
const intent = JSON.parse(fs.readFileSync(new URL('../examples/transaction-intent.json', import.meta.url), 'utf8'));
const NOW = new Date('2026-12-01T00:02:00.000Z');

function keyPair(id) {
  const pair = crypto.generateKeyPairSync('ed25519');
  return {
    id,
    privateKey: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }),
    trusted: { id, algorithm: 'ed25519', publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') },
  };
}

const signerA = keyPair('operations-a');
const signerB = keyPair('security-b');

function policyWithState() {
  const policy = structuredClone(basePolicy);
  policy.protocolState = {
    required: true,
    maxAgeSeconds: 300,
    maxClockSkewSeconds: 15,
    minimumSequence: 1,
    threshold: 2,
    trustedKeys: [signerA.trusted, signerB.trusted],
  };
  return policy;
}

function payload({ sequence = 7, status = 'operational', contracts = [intent.to], issuedAt = '2026-12-01T00:00:00.000Z', observedAt = '2026-12-01T00:01:00.000Z', expiresAt = '2026-12-01T00:05:00.000Z' } = {}) {
  return {
    version: 1,
    sequence,
    issuedAt,
    expiresAt,
    protocols: [{
      id: 'usdc',
      chainId: 1,
      status,
      observedAt,
      contracts,
      blockNumber: '23800000',
      evidence: ['onchain-code-hash', 'incident-response-feed'],
    }],
  };
}

function bundle(statePayload = payload(), signers = [signerA, signerB]) {
  let state = { version: 1, payload: statePayload, signatures: [] };
  for (const signer of signers) state = addProtocolStateSignature(state, signProtocolState(statePayload, { keyId: signer.id, privateKey: signer.privateKey }));
  return state;
}

test('accepts a valid threshold-signed, fresh, operational state bound to the target', () => {
  const policy = policyWithState();
  assert.equal(validatePolicy(policy).valid, true);
  const state = bundle();
  assert.equal(validateProtocolState(state).valid, true);
  const result = evaluateProtocolState(state, policy.protocolState, { protocolId: 'usdc', chainId: 1, address: intent.to, now: NOW });
  assert.equal(result.valid, true);
  assert.equal(result.authenticated, true);
  assert.deepEqual(result.summary.verifiedSigners.sort(), ['operations-a', 'security-b']);
});

test('live state is an independent veto in the authorization receipt', () => {
  const policy = policyWithState();
  const receipt = authorizeIntent(policy, intent, { protocolState: bundle(), now: NOW });
  assert.equal(receipt.decision, 'simulate');
  assert.equal(receipt.protocolState.status, 'operational');
  assert.ok(receipt.checks.some((check) => check.id === 'state:signature-threshold' && check.status === 'pass'));
  assert.equal(auditPolicy(policy).findings.length, 0);
});

test('denies missing quorum and payload tampering', () => {
  const policy = policyWithState();
  let receipt = authorizeIntent(policy, intent, { protocolState: bundle(payload(), [signerA]), now: NOW });
  assert.equal(receipt.decision, 'deny');
  assert.equal(receipt.checks.find((check) => check.id === 'state:signature-threshold').status, 'deny');

  const tampered = bundle();
  tampered.payload.protocols[0].status = 'operational';
  tampered.payload.sequence = 8;
  receipt = authorizeIntent(policy, intent, { protocolState: tampered, now: NOW });
  assert.equal(receipt.decision, 'deny');
  assert.equal(receipt.checks.find((check) => check.id === 'state:signature-threshold').status, 'deny');
});

test('denies compromised, stale, expired, and incorrectly bound state', () => {
  const policy = policyWithState();
  const cases = [
    [bundle(payload({ status: 'compromised' })), 'state:operational'],
    [bundle(payload({ issuedAt: '2026-11-30T23:00:00.000Z', observedAt: '2026-11-30T23:00:00.000Z' })), 'state:fresh'],
    [bundle(payload({ expiresAt: '2026-12-01T00:01:30.000Z' })), 'state:not-expired'],
    [bundle(payload({ contracts: ['0x2222222222222222222222222222222222222222'] })), 'state:contract-bound'],
  ];
  for (const [state, failedCheck] of cases) {
    const receipt = authorizeIntent(policy, intent, { protocolState: state, now: NOW });
    assert.equal(receipt.decision, 'deny');
    assert.equal(receipt.checks.find((check) => check.id === failedCheck).status, 'deny');
  }
});

test('guard remembers an authenticated unsafe sequence and blocks rollback', async () => {
  const policy = policyWithState();
  const states = [bundle(payload({ sequence: 10, status: 'compromised' })), bundle(payload({ sequence: 9 }))];
  const receipts = [];
  const provider = {
    async request(request) {
      if (request.method === 'eth_chainId') return '0x1';
      throw new Error('A denied transaction must not be forwarded.');
    },
  };
  const guard = createGuardedProvider({
    provider,
    policy,
    now: NOW,
    stateSource: async () => states.shift(),
    onDecision: (receipt) => receipts.push(receipt),
  });
  await assert.rejects(guard.request({ method: 'eth_sendTransaction', params: [intent] }), WalletGuardError);
  await assert.rejects(guard.request({ method: 'eth_sendTransaction', params: [intent] }), WalletGuardError);
  assert.equal(receipts[0].checks.find((check) => check.id === 'state:operational').status, 'deny');
  assert.equal(receipts[1].checks.find((check) => check.id === 'state:no-rollback').status, 'deny');
});

test('persistent sequence store refuses rollback', async () => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'keybound-sequence-'));
  try {
    const store = createFileSequenceStore(path.join(directory, 'state.json'));
    assert.equal(await store.read(), 0);
    await store.write(12);
    assert.equal(await store.read(), 12);
    await assert.rejects(store.write(11), /Refusing to roll sequence back/);
  } finally {
    await fsp.rm(directory, { recursive: true });
  }
});

test('HTTPS live source caches untrusted bundles and falls back only to that cache', async () => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'keybound-cache-'));
  try {
    const state = bundle();
    let online = true;
    const source = createLiveStateSource({
      url: 'https://state.example/keybound.json',
      cachePath: path.join(directory, 'state.json'),
      fetchImpl: async () => {
        if (!online) throw new Error('offline');
        const bytes = Buffer.from(JSON.stringify(state));
        return { ok: true, headers: { get: () => String(bytes.length) }, arrayBuffer: async () => bytes };
      },
    });
    assert.deepEqual(await source(), state);
    online = false;
    assert.deepEqual(await source(), state);
    assert.throws(() => createLiveStateSource({ url: 'http://state.example/insecure.json' }), /HTTPS/);
  } finally {
    await fsp.rm(directory, { recursive: true });
  }
});

test('guard fails closed when rollback protection cannot be persisted', async () => {
  const policy = policyWithState();
  let forwarded = false;
  const provider = {
    async request(request) {
      if (request.method === 'eth_chainId') return '0x1';
      forwarded = true;
      return 'unexpected';
    },
  };
  const guard = createGuardedProvider({
    provider,
    policy,
    protocolState: bundle(),
    now: NOW,
    stateSequenceStore: { async read() { throw new Error('read-only filesystem'); }, async write() {} },
  });
  await assert.rejects(guard.request({ method: 'eth_sendTransaction', params: [intent] }), WalletGuardError);
  assert.equal(forwarded, false);
});

test('rejects unknown state fields and duplicate signer entries', () => {
  const state = bundle();
  state.payload.untrustedClaim = true;
  state.signatures.push(structuredClone(state.signatures[0]));
  const validation = validateProtocolState(state);
  assert.equal(validation.valid, false);
  assert.ok(validation.errors.some((error) => error.code === 'unknown-field'));
  assert.ok(validation.errors.some((error) => error.code === 'duplicate-signature'));
});
