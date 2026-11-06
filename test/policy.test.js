import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { auditPolicy, authorizeIntent, canonicalJson, sha256, validatePolicy } from '../src/policy.js';

const fixture = JSON.parse(fs.readFileSync(new URL('../examples/wallet-policy.json', import.meta.url), 'utf8'));
const intent = JSON.parse(fs.readFileSync(new URL('../examples/transaction-intent.json', import.meta.url), 'utf8'));
const NOW = new Date('2026-12-01T00:00:00.000Z');

function clone(value) { return structuredClone(value); }

test('validates the strict example policy', () => {
  assert.deepEqual(validatePolicy(fixture), { valid: true, errors: [] });
});

test('rejects allow-by-default and malformed allowlists', () => {
  const policy = clone(fixture);
  policy.defaultAction = 'allow';
  policy.contracts[0].address = '*';
  const result = validatePolicy(policy);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.code === 'unsafe-default'));
  assert.ok(result.errors.some((error) => error.code === 'invalid-address'));
});

test('rejects policy fields that the engine does not understand', () => {
  const policy = clone(fixture);
  policy.invariants.allowEverythingAfterMidnight = true;
  const result = validatePolicy(policy);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.code === 'unknown-field'));
});

test('canonical policy hashes do not depend on object key order', () => {
  assert.equal(canonicalJson({ b: 2, a: { d: 4, c: 3 } }), '{"a":{"c":3,"d":4},"b":2}');
  assert.equal(sha256({ b: 2, a: 1 }), sha256({ a: 1, b: 2 }));
});

test('allows an exact transaction that satisfies every invariant', () => {
  const receipt = authorizeIntent(fixture, intent, { now: NOW });
  assert.equal(receipt.decision, 'allow');
  assert.match(receipt.policy.hash, /^[0-9a-f]{64}$/);
  assert.match(receipt.intent.hash, /^[0-9a-f]{64}$/);
  assert.ok(receipt.checks.length >= 9);
  assert.ok(receipt.checks.every((check) => check.status === 'pass'));
});

test('denies an unknown target and selector', () => {
  const unknownTarget = clone(intent);
  unknownTarget.to = '0x2222222222222222222222222222222222222222';
  let receipt = authorizeIntent(fixture, unknownTarget, { now: NOW });
  assert.equal(receipt.decision, 'deny');
  assert.equal(receipt.checks.find((check) => check.id === 'target:allowlisted').status, 'deny');

  const unknownSelector = clone(intent);
  unknownSelector.data = `0xdeadbeef${unknownSelector.data.slice(10)}`;
  receipt = authorizeIntent(fixture, unknownSelector, { now: NOW });
  assert.equal(receipt.decision, 'deny');
  assert.equal(receipt.checks.find((check) => check.id === 'method:allowlisted').status, 'deny');
});

test('denies unsupported transaction fields instead of omitting them from the receipt hash', () => {
  const eip7702 = clone(intent);
  eip7702.authorizationList = [{ chainId: '0x1', address: intent.to }];
  const receipt = authorizeIntent(fixture, eip7702, { now: NOW });
  assert.equal(receipt.decision, 'deny');
  assert.ok(receipt.checks.some((check) => check.id === 'intent:unknown-field'));
});

test('enforces ABI address and uint constraints directly from calldata', () => {
  const wrongSpender = clone(intent);
  wrongSpender.data = `${wrongSpender.data.slice(0, 34)}2222222222222222222222222222222222222222${wrongSpender.data.slice(74)}`;
  let receipt = authorizeIntent(fixture, wrongSpender, { now: NOW });
  assert.equal(receipt.decision, 'deny');
  assert.ok(receipt.checks.some((check) => check.id.includes('address-in') && check.status === 'deny'));

  const tooMuch = clone(intent);
  tooMuch.data = `${tooMuch.data.slice(0, 74)}${(1_000_000_001n).toString(16).padStart(64, '0')}`;
  receipt = authorizeIntent(fixture, tooMuch, { now: NOW });
  assert.equal(receipt.decision, 'deny');
  assert.ok(receipt.checks.some((check) => check.id.includes('uint-max') && check.status === 'deny'));
});

test('hard-blocks unlimited ERC-20 approvals', () => {
  const unlimited = clone(intent);
  unlimited.data = `${unlimited.data.slice(0, 74)}${'f'.repeat(64)}`;
  const receipt = authorizeIntent(fixture, unlimited, { now: NOW });
  assert.equal(receipt.decision, 'deny');
  assert.equal(receipt.checks.find((check) => check.id === 'erc20:no-unlimited-approval').status, 'deny');
});

test('denies expired policies and missing mandatory fee fields', () => {
  let receipt = authorizeIntent(fixture, intent, { now: new Date('2030-02-01T00:00:00.000Z') });
  assert.equal(receipt.decision, 'deny');
  assert.equal(receipt.checks.find((check) => check.id === 'policy:not-expired').status, 'deny');

  const noGas = clone(intent);
  delete noGas.gas;
  receipt = authorizeIntent(fixture, noGas, { now: NOW });
  assert.equal(receipt.decision, 'deny');
  assert.equal(receipt.checks.find((check) => check.id === 'gas:limit').status, 'deny');
});

test('policy audit identifies broad but structurally valid permissions', () => {
  const broad = clone(fixture);
  delete broad.wallets;
  delete broad.validUntil;
  broad.contracts[0].methods[0].constraints = [];
  const audit = auditPolicy(broad);
  assert.equal(audit.valid, true);
  assert.ok(audit.findings.some((finding) => finding.code === 'unbound-wallet'));
  assert.ok(audit.findings.some((finding) => finding.code === 'unbounded-approval-spender'));
});
