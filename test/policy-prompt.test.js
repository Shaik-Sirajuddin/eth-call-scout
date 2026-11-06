import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { validatePolicy } from '../src/policy.js';
import { compilePolicyPrompt, parseDecimalUnits } from '../src/policy-prompt.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const registry = JSON.parse(fs.readFileSync(path.join(root, 'data', 'registry.static.json'), 'utf8'));
const seedPolicy = JSON.parse(fs.readFileSync(path.join(root, 'examples', 'wallet-policy.json'), 'utf8'));
const header = 'Create "Treasury approvals" for wallet 0x1111111111111111111111111111111111111111 on Ethereum.\nExpire on 2030-01-01.';

test('prompt compiler resolves an approval into exact registry addresses and base units', () => {
  const result = compilePolicyPrompt(`${header}
Allow USDC approvals to Uniswap up to 1,000.25 USDC.
Max native value 0 ETH.
Max gas 350000.
Max fee 100 gwei.
Max priority fee 5 gwei.
Require 2 of 2 live state signers.
Require 2 of 2 simulation sources.
Deny EIP-7702.`, { registry, seedPolicy });

  assert.equal(result.valid, true, JSON.stringify(result.errors));
  assert.equal(validatePolicy(result.policy, { activation: true }).valid, true);
  assert.equal(result.policy.contracts[0].address, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');
  assert.equal(result.policy.contracts[0].methods[0].selector, '0x095ea7b3');
  assert.equal(result.policy.contracts[0].methods[0].constraints[1].value, '1000250000');
  assert.deepEqual(result.policy.simulation.assetLimits[0].allowedSpenders, ['0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45']);
  assert.equal(result.policy.simulation.eip7702.allowAuthorizationList, false);
  assert.equal(result.policy.simulation.eip7702.allowDelegatedWallet, false);
});

test('prompt compiler rejects broad access and attempts to bypass security gates', () => {
  const result = compilePolicyPrompt(`${header}
Allow any contract with unlimited approvals.
Disable simulation and live state.`, { registry, seedPolicy });

  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.code === 'unsafe-broad-rule'));
  assert.ok(result.errors.some((error) => error.code === 'security-bypass-request'));
  assert.equal(result.policy.contracts.length, 0);
});

test('unsupported and unknown registry requirements are never silently dropped', () => {
  const result = compilePolicyPrompt(`${header}
Allow MOON approvals to MysterySwap up to 5 MOON.
Send me an email when it happens.`, { registry, seedPolicy });

  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.code === 'unknown-token'));
  assert.ok(result.errors.some((error) => error.code === 'unsupported-clause' && /email/i.test(error.clause)));
});

test('EIP-7702 opt-in requires an exact policy-chain delegate and runtime code hash', () => {
  const delegate = '0x2222222222222222222222222222222222222222';
  const codeHash = `0x${'ab'.repeat(32)}`;
  const result = compilePolicyPrompt(`${header}
Allow USDC approvals to Uniswap up to 50 USDC.
Allow EIP-7702 authorization lists for delegate ${delegate} on Ethereum with code hash ${codeHash}.
Allow already-delegated EOA for delegate ${delegate} on Ethereum with code hash ${codeHash}.`, { registry, seedPolicy });

  assert.equal(result.valid, true, JSON.stringify(result.errors));
  assert.equal(result.policy.simulation.eip7702.allowAuthorizationList, true);
  assert.equal(result.policy.simulation.eip7702.allowDelegatedWallet, true);
  assert.deepEqual(result.policy.simulation.eip7702.delegates, [{ chainId: 1, address: delegate, codeHash }]);

  const unsafe = compilePolicyPrompt(`${header}
Allow USDC approvals to Uniswap up to 50 USDC.
Allow EIP-7702.`, { registry, seedPolicy });
  assert.equal(unsafe.valid, false);
  assert.ok(unsafe.errors.some((error) => error.code === 'unpinned-eip7702-opt-in'));
});

test('decimal conversion is lossless and never uses floating point', () => {
  assert.equal(parseDecimalUnits('1,000.000001', 6), '1000000001');
  assert.throws(() => parseDecimalUnits('0.0000001', 6), /more than 6 decimal places/);
});
