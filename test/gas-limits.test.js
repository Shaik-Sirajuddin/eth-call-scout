import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { FunctionFragment, id, keccak256, toBeHex } from 'ethers';
import { firstBlockOfCurrentVersion, IMPLEMENTATION_SLOTS, readCodeVersion, samplesFromBlock } from '../src/code-version.js';
import { checkGasRuleVersions, createGasRules, GAS_RULES } from '../src/gas-limits.js';
import { auditPolicy, authorizeIntent, evaluateWalletCalls, resolveGasLimit, validatePolicy } from '../src/policy.js';
import { addProtocolStateSignature, signProtocolState } from '../src/protocol-state.js';
import { simulateTransaction } from '../src/transaction-simulator.js';
import { createGuardedProvider, WalletGuardError } from '../src/wallet-guard.js';

const example = JSON.parse(fs.readFileSync(new URL('../examples/wallet-policy.json', import.meta.url), 'utf8'));
const intent = JSON.parse(fs.readFileSync(new URL('../examples/transaction-intent.json', import.meta.url), 'utf8'));
const NOW = new Date('2026-12-01T00:00:00.000Z');
const USDC = intent.to;
const WALLET = intent.from;
const APPROVE = '0x095ea7b3';
const CODE = '0x6001600055';
const SLOT = id('org.zeppelinos.proxy.implementation');
const IMPLEMENTATION = `0x${'77'.repeat(20)}`;
const word = (address) => `0x${address.slice(2).padStart(64, '0')}`;
const hex = (n) => `0x${n.toString(16)}`;
const rpcUrls = { 'sim-primary': 'https://primary.example', 'sim-secondary': 'https://secondary.example' };

function measuredRules({ maxGas = '100000', validUntil = '2027-05-01T00:00:00.000Z', rulesVersion = '2026-11-06' } = {}) {
  return createGasRules({
    version: 1,
    rulesVersion,
    validUntil,
    rules: [{
      chainId: 1,
      address: USDC,
      protocolId: 'usdc',
      versionTag: 'usdc-erc20',
      selector: APPROVE,
      maxGas,
      codeVersion: { codeHash: keccak256(CODE), implementation: { kind: 'slot', slot: SLOT, address: IMPLEMENTATION } },
    }],
  });
}

/** A chain where the proposed call runs cleanly: no reverts, no bad targets, no asset problems. */
function fakeChain({ estimate = 60000, gasUsed = 60000, code = CODE, implementation = IMPLEMENTATION, frames = [] } = {}) {
  return async (_url, options) => {
    const request = JSON.parse(options.body);
    const results = {
      eth_chainId: () => '0x1',
      eth_blockNumber: () => '0x100',
      eth_getTransactionCount: () => intent.nonce,
      eth_getCode: () => (request.params[0].toLowerCase() === USDC.toLowerCase() ? code : '0x'),
      eth_getStorageAt: () => word(implementation),
      eth_call: () => '0x',
      eth_estimateGas: () => hex(estimate),
      debug_traceCall: () => {
        if (request.params[2].tracer === 'prestateTracer') return { pre: {}, post: {} };
        const tx = request.params[0];
        return { type: 'CALL', from: tx.from, to: tx.to, value: '0x0', input: tx.data, output: '0x', ...(gasUsed == null ? {} : { gasUsed: hex(gasUsed) }), calls: frames };
      },
    };
    const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: results[request.method]() }));
    return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
  };
}

const NORMAL_TX = { ...intent, gas: hex(100000) };
const WASTEFUL_TX = { ...intent, gas: hex(350000) };

function simulate(chain, { tx = WASTEFUL_TX, policy = structuredClone(example), rules = measuredRules(), now = NOW } = {}) {
  return simulateTransaction(policy, tx, { rpcUrls, fetchImpl: fakeChain(chain), now, gasRules: rules });
}
const failures = (result) => result.summary.sources.flatMap((source) => source.failures);

test('denies a valid call that wastes gas even though nothing else is wrong with it', async () => {
  const result = await simulate({ estimate: 300000, gasUsed: 300000 });
  assert.equal(result.valid, false);
  assert.ok(failures(result).every((failure) => /gas/i.test(failure)), `only gas should fail: ${failures(result).join(' | ')}`);
  assert.ok(failures(result).some((failure) => failure.includes('Estimated gas 300000') && failure.includes('usdc-erc20')));
});

test('allows the same function at a normal gas cost and records the rule that decided it', async () => {
  const result = await simulate({ estimate: 60000, gasUsed: 60000 }, { tx: NORMAL_TX });
  assert.equal(result.valid, true);
  const { gasLimit, gasLimitSource, gasRule, gasUsed } = result.summary.metrics;
  assert.equal(gasLimit, '100000');
  assert.equal(gasUsed, '60000');
  assert.match(gasLimitSource, /usdc-erc20, measured 2026-11-06/);
  assert.deepEqual(gasRule, { versionTag: 'usdc-erc20', measured: '2026-11-06', outdated: false });
});

test('checks the transaction gas limit itself, because that is what the chain enforces', async () => {
  const result = await simulate({ estimate: 60000, gasUsed: 60000 });
  assert.equal(result.valid, false);
  assert.ok(failures(result).some((failure) => failure.includes('Transaction gas 350000')));
});

test('checks traced gas as well as the estimate', async () => {
  const result = await simulate({ estimate: 60000, gasUsed: 90000 }, { tx: NORMAL_TX, rules: measuredRules({ maxGas: '70000' }) });
  assert.ok(failures(result).some((failure) => failure.includes('Traced gas 90000')));
});

test('an outdated rule does not deny: changed contract code falls back to the overall cap', async () => {
  const result = await simulate({ estimate: 300000, gasUsed: 300000, code: '0x6002600055' });
  assert.equal(result.valid, true, failures(result).join(' | '));
  const { gasLimit, gasLimitSource, gasRule } = result.summary.metrics;
  assert.equal(gasLimit, example.invariants.maxGas);
  assert.match(gasLimitSource, /overall gas cap; gas rule usdc-erc20 not used because the contract code changed/);
  assert.equal(gasRule.outdated, true);
});

test('an outdated rule does not deny: a proxy upgrade falls back to the overall cap', async () => {
  const result = await simulate({ estimate: 300000, gasUsed: 300000, implementation: `0x${'88'.repeat(20)}` });
  assert.equal(result.valid, true, failures(result).join(' | '));
  assert.match(result.summary.metrics.gasLimitSource, /the contract was upgraded/);
});

test('an expired rule set does not deny and says why', async () => {
  const result = await simulate({ estimate: 300000, gasUsed: 300000 }, { rules: measuredRules({ validUntil: '2026-11-30T00:00:00.000Z' }) });
  assert.equal(result.valid, true, failures(result).join(' | '));
  assert.match(result.summary.metrics.gasLimitSource, /the rule set expired/);
});

test('an outdated rule still has a ceiling: the overall cap and the contract limit keep applying', async () => {
  const overCap = await simulate({ estimate: 340000, gasUsed: 340000, code: '0x6002600055' }, { tx: { ...intent, gas: hex(360000) } });
  assert.ok(failures(overCap).some((failure) => failure.includes('Transaction gas 360000')));

  const policy = structuredClone(example);
  policy.contracts[0].maxGas = '150000';
  const overContract = await simulate({ estimate: 300000, gasUsed: 300000, code: '0x6002600055' }, { policy });
  assert.equal(overContract.valid, false);
  assert.ok(failures(overContract).some((failure) => failure.includes('limit of 150000 (policy contract limit; gas rule usdc-erc20 not used')));
});

test('a failed version read fails closed', async () => {
  const fetchImpl = async (url, options) => {
    if (JSON.parse(options.body).method === 'eth_getStorageAt') throw new Error('offline');
    return fakeChain()(url, options);
  };
  const result = await simulateTransaction(example, NORMAL_TX, { rpcUrls, fetchImpl, now: NOW, gasRules: measuredRules() });
  assert.equal(result.valid, false);
});

test('a policy method limit wins over the measured rule at both stages', async () => {
  const policy = structuredClone(example);
  policy.contracts[0].methods[0].maxGas = '70000';
  const simulated = await simulate({ estimate: 80000, gasUsed: 80000 }, { tx: NORMAL_TX, policy });
  assert.ok(failures(simulated).some((failure) => failure.includes('limit of 70000 (policy method limit)')));

  const receipt = authorizeIntent(policy, NORMAL_TX, { now: NOW });
  assert.equal(receipt.checks.find((check) => check.id === 'gas:function-limit').status, 'deny');
});

test('a batch cannot hide a wasteful call: each wallet call has its own limit', async () => {
  const rules = measuredRules();
  const statuses = await checkGasRuleVersions(rules, [rules.find(1, USDC, APPROVE)], (method) => fakeRpc(method), { now: NOW });
  const call = (gasUsed) => ({ type: 'CALL', to: USDC.toLowerCase(), value: '0', input: `${APPROVE}${'00'.repeat(64)}`, gasUsed: hex(gasUsed) });
  const check = (gasUsed) => evaluateWalletCalls(example, 1, [call(gasUsed)], { now: NOW, gasRules: rules, gasRuleStatuses: statuses }).filter((failure) => failure.includes('gas:function-limit'));
  assert.equal(check(60000).length, 0);
  assert.equal(check(300000).length, 1);
});

function fakeRpc(method) {
  return method === 'eth_getCode' ? CODE : word(IMPLEMENTATION);
}

test('gas fields must be exact hex in the gas field, so a wallet cannot read a bigger limit', () => {
  const denied = (tx, code) => {
    const receipt = authorizeIntent(example, tx, { now: NOW });
    assert.equal(receipt.decision, 'deny');
    assert.ok(receipt.checks.some((check) => check.id === `intent:${code}`), JSON.stringify(receipt.checks.map((check) => check.id)));
  };
  const { gas: _gas, ...withoutGas } = NORMAL_TX;
  denied({ ...withoutGas, gasLimit: hex(100000) }, 'gas-field-required');
  denied({ ...NORMAL_TX, gas: '100000' }, 'invalid-gas-quantity');
  denied({ ...NORMAL_TX, gas: 100000 }, 'invalid-gas-quantity');
  denied({ ...NORMAL_TX, maxFeePerGas: '99999999999' }, 'invalid-gas-quantity');
  denied({ ...NORMAL_TX, maxPriorityFeePerGas: '1000000000' }, 'invalid-gas-quantity');

  const missing = authorizeIntent(example, withoutGas, { now: NOW });
  assert.equal(missing.checks.find((check) => check.id === 'gas:function-limit').status, 'deny');
});

test('an upgrade transaction gets room for the authorization cost', () => {
  const policy = structuredClone(example);
  policy.contracts[0].methods[0].maxGas = '100000';
  const base = { chainId: 1, to: USDC.toLowerCase(), data: `${APPROVE}${'00'.repeat(64)}` };
  assert.equal(resolveGasLimit(policy, base).limit, 100000n);
  assert.equal(resolveGasLimit(policy, { ...base, authorizationList: [{}] }).limit, 125000n);
});

test('activation requires a gas limit for every allowed call', () => {
  const unknown = { selector: id('doThing()').slice(0, 10), name: 'doThing()' };
  const policy = structuredClone(example);
  policy.contracts[0].methods.push(unknown);
  assert.ok(validatePolicy(policy).errors.some((error) => error.code === 'activation-uncapped-function-gas'));

  policy.contracts[0].methods[1].maxGas = '90000';
  assert.deepEqual(validatePolicy(policy), { valid: true, errors: [] });

  const contractLimit = structuredClone(example);
  contractLimit.contracts[0].methods.push(unknown);
  contractLimit.contracts[0].maxGas = '90000';
  assert.deepEqual(validatePolicy(contractLimit), { valid: true, errors: [] });

  const native = structuredClone(example);
  native.contracts.push({ chainId: 1, address: WALLET, protocolId: 'usdc', allowEmptyCalldata: true });
  assert.ok(validatePolicy(native).errors.some((error) => error.code === 'activation-uncapped-empty-calldata-gas'));

  const tooLow = structuredClone(example);
  tooLow.contracts[0].methods[0].maxGas = '20999';
  assert.ok(validatePolicy(tooLow).errors.some((error) => error.code === 'invalid-gas-limit'));
});

test('audit flags calls with no gas limit and limits set above the measured rule', () => {
  const uncapped = structuredClone(example);
  uncapped.contracts[0].methods.push({ selector: id('doThing()').slice(0, 10) });
  const finding = auditPolicy(uncapped).findings.find((entry) => entry.code === 'uncapped-function-gas');
  assert.equal(finding.severity, 'high');

  const rule = GAS_RULES.find(1, USDC, APPROVE);
  const generous = structuredClone(example);
  generous.contracts[0].methods[0].maxGas = (BigInt(rule.maxGas) + 1n).toString();
  assert.equal(auditPolicy(generous).findings.find((entry) => entry.code === 'function-gas-above-rule').severity, 'medium');
  assert.ok(!auditPolicy(example).findings.some((entry) => entry.code === 'function-gas-above-rule'));
});

test('the shipped rule set is well formed and labelled with version tags', () => {
  const document = JSON.parse(fs.readFileSync(new URL('../data/gas-limits.json', import.meta.url), 'utf8'));
  assert.ok(document.rules.length > 0);
  for (const rule of document.rules) {
    assert.match(rule.versionTag, /^[a-z0-9.-]+$/);
    assert.match(rule.codeVersion.codeHash, /^0x[0-9a-f]{64}$/);
    assert.ok(BigInt(rule.maxGas) >= BigInt(rule.observed.p99), `${rule.contract} ${rule.selector} limit is below its measured p99`);
    if (rule.signature) assert.equal(id(FunctionFragment.from(`function ${rule.signature}`).format('sighash')).slice(0, 10), rule.selector);
  }
  assert.equal(GAS_RULES.find(1, USDC, APPROVE).versionTag, 'usdc-erc20');
  assert.equal(GAS_RULES.find(1, '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2', id('supply(address,uint256,address,uint16)').slice(0, 10)).versionTag, 'aave-v3');
});

test('a damaged rule set refuses to load instead of removing limits', () => {
  const rule = { chainId: 1, address: USDC, versionTag: 'usdc-erc20', selector: APPROVE, maxGas: '100000', codeVersion: { codeHash: keccak256(CODE), implementation: null } };
  const document = { version: 1, rulesVersion: '2026-11-06', validUntil: '2027-05-01T00:00:00.000Z', rules: [rule] };
  assert.doesNotThrow(() => createGasRules(document));
  assert.throws(() => createGasRules({ ...document, rules: [{ ...rule, versionTag: '' }] }), /Invalid gas rule/);
  assert.throws(() => createGasRules({ ...document, rules: [{ ...rule, codeVersion: null }] }), /Invalid gas rule/);
  assert.throws(() => createGasRules({ ...document, rules: [{ ...rule, maxGas: '0' }] }), /Invalid gas rule/);
  assert.throws(() => createGasRules({ ...document, validUntil: undefined }), /Invalid gas rule set/);
});

test('the guard never forwards the wasteful call, and still forwards the normal one', async () => {
  const keys = [crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519')];
  const policy = structuredClone(example);
  policy.protocolState = {
    required: true,
    maxAgeSeconds: 300,
    threshold: 2,
    trustedKeys: keys.map((pair, index) => ({ id: `gas-${index}`, algorithm: 'ed25519', publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') })),
  };
  const payload = { version: 1, sequence: 1, issuedAt: NOW.toISOString(), expiresAt: '2026-12-01T00:05:00.000Z', protocols: [{ id: 'usdc', chainId: 1, status: 'operational', observedAt: NOW.toISOString(), contracts: [USDC] }] };
  let protocolState = { version: 1, payload, signatures: [] };
  keys.forEach((pair, index) => { protocolState = addProtocolStateSignature(protocolState, signProtocolState(payload, { keyId: `gas-${index}`, privateKey: pair.privateKey })); });

  const sent = [];
  const provider = { async request(request) { if (request.method === 'eth_chainId') return '0x1'; sent.push(request.method); return '0xhash'; } };
  const guard = (chain) => createGuardedProvider({ provider, policy, protocolState, now: NOW, gasRules: measuredRules(), simulationOptions: { rpcUrls, fetchImpl: fakeChain(chain) } });

  await assert.rejects(
    guard({ estimate: 300000, gasUsed: 300000 }).request({ method: 'eth_sendTransaction', params: [WASTEFUL_TX] }),
    (error) => error instanceof WalletGuardError && error.receipt.simulation.sources.some((source) => source.failures.some((failure) => failure.includes('usdc-erc20'))),
  );
  assert.deepEqual(sent, []);

  assert.equal(await guard({ estimate: 60000, gasUsed: 60000 }).request({ method: 'eth_sendTransaction', params: [NORMAL_TX] }), '0xhash');
  assert.deepEqual(sent, ['eth_sendTransaction']);
});

test('proxy slots equal the values their standards define', () => {
  assert.ok(IMPLEMENTATION_SLOTS.includes(id('org.zeppelinos.proxy.implementation')));
  assert.ok(IMPLEMENTATION_SLOTS.includes(toBeHex(BigInt(id('eip1967.proxy.implementation')) - 1n, 32)));
});

test('a USDC-style proxy is recognised, so its upgrades make rules outdated', async () => {
  const rpc = async (method, params) => {
    if (method === 'eth_getCode') return CODE;
    if (method === 'eth_getStorageAt') return params[1] === SLOT ? word(IMPLEMENTATION) : `0x${'00'.repeat(32)}`;
    return '0x';
  };
  assert.deepEqual((await readCodeVersion(rpc, USDC)).implementation, { kind: 'slot', slot: SLOT, address: IMPLEMENTATION });

  const shipped = GAS_RULES.find(1, USDC, APPROVE).codeVersion.implementation;
  assert.equal(shipped?.slot, SLOT, 'the shipped USDC rules must pin its implementation');
  assert.match(shipped.address, /^0x[0-9a-f]{40}$/);
});

test('a wallet call with no reported gas fails closed', async () => {
  const rules = measuredRules();
  const statuses = await checkGasRuleVersions(rules, [rules.find(1, USDC, APPROVE)], (method) => fakeRpc(method), { now: NOW });
  const input = `${APPROVE}${'00'.repeat(64)}`;
  const gasFailures = (call) => evaluateWalletCalls(example, 1, [call], { now: NOW, gasRules: rules, gasRuleStatuses: statuses }).filter((failure) => failure.includes('gas:function-limit'));
  const base = { type: 'CALL', to: USDC.toLowerCase(), value: '0', input };
  assert.equal(gasFailures(base).length, 1, 'a missing gasUsed must not skip the check');
  assert.match(gasFailures(base)[0], /reports no gas/);
  assert.equal(gasFailures({ ...base, gasUsed: hex(300000) }).length, 1);
  assert.equal(gasFailures({ ...base, gasUsed: hex(60000) }).length, 0);

  const frame = { type: 'CALL', from: WALLET, to: USDC, value: '0x0', input, output: '0x' };
  const result = await simulate({ frames: [frame] }, { tx: NORMAL_TX });
  assert.equal(result.valid, false);
  assert.ok(result.summary.sources.every((source) => source.status === 'error' && source.failures.some((failure) => failure.includes('a wallet call has no gasUsed'))));
});

test('a trace whose root reports no gas is malformed', async () => {
  const result = await simulate({ gasUsed: null }, { tx: NORMAL_TX });
  assert.equal(result.valid, false);
  assert.ok(result.summary.sources.every((source) => source.status === 'error' && source.failures.some((failure) => failure.includes('the root call has no gasUsed'))));
});

test('the receipt names the rule set that really made the decision', async () => {
  const keys = [crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519')];
  const policy = structuredClone(example);
  policy.protocolState = { required: true, maxAgeSeconds: 300, threshold: 2, trustedKeys: keys.map((pair, index) => ({ id: `r-${index}`, algorithm: 'ed25519', publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') })) };
  const payload = { version: 1, sequence: 1, issuedAt: NOW.toISOString(), expiresAt: '2026-12-01T00:05:00.000Z', protocols: [{ id: 'usdc', chainId: 1, status: 'operational', observedAt: NOW.toISOString(), contracts: [USDC] }] };
  let protocolState = { version: 1, payload, signatures: [] };
  keys.forEach((pair, index) => { protocolState = addProtocolStateSignature(protocolState, signProtocolState(payload, { keyId: `r-${index}`, privateKey: pair.privateKey })); });
  const provider = { async request(request) { return request.method === 'eth_chainId' ? '0x1' : '0xhash'; } };
  const rules = measuredRules();
  assert.notEqual(rules.hash, GAS_RULES.hash);

  const receipts = [];
  const guard = createGuardedProvider({ provider, policy, protocolState, now: NOW, gasRules: rules, onDecision: (receipt) => receipts.push(receipt), simulationOptions: { rpcUrls, fetchImpl: fakeChain() } });
  await guard.request({ method: 'eth_sendTransaction', params: [NORMAL_TX] });
  assert.equal(receipts[0].decision, 'allow');
  assert.equal(receipts[0].gasRules.hash, rules.hash);
  assert.equal(receipts[0].simulation.gasRules.hash, rules.hash);
  assert.equal(receipts[0].checks.find((check) => check.id === 'gas:rules-match').status, 'pass');

  // A simulator that used any other set cannot produce an allow.
  const otherRules = async () => ({ valid: true, checks: [], summary: { gasRules: { version: 'other', hash: 'not-the-same' } } });
  const mismatched = createGuardedProvider({ provider, policy, protocolState, now: NOW, gasRules: rules, simulator: otherRules });
  await assert.rejects(mismatched.request({ method: 'eth_sendTransaction', params: [NORMAL_TX] }), (error) => error instanceof WalletGuardError && error.receipt.checks.find((check) => check.id === 'gas:rules-match').status === 'deny');
});

test('one rule set is chosen at construction and cannot be swapped or forged', () => {
  const provider = { async request() { return '0x1'; } };
  assert.throws(() => createGuardedProvider({ provider, policy: example, simulationOptions: { gasRules: measuredRules() } }), /Pass gasRules to createGuardedProvider/);
  const forged = { version: 'x', validUntil: '2030-01-01T00:00:00.000Z', hash: GAS_RULES.hash, find: () => null };
  assert.throws(() => createGuardedProvider({ provider, policy: example, gasRules: forged }), /created by createGasRules/);
  assert.throws(() => authorizeIntent(example, NORMAL_TX, { now: NOW, gasRules: forged }), /created by createGasRules/);
});

test('a forged rule set is refused by the simulator too', async () => {
  const forged = { version: 'x', validUntil: '2030-01-01T00:00:00.000Z', hash: GAS_RULES.hash, find: () => null };
  await assert.rejects(simulate({}, { tx: NORMAL_TX, rules: forged }), /created by createGasRules/);
});

test('the decision fingerprint changes with the rule set', async () => {
  const first = await simulate({}, { tx: NORMAL_TX, rules: measuredRules({ rulesVersion: 'a' }) });
  const second = await simulate({}, { tx: NORMAL_TX, rules: measuredRules({ rulesVersion: 'b' }) });
  assert.ok(first.summary.fingerprint && second.summary.fingerprint);
  assert.notEqual(first.summary.fingerprint, second.summary.fingerprint);
});

test('samples from before an upgrade inside the window are not attributed to the current version', async () => {
  const OLD = `0x${'99'.repeat(20)}`;
  const pin = { codeHash: keccak256(CODE), implementation: { kind: 'slot', slot: SLOT, address: IMPLEMENTATION } };
  const chainUpgradedAt = (upgradeBlock) => async (method, params) => (method === 'eth_getCode' ? CODE : word(Number(BigInt(params[2])) >= upgradeBlock ? IMPLEMENTATION : OLD));

  const from = await firstBlockOfCurrentVersion(chainUpgradedAt(1234), USDC, pin, 1000, 2000);
  assert.equal(from, 1234);
  const kept = samplesFromBlock([{ gas: 900000, block: 1100 }, { gas: 60000, block: 1234 }, { gas: 61000, block: 1900 }], from);
  assert.deepEqual(kept.map((sample) => sample.gas), [60000, 61000]);

  assert.equal(await firstBlockOfCurrentVersion(chainUpgradedAt(0), USDC, pin, 1000, 2000), 1000, 'no upgrade keeps the whole window');
  assert.equal(await firstBlockOfCurrentVersion(chainUpgradedAt(2000), USDC, pin, 1000, 2000), 2000, 'an upgrade at the last block keeps only that block');
  await assert.rejects(firstBlockOfCurrentVersion(chainUpgradedAt(3000), USDC, pin, 1000, 2000), /newest block does not match/);
});

test('proxies read through implementation() are searched the same way, and other contracts need no search', async () => {
  const OLD = `0x${'99'.repeat(20)}`;
  const pin = { codeHash: keccak256(CODE), implementation: { kind: 'call', address: IMPLEMENTATION } };
  const rpc = async (method, params) => (method === 'eth_getCode' ? CODE : word(Number(BigInt(params[1])) >= 1500 ? IMPLEMENTATION : OLD));
  assert.equal(await firstBlockOfCurrentVersion(rpc, USDC, pin, 1000, 2000), 1500);

  const noCalls = async () => { throw new Error('a plain contract needs no history'); };
  assert.equal(await firstBlockOfCurrentVersion(noCalls, USDC, { codeHash: keccak256(CODE), implementation: null }, 1000, 2000), 1000);
});

test('a node that cannot read history leaves the rules out instead of guessing', async () => {
  const pin = { codeHash: keccak256(CODE), implementation: { kind: 'slot', slot: SLOT, address: IMPLEMENTATION } };
  const rpc = async (method) => { if (method === 'eth_getCode') throw new Error('Archive requests require a personal token'); return '0x'; };
  await assert.rejects(firstBlockOfCurrentVersion(rpc, USDC, pin, 1000, 2000), /Archive requests/);
});
