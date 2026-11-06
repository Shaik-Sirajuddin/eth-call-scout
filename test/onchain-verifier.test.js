import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { id } from 'ethers';
import { ALERT_CODES } from '../src/alerts.js';
import { ATTACKER_LIST } from '../src/attacker-list.js';
import { createBlockSpendTracker } from '../src/block-spend.js';
import { createOnChainVerifier, envelopeDifferences, flattenCallTrace } from '../src/onchain-verifier.js';
import { createPolicyFromRuleSet } from '../src/rule-sets.js';

const EXPLOITER = '0x489A8756C18C0b8B24EC2a2b9FF3D4d447F79BEc';
const ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const WALLET = '0x1111111111111111111111111111111111111111';
const OTHER = '0x2222222222222222222222222222222222222222';
const TRANSFER = id('Transfer(address,address,uint256)');
const KEY_A = `0x${'aa'.repeat(32)}`;
const KEY_B = `0x${'bb'.repeat(32)}`;
const R = `0x${'cc'.repeat(32)}`;
const S = `0x${'dd'.repeat(32)}`;
const topic = (address) => `0x${address.slice(2).toLowerCase().padStart(64, '0')}`;
const amountData = (amount) => `0x${BigInt(amount).toString(16).padStart(64, '0')}`;

const intent1559 = { chainId: 1, from: WALLET, to: ROUTER.toLowerCase(), data: '0xabcd', value: '5', nonce: '7', gas: '180000', gasPrice: null, maxFeePerGas: '1000', maxPriorityFeePerGas: '10', type: '2', accessList: null, authorizationList: null };
const mined1559 = { hash: `0x${'b'.repeat(64)}`, chainId: '0x1', from: WALLET, to: ROUTER, input: '0xabcd', value: '0x5', nonce: '0x7', gas: '0x2bf20', gasPrice: '0x64', maxFeePerGas: '0x3e8', maxPriorityFeePerGas: '0xa', type: '0x2', accessList: [] };
const authorization = { chainId: '1', address: OTHER, nonce: '8', yParity: '1', r: R, s: S };
const minedAuthorization = { chainId: '0x1', address: OTHER, nonce: '0x8', yParity: '0x1', r: R, s: S };

test('a transaction matching in every signed field has no differences', () => {
  assert.deepEqual(envelopeDifferences(mined1559, intent1559), []);
});

test('each signed field that changes is reported', async (t) => {
  const cases = [
    ['chain ID', { chainId: '0x2' }, /chain ID/],
    ['sender', { from: OTHER }, /sender/],
    ['target', { to: OTHER }, /target/],
    ['calldata', { input: '0xabce' }, /calldata/],
    ['value', { value: '0x6' }, /value/],
    ['nonce', { nonce: '0x8' }, /nonce/],
    ['type', { type: '0x0' }, /type/],
    ['gas limit', { gas: '0xf423f' }, /gas limit/],
    ['max fee per gas', { maxFeePerGas: '0xfffff' }, /max fee per gas/],
    ['max priority fee', { maxPriorityFeePerGas: '0xffff' }, /max priority fee/],
    ['access list added', { accessList: [{ address: OTHER, storageKeys: [] }] }, /access list/],
    ['authorization list added', { authorizationList: [minedAuthorization] }, /authorization list/],
  ];
  for (const [name, change, expected] of cases) {
    await t.test(name, () => {
      const differences = envelopeDifferences({ ...mined1559, ...change }, intent1559);
      assert.equal(differences.length, 1, JSON.stringify(differences));
      assert.match(differences[0], expected);
    });
  }
});

test('a field the node leaves out does not count as a match', async (t) => {
  for (const field of ['chainId', 'value', 'nonce', 'type', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas']) {
    await t.test(field, () => {
      const { [field]: removed, ...rest } = mined1559;
      assert.equal(envelopeDifferences(rest, intent1559).length, 1, `${field} was ${removed}`);
    });
  }
  assert.deepEqual(envelopeDifferences(null, intent1559), ['the node returned no transaction']);
});

test('the price paid on an EIP-1559 transaction is not treated as a change', () => {
  assert.deepEqual(envelopeDifferences({ ...mined1559, gasPrice: '0x3e7' }, intent1559), []);
});

test('legacy gas price is compared, and an omitted type is still pinned by the fee model', () => {
  const legacyIntent = { ...intent1559, type: null, gasPrice: '500', maxFeePerGas: null, maxPriorityFeePerGas: null };
  const legacyMined = { ...mined1559, type: '0x0', gasPrice: '0x1f4', maxFeePerGas: undefined, maxPriorityFeePerGas: undefined, accessList: undefined };
  assert.deepEqual(envelopeDifferences(legacyMined, legacyIntent), []);
  assert.match(envelopeDifferences({ ...legacyMined, gasPrice: '0x1f5' }, legacyIntent)[0], /gas price/);
  assert.match(envelopeDifferences({ ...legacyMined, type: '0x2' }, legacyIntent)[0], /type/);
  const untyped = { ...intent1559, type: null };
  assert.deepEqual(envelopeDifferences(mined1559, untyped), []);
  assert.match(envelopeDifferences({ ...mined1559, type: '0x0' }, untyped)[0], /type/);
});

test('access lists compare by content, and a changed key or address is reported', () => {
  const entries = [{ address: USDC.toLowerCase(), storageKeys: [KEY_A, KEY_B] }, { address: OTHER, storageKeys: [] }];
  const withList = { ...intent1559, accessList: entries };
  const reordered = [{ address: OTHER, storageKeys: [] }, { address: USDC, storageKeys: [KEY_B.toUpperCase().replace('0X', '0x'), KEY_A] }];
  assert.deepEqual(envelopeDifferences({ ...mined1559, accessList: reordered }, withList), []);
  assert.match(envelopeDifferences({ ...mined1559, accessList: [{ address: USDC, storageKeys: [KEY_A] }, { address: OTHER, storageKeys: [] }] }, withList)[0], /access list/);
  assert.match(envelopeDifferences({ ...mined1559, accessList: [{ address: USDC, storageKeys: [KEY_A, KEY_B] }] }, withList)[0], /access list/);
  assert.match(envelopeDifferences({ ...mined1559, accessList: [] }, withList)[0], /access list/);
});

test('every authorization field is compared, in order', async (t) => {
  const withAuthorization = { ...intent1559, type: '4', authorizationList: [authorization] };
  const mined = { ...mined1559, type: '0x4', authorizationList: [minedAuthorization] };
  assert.deepEqual(envelopeDifferences(mined, withAuthorization), []);
  for (const [field, value] of [['chainId', '0x0'], ['address', USDC], ['nonce', '0x9'], ['yParity', '0x0'], ['r', S], ['s', R]]) {
    await t.test(field, () => {
      const differences = envelopeDifferences({ ...mined, authorizationList: [{ ...minedAuthorization, [field]: value }] }, withAuthorization);
      assert.match(differences[0], /authorization list/);
    });
  }
  assert.match(envelopeDifferences({ ...mined, authorizationList: [] }, withAuthorization)[0], /authorization list/);
  const two = { ...withAuthorization, authorizationList: [authorization, { ...authorization, address: USDC }] };
  assert.match(envelopeDifferences({ ...mined, authorizationList: [{ ...minedAuthorization, address: USDC }, minedAuthorization] }, two)[0], /authorization list/);
});

const policy = createPolicyFromRuleSet({ wallet: WALLET, trustedKeys: [crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519')].map((pair, index) => ({ id: `k${index}`, algorithm: 'ed25519', publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') })), validUntil: '2030-01-01T00:00:00.000Z' });

const cleanTrace = { type: 'CALL', from: WALLET, to: ROUTER, value: '0x5', input: '0xabcd', calls: [{ type: 'STATICCALL', from: ROUTER, to: USDC, input: '0x70a08231', value: '0x0' }] };

async function verify({ transaction = {}, trace = cleanTrace, logs = [], metrics = { gasLimit: '190000', outflows: {} }, traceRequest = null, status = '0x1' } = {}) {
  const entries = [];
  const decision = { policy: { name: 't', hash: 'h' }, intent: intent1559, simulation: { metrics } };
  const verifier = createOnChainVerifier({
    request: async (method) => {
      if (method === 'eth_getTransactionReceipt') return { status, blockNumber: '0x100', gasUsed: '0x1000', logs };
      if (method === 'eth_getTransactionByHash') return { ...mined1559, ...transaction };
      if (method === 'eth_getTransactionCount') return '0x8';
      if (method === 'debug_traceTransaction') return traceRequest ? traceRequest() : trace;
      throw new Error(method);
    },
    policy,
    attackerList: ATTACKER_LIST,
    alerts: { append: async (alert) => { entries.push(alert); return alert; } },
    tracker: createBlockSpendTracker(),
    timeoutMs: 50,
    pollMs: 1,
  });
  verifier.expectNonce('7');
  const result = await verifier.verify(mined1559.hash, decision);
  const check = (name) => result.checks.find((entry) => entry.id === name);
  return { result, alerts: entries, check };
}

test('changed gas and fees on the mined transaction fail verification and raise an alert', async () => {
  const { result, alerts, check } = await verify({ transaction: { gas: '0xf423f', maxFeePerGas: '0xfffff', maxPriorityFeePerGas: '0xffff' } });
  assert.equal(result.status, 'failed');
  assert.equal(check('onchain:transaction-match').status, 'fail');
  assert.match(check('onchain:transaction-match').detail, /gas limit.*max fee per gas.*max priority fee/);
  assert.equal(alerts[0].code, ALERT_CODES.ONCHAIN_MISMATCH);
});

test('a clean transaction verifies, and says how much was checked', async () => {
  const { result, alerts, check } = await verify();
  assert.equal(result.status, 'verified');
  assert.equal(alerts.length, 0);
  assert.equal(result.internalCallsChecked, 2);
  assert.match(check('onchain:attacker').detail, /2 call\(s\).*internal ETH transfers/);
});

test('internal ETH sent to an attacker is caught, even with no logs', async () => {
  const nested = { ...cleanTrace, calls: [{ type: 'CALL', from: ROUTER, to: OTHER, value: '0x0', input: '0x', calls: [{ type: 'CALL', from: OTHER, to: EXPLOITER, value: '0xde0b6b3a7640000', input: '0x' }] }] };
  const { result, alerts, check } = await verify({ trace: nested, logs: [] });
  assert.equal(result.status, 'failed');
  assert.equal(check('onchain:attacker').status, 'fail');
  assert.equal(alerts.find((alert) => alert.code === ALERT_CODES.ONCHAIN_ATTACKER).details.hits[0].address, EXPLOITER.toLowerCase());
});

test('with no trace, the result is incomplete and never claims internal transfers were checked', async (t) => {
  const failures = [
    ['node refuses', { traceRequest: () => { throw new Error('method not found'); } }],
    ['node returns nothing', { trace: null }],
    ['node returns junk', { trace: { calls: 'nope' } }],
    ['one frame is malformed', { trace: { ...cleanTrace, calls: [{ to: EXPLOITER }] } }],
  ];
  for (const [name, options] of failures) {
    await t.test(name, async () => {
      const { result, alerts, check } = await verify(options);
      assert.equal(result.status, 'incomplete');
      assert.equal(check('onchain:attacker').status, 'unknown');
      assert.match(check('onchain:attacker').detail, /not checked/);
      assert.equal(result.internalCallsChecked, null);
      assert.ok(alerts.some((alert) => alert.code === ALERT_CODES.ONCHAIN_TRACE_UNAVAILABLE));
    });
  }
});

test('an attacker in the logs still fails when the trace is unavailable', async () => {
  const { result, check } = await verify({ trace: null, logs: [{ address: USDC, topics: [TRANSFER, topic(ROUTER), topic(EXPLOITER)], data: amountData(5) }] });
  assert.equal(result.status, 'failed');
  assert.equal(check('onchain:attacker').status, 'fail');
});

test('a node that needs a moment to trace gets another try', async () => {
  let calls = 0;
  const { result } = await verify({ traceRequest: () => { calls++; if (calls < 3) throw new Error('not ready'); return cleanTrace; } });
  assert.equal(result.status, 'verified');
  assert.equal(calls, 3);
});

test('native spend counts internal sends from the wallet, and ignores reverted frames and delegatecalls', () => {
  const calls = flattenCallTrace({ type: 'CALL', from: WALLET, to: WALLET, value: '0x0', calls: [{ type: 'CALL', from: WALLET, to: OTHER, value: '0x5' }, { type: 'CALL', from: OTHER, to: USDC, error: 'execution reverted', value: '0x0', calls: [{ type: 'CALL', from: USDC, to: EXPLOITER, value: '0x1' }] }] });
  assert.equal(calls.length, 4);
  assert.equal(calls[3].reverted, true, 'A child of a reverted frame moved nothing either.');
});

test('internal ETH over the policy limit raises an alert', async () => {
  const over = BigInt(policy.invariants.maxNativeValueWei) + 1n;
  const trace = { ...cleanTrace, calls: [{ type: 'CALL', from: WALLET, to: OTHER, value: `0x${over.toString(16)}`, input: '0x' }] };
  const { result, check, alerts } = await verify({ trace });
  assert.equal(result.status, 'failed');
  assert.equal(check('onchain:native-limit').status, 'fail');
  assert.ok(alerts.some((alert) => alert.code === ALERT_CODES.ONCHAIN_LIMIT_EXCEEDED));
});

test('more native value leaving than simulated raises a warning', async () => {
  const { check, alerts } = await verify({ metrics: { gasLimit: '190000', outflows: {}, nativeOutflow: '1' } });
  assert.equal(check('onchain:matches-simulation').status, 'fail');
  assert.ok(alerts.some((alert) => alert.code === ALERT_CODES.ONCHAIN_DIFFERS_FROM_SIMULATION));
});

test('a swap paying less than the quote required raises an alert', async () => {
  const swaps = [{ tokenOut: USDC.toLowerCase(), requiredOut: '100' }];
  const paid = (amount) => [{ address: USDC, topics: [TRANSFER, topic(OTHER), topic(WALLET)], data: amountData(amount) }];
  assert.equal((await verify({ metrics: { gasLimit: '190000', outflows: {}, swaps }, logs: paid(100) })).result.status, 'verified');
  const short = await verify({ metrics: { gasLimit: '190000', outflows: {}, swaps }, logs: paid(99) });
  assert.equal(short.result.status, 'failed');
  assert.ok(short.alerts.some((alert) => alert.code === ALERT_CODES.ONCHAIN_SWAP_OUTPUT));
  const reverted = await verify({ metrics: { gasLimit: '190000', outflows: {}, swaps }, logs: [], status: '0x0' });
  assert.equal(reverted.check('onchain:swap-output'), undefined, 'A reverted swap already has its own alert.');
});
