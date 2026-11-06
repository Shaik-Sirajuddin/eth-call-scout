import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { id, Interface } from 'ethers';
import { ALERT_CODES, createAlertLog, raiseAlert, readAlerts } from '../src/alerts.js';
import { attackerListResponse, attackerLookupResponse } from '../src/attacker-api.js';
import { assertAttackerDocument, fetchAttackerDocument, mergeAttackerDocuments, protectedAddresses, updateLocalAttackerList } from '../src/attacker-feed.js';
import { assertAttackerList, ATTACKER_DOCUMENT, ATTACKER_LIST, attackerListIdentity, attackerLookup, createAttackerList, findAttackersInEffects, findAttackersInHex } from '../src/attacker-list.js';
import { blockSpendLimits, createBlockSpendTracker } from '../src/block-spend.js';
import { sha256 } from '../src/canonical.js';
import { GAS_RULES, gasRulesIdentity } from '../src/gas-limits.js';
import { createOnChainVerifier } from '../src/onchain-verifier.js';
import { authorizeIntent, validatePolicy } from '../src/policy.js';
import { addProtocolStateSignature, signProtocolState } from '../src/protocol-state.js';
import { createMonitorFromPolicy, createPolicyFromRuleSet, GENERAL_RULE_SET, ruleSetProfiles, toBaseUnits } from '../src/rule-sets.js';
import { renderRulesetBuilder } from '../src/ruleset-page.js';
import { simulateTransaction } from '../src/transaction-simulator.js';
import { createGuardedProvider, WalletGuardError } from '../src/wallet-guard.js';

const EXPLOITER = '0x489A8756C18C0b8B24EC2a2b9FF3D4d447F79BEc';
const ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const AAVE = '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const WALLET = '0x1111111111111111111111111111111111111111';
const NOW = new Date('2026-12-01T00:00:00.000Z');
const TRANSFER = id('Transfer(address,address,uint256)');
const APPROVAL = id('Approval(address,address,uint256)');
const topic = (address) => `0x${address.slice(2).toLowerCase().padStart(64, '0')}`;
const amountData = (amount) => `0x${BigInt(amount).toString(16).padStart(64, '0')}`;

const stateKeys = [crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519')];
const trustedKeys = stateKeys.map((keys, index) => ({ id: `test-${index}`, algorithm: 'ed25519', publicKey: keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') }));
const sources = [{ id: 'sim-a', env: 'TEST_SIM_A' }, { id: 'sim-b', env: 'TEST_SIM_B' }];
const rpcUrls = { 'sim-a': 'https://a.example', 'sim-b': 'https://b.example' };
const swapAbi = new Interface(['function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96)) payable returns (uint256)']);
const aaveAbi = new Interface(['function supply(address,uint256,address,uint16)', 'function flashLoanSimple(address,address,uint256,bytes,uint16)', 'function borrow(address,uint256,uint256,uint16,address)']);
const erc20Abi = new Interface(['function approve(address,uint256)', 'function transfer(address,uint256)']);

const policyFor = (options = {}) => createPolicyFromRuleSet({ wallet: WALLET, trustedKeys, sources, validUntil: '2030-01-01T00:00:00.000Z', ...options });

function signedState(policy) {
  const byProtocol = new Map();
  for (const contract of policy.contracts) byProtocol.set(contract.protocolId, [...(byProtocol.get(contract.protocolId) ?? []), contract.address]);
  const at = NOW.toISOString();
  const payload = { version: 1, sequence: 1, issuedAt: at, expiresAt: '2026-12-01T00:05:00.000Z', protocols: [...byProtocol].map(([protocolId, contracts]) => ({ id: protocolId, chainId: 1, status: 'operational', observedAt: at, contracts })) };
  let bundle = { version: 1, payload, signatures: [] };
  stateKeys.forEach((keys, index) => { bundle = addProtocolStateSignature(bundle, signProtocolState(payload, { keyId: `test-${index}`, privateKey: keys.privateKey })); });
  return bundle;
}

function swapData(recipient, overrides = {}) {
  return swapAbi.encodeFunctionData('exactInputSingle', [{ tokenIn: WETH, tokenOut: USDC, fee: 500, recipient, amountIn: 10n ** 15n, amountOutMinimum: 1_000_000n, sqrtPriceLimitX96: 0n, ...overrides }]);
}

function intentFor(to, data, overrides = {}) {
  return { chainId: 1, from: WALLET, to, data, value: '0x0', gas: '0x2bf20', maxFeePerGas: '0x4a817c800', maxPriorityFeePerGas: '0x3b9aca00', nonce: '0x7', type: '0x2', ...overrides };
}

const deniedIds = (receipt) => receipt.checks.filter((check) => check.status === 'deny').map((check) => check.id);
const memoryAlerts = () => { const entries = []; return { entries, async append(alert) { entries.push(alert); return alert; } }; };

test('the shipped list holds the demo exploiter, and it cannot be forged', () => {
  const match = ATTACKER_LIST.find(EXPLOITER);
  assert.match(match.label, /BNB Bridge Exploiter/);
  assert.ok(ATTACKER_LIST.count > 1000);
  assert.throws(() => assertAttackerList({ ...ATTACKER_LIST }), /createAttackerList/);
  assert.throws(() => createAttackerList({ version: 1, listVersion: 'x', entries: { 'not-an-address': { sources: ['a'] } } }), /Invalid attacker list entry/);
});

test('the shipped list never blocks the protocols and system addresses we rely on', () => {
  for (const address of protectedAddresses()) assert.equal(ATTACKER_LIST.find(address), null, address);
});

test('a listed target, a calldata word, and a packed path are all denied before simulation', () => {
  const policy = policyFor();
  const state = signedState(policy);
  const receipt = authorizeIntent(policy, intentFor(ROUTER, swapData(EXPLOITER), { value: '0x38d7ea4c68000' }), { now: NOW, protocolState: state });
  assert.equal(receipt.decision, 'deny');
  assert.ok(deniedIds(receipt).includes('attacker:calldata'));
  assert.deepEqual(receipt.attackerList, attackerListIdentity(ATTACKER_LIST));

  const toAttacker = authorizeIntent(policy, intentFor(EXPLOITER, '0x'), { now: NOW, protocolState: state });
  assert.ok(deniedIds(toAttacker).includes('attacker:target'));

  const lookup = attackerLookup(ATTACKER_LIST);
  const packed = `0x12345678${WETH.slice(2)}0001f4${EXPLOITER.slice(2)}`;
  assert.equal(findAttackersInHex(packed, lookup)[0].address, EXPLOITER.toLowerCase());
  assert.equal(findAttackersInHex(swapData(WALLET), lookup).length, 0);
});

test('a policy can add blocked addresses but cannot allow a listed attacker', () => {
  const extra = '0x9999999999999999999999999999999999999999';
  const policy = policyFor({ blockedAddresses: [extra] });
  assert.equal(validatePolicy(policy).valid, true);
  const receipt = authorizeIntent(policy, intentFor(ROUTER, swapData(extra)), { now: NOW, protocolState: signedState(policy) });
  assert.ok(deniedIds(receipt).includes('attacker:calldata'));

  const bad = structuredClone(policy);
  bad.simulation.assetLimits[0].allowedRecipients.push(EXPLOITER);
  const validation = validatePolicy(bad);
  assert.equal(validation.valid, false);
  assert.ok(validation.errors.some((error) => error.code === 'attacker-in-policy'));
  assert.equal(validatePolicy({ ...policy, blockedAddresses: ['nope'] }).valid, false);
});

function fakeChain({ logs = [], logsByHost = {}, extraCalls = [] } = {}) {
  const response = (requestId, result) => {
    const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: requestId, result }));
    return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
  };
  return async (url, options) => {
    const request = JSON.parse(options.body);
    const host = new URL(url).hostname;
    switch (request.method) {
      case 'eth_chainId': return response(request.id, '0x1');
      case 'eth_blockNumber': return response(request.id, '0x100');
      case 'eth_getTransactionCount': return response(request.id, '0x7');
      case 'eth_getCode': return response(request.id, request.params[0].toLowerCase() === WALLET ? '0x' : '0x60016000');
      case 'eth_getStorageAt': return response(request.id, `0x${'0'.repeat(64)}`);
      case 'eth_call': return response(request.id, '0x');
      case 'eth_estimateGas': return response(request.id, '0xc350');
      case 'debug_traceCall': {
        const tx = request.params[0];
        if (request.params[2].tracer === 'prestateTracer') return response(request.id, { pre: {}, post: {} });
        return response(request.id, { type: 'CALL', from: tx.from, to: tx.to, value: tx.value, input: tx.data, output: '0x', gasUsed: '0xc350', logs: logsByHost[host] ?? logs, calls: extraCalls });
      }
      default: throw new Error(`Unexpected ${request.method}`);
    }
  };
}

test('an attacker hidden from calldata is caught in the simulated transfers', async () => {
  const policy = policyFor();
  const hiddenPayout = { address: USDC, topics: [TRANSFER, topic(ROUTER), topic(EXPLOITER)], data: amountData(5_000_000n) };
  const intent = intentFor(ROUTER, swapData(WALLET), { value: '0x38d7ea4c68000' });

  const clean = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fakeChain({ logs: [] }), now: NOW, protocolState: signedState(policy) });
  assert.equal(clean.valid, true, JSON.stringify(clean.summary.sources));

  const dirty = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fakeChain({ logs: [hiddenPayout] }), now: NOW, protocolState: signedState(policy) });
  assert.equal(dirty.valid, false);
  assert.equal(dirty.checks.find((check) => check.id === 'attacker:effects').status, 'deny');
  assert.equal(dirty.summary.attackerHits[0].address, EXPLOITER.toLowerCase());

  // One source reporting a thief is enough, even when the other looks clean.
  const oneSource = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fakeChain({ logsByHost: { 'a.example': [hiddenPayout] } }), now: NOW, protocolState: signedState(policy) });
  assert.equal(oneSource.valid, false);
  assert.equal(oneSource.checks.find((check) => check.id === 'attacker:effects').status, 'deny');
});

test('approvals and internal calls to an attacker count as well', () => {
  const lookup = attackerLookup(ATTACKER_LIST);
  const approval = findAttackersInEffects({ logs: [{ address: USDC, topics: [APPROVAL, topic(WALLET), topic(EXPLOITER)], data: amountData(1) }] }, lookup);
  assert.match(approval[0].reasons[0], /approval/);
  const call = findAttackersInEffects({ calls: [{ to: EXPLOITER, input: '0x' }] }, lookup);
  assert.match(call[0].reasons[0], /called or paid/);
  assert.equal(findAttackersInEffects({ logs: [{ address: USDC, topics: [TRANSFER, topic(EXPLOITER), topic(WALLET)], data: amountData(1) }] }, lookup).length, 0, 'Receiving from an address is not paying it.');
});

function allowedSimulator(metrics, blockNumber = '256') {
  return async () => ({
    valid: true,
    checks: [{ id: 'simulation:consensus', status: 'pass', detail: 'test' }],
    summary: { gasRules: gasRulesIdentity(GAS_RULES), attackerList: attackerListIdentity(ATTACKER_LIST), attackerHits: [], fingerprint: 'test', agreeingSources: ['a', 'b'], blockNumber, metrics },
  });
}

function guardedSwap({ limitWei = '150', metrics = { nativeOutflow: '100', outflows: {} }, provider, simulator, alerts = memoryAlerts(), blockSpend = createBlockSpendTracker(), verification = false }) {
  const policy = policyFor({ native: { maxValueWei: '1000', maxPerBlockWei: limitWei } });
  const sent = [];
  const guard = createGuardedProvider({
    provider: provider ?? { async request(request) { if (request.method === 'eth_chainId') return '0x1'; sent.push(request.params[0]); return `0x${String(sent.length).padStart(64, '0')}`; } },
    policy,
    protocolState: signedState(policy),
    simulator: simulator ?? allowedSimulator(metrics),
    alerts,
    blockSpend,
    verification,
    now: NOW,
  });
  const request = (nonce = '0x7') => guard.request({ method: 'eth_sendTransaction', params: [intentFor(ROUTER, swapData(WALLET), { value: '0x64', nonce })] });
  return { guard, request, sent, alerts };
}

test('a per-block limit denies the transaction that goes over it, and writes an alert', async () => {
  const { request, sent, alerts } = guardedSwap({});
  await request('0x7');
  assert.equal(sent.length, 1);
  await assert.rejects(request('0x8'), (error) => {
    assert.ok(error instanceof WalletGuardError);
    assert.ok(deniedIds(error.receipt).includes('spend:block-limit'));
    return true;
  });
  assert.equal(sent.length, 1, 'The wallet must not be called.');
  assert.equal(alerts.entries[0].code, ALERT_CODES.BLOCK_LIMIT_REACHED);
  assert.equal(alerts.entries[0].blockNumber, '256');
});

test('the limit is per block, and a new block starts again', async () => {
  const blockSpend = createBlockSpendTracker();
  let block = '256';
  const simulator = async (...args) => allowedSimulator({ nativeOutflow: '100', outflows: {} }, block)(...args);
  const { request, sent } = guardedSwap({ simulator, blockSpend });
  await request('0x7');
  block = '257';
  await request('0x8');
  assert.equal(sent.length, 2);
});

test('token limits work too, and two requests at once cannot both use the same room', async () => {
  const tracker = createBlockSpendTracker();
  const limits = blockSpendLimits(policyFor({ limits: { USDC: { maxOutflowPerBlock: '100' } } }), 1);
  assert.equal(limits.get(USDC.toLowerCase()), 100n);
  const spend = new Map([[USDC.toLowerCase(), 60n]]);
  const args = { chainId: 1, wallet: WALLET, block: '256', spend, limits };
  const results = [tracker.reserve(args), tracker.reserve(args)];
  assert.deepEqual(results.map((result) => result.ok), [true, false]);
  tracker.release(results[0].reservation);
  assert.equal(tracker.reserve(args).ok, true);
});

test('a wallet that refuses gives the room back', async () => {
  let fail = true;
  const sent = [];
  const provider = { async request(request) { if (request.method === 'eth_chainId') return '0x1'; if (fail) throw new Error('user rejected'); sent.push(request); return `0x${'a'.repeat(64)}`; } };
  const { request } = guardedSwap({ provider, limitWei: '100' });
  await assert.rejects(request(), /user rejected/);
  fail = false;
  await request();
  assert.equal(sent.length, 1);
});

test('a policy that sets a block limit fails closed when simulation reports no block', async () => {
  const simulator = async () => ({ valid: true, checks: [], summary: { gasRules: gasRulesIdentity(GAS_RULES), attackerList: attackerListIdentity(ATTACKER_LIST) } });
  const { request, sent } = guardedSwap({ simulator });
  await assert.rejects(request(), WalletGuardError);
  assert.equal(sent.length, 0);
});

test('blocked attacker requests raise a critical alert and never reach the wallet', async () => {
  const alerts = memoryAlerts();
  const { guard, sent } = guardedSwap({ alerts });
  await assert.rejects(guard.request({ method: 'eth_sendTransaction', params: [intentFor(ROUTER, swapData(EXPLOITER))] }), WalletGuardError);
  assert.equal(sent.length, 0);
  assert.equal(alerts.entries[0].code, ALERT_CODES.ATTACKER_BLOCKED);
  assert.equal(alerts.entries[0].severity, 'critical');
});

function chainFor({ receipt = {}, transaction = {}, latestNonce = '0x8', logs = [] } = {}) {
  const decisionIntent = { chainId: 1, from: WALLET.toLowerCase(), to: ROUTER.toLowerCase(), data: '0xabcd', value: '0', nonce: '7' };
  return {
    decision: { policy: { name: 't', hash: 'h' }, intent: decisionIntent, simulation: { metrics: { gasLimit: '190000', outflows: {} } } },
    request: async (method) => {
      if (method === 'eth_getTransactionReceipt') return { status: '0x1', blockNumber: '0x100', gasUsed: '0x1000', logs, ...receipt };
      if (method === 'eth_getTransactionByHash') return { from: WALLET, to: ROUTER, input: '0xabcd', value: '0x0', nonce: '0x7', ...transaction };
      if (method === 'eth_getTransactionCount') return latestNonce;
      throw new Error(method);
    },
  };
}

async function verifyWith(chain, policy = policyFor()) {
  const alerts = memoryAlerts();
  const verifier = createOnChainVerifier({ request: chain.request, policy, attackerList: ATTACKER_LIST, alerts, tracker: createBlockSpendTracker(), timeoutMs: 50, pollMs: 5 });
  verifier.expectNonce('7');
  return { result: await verifier.verify(`0x${'b'.repeat(64)}`, chain.decision), alerts: alerts.entries };
}

test('a clean mined transaction verifies with no alerts', async () => {
  const { result, alerts } = await verifyWith(chainFor());
  assert.equal(result.status, 'verified');
  assert.equal(alerts.length, 0);
  assert.equal(result.blockNumber, '256');
});

test('on-chain failures become alerts', async (t) => {
  const cases = [
    ['reverted', chainFor({ receipt: { status: '0x0' } }), ALERT_CODES.ONCHAIN_REVERTED],
    ['wallet changed the call', chainFor({ transaction: { to: EXPLOITER } }), ALERT_CODES.ONCHAIN_MISMATCH],
    ['attacker got tokens', chainFor({ logs: [{ address: USDC, topics: [TRANSFER, topic(ROUTER), topic(EXPLOITER)], data: amountData(5) }] }), ALERT_CODES.ONCHAIN_ATTACKER],
    ['token left beyond the limit', chainFor({ logs: [{ address: USDC, topics: [TRANSFER, topic(WALLET), topic(EXPLOITER)], data: amountData(10n ** 30n) }] }), ALERT_CODES.ONCHAIN_LIMIT_EXCEEDED],
    ['too much gas', chainFor({ receipt: { gasUsed: '0xfffff' } }), ALERT_CODES.ONCHAIN_GAS_EXCEEDED],
    ['transaction sent around the guard', chainFor({ latestNonce: '0xa' }), ALERT_CODES.UNAPPROVED_TRANSACTION],
  ];
  for (const [name, chain, code] of cases) {
    await t.test(name, async () => {
      const { result, alerts } = await verifyWith(chain);
      assert.equal(result.status, 'failed');
      assert.ok(alerts.some((alert) => alert.code === code), JSON.stringify(alerts.map((alert) => alert.code)));
    });
  }
});

test('an unreadable or unmined transaction raises a warning instead of passing', async () => {
  const notMined = await verifyWith({ decision: chainFor().decision, request: async () => null });
  assert.equal(notMined.result.status, 'not-mined');
  assert.equal(notMined.alerts[0].code, ALERT_CODES.ONCHAIN_NOT_MINED);
  const down = await verifyWith({ decision: chainFor().decision, request: async () => { throw new Error('node down'); } });
  assert.equal(down.result.status, 'unavailable');
  assert.equal(down.alerts[0].code, ALERT_CODES.ONCHAIN_UNAVAILABLE);
});

test('the guard verifies in the background and reports the result', async () => {
  const chain = chainFor();
  const results = [];
  const policy = policyFor({ native: { maxValueWei: '1000', maxPerBlockWei: '1000' } });
  const provider = { async request(request) { return request.method === 'eth_chainId' ? '0x1' : `0x${'c'.repeat(64)}`; } };
  const guard = createGuardedProvider({ provider, policy, protocolState: signedState(policy), simulator: allowedSimulator({ nativeOutflow: '100', outflows: {} }), alerts: memoryAlerts(), verification: { request: chain.request, timeoutMs: 50, pollMs: 5 }, onVerification: (result) => results.push(result), now: NOW });
  const hash = await guard.request({ method: 'eth_sendTransaction', params: [intentFor(ROUTER, swapData(WALLET), { value: '0x64' })] });
  const [settled] = await guard.settled();
  assert.equal(settled.transactionHash, hash);
  assert.equal((await guard.verification(hash)).kind, 'onchain-verification');
  assert.equal(results.length, 1);
});

test('the alert log stays a valid chain under parallel writes, and a failing log never throws', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'kb-alerts-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'alerts.jsonl');
  const log = createAlertLog(file, { echo: false });
  await Promise.all([1, 2, 3, 4].map((index) => raiseAlert(log, { code: ALERT_CODES.ATTACKER_BLOCKED, message: `alert ${index}` })));
  assert.equal((await log.verify()).valid, true);
  assert.equal((await readAlerts(file)).length, 4);
  assert.deepEqual(await readAlerts(path.join(directory, 'missing.jsonl')), []);
  const alert = await raiseAlert({ append: async () => { throw new Error('disk full'); } }, { code: 'x', message: 'still returned' });
  assert.equal(alert.message, 'still returned');
});

test('the free API serves the whole list, a cheap summary, a plain array, and single lookups', async () => {
  const list = createAttackerList(ATTACKER_DOCUMENT);
  const get = (query, headers = {}) => attackerListResponse(new Request(`https://example.test/api/v1/attackers${query}`, { headers }));
  const full = await get('');
  assert.equal(full.status, 200);
  assert.equal(full.headers.get('access-control-allow-origin'), '*');
  assert.equal(full.headers.get('x-keybound-list-hash'), list.hash);
  assert.equal(sha256(await full.json()), list.hash, 'A client must be able to check the hash it was told.');

  const meta = await (await get('?view=meta')).json();
  assert.equal(meta.count, list.count);
  assert.ok(!('entries' in meta));
  const addresses = await (await get('?view=addresses')).json();
  assert.ok(addresses.addresses.includes(EXPLOITER.toLowerCase()));

  const cached = await get('', { 'if-none-match': `"${list.hash}"` });
  assert.equal(cached.status, 304);
  assert.equal((await get('?view=nope')).status, 400);

  const hit = await attackerLookupResponse(EXPLOITER).json();
  assert.equal(hit.listed, true);
  assert.match(hit.label, /BNB Bridge/);
  assert.equal((await attackerLookupResponse(WALLET).json()).listed, false);
  assert.equal(attackerLookupResponse('bad').status, 400);
});

test('an update can only add addresses, and can never list a protected one', () => {
  const entry = { sources: ['test'] };
  const a = `0x${'a1'.repeat(20)}`;
  const b = `0x${'b2'.repeat(20)}`;
  const base = { version: 1, listVersion: '2026-01-01', entries: { [a]: entry } };
  const update = { version: 1, listVersion: '2026-02-02', entries: { [b]: entry, [USDC.toLowerCase()]: entry } };
  const merged = mergeAttackerDocuments(base, update);
  assert.ok(merged.document.entries[a], 'An update must not remove an address.');
  assert.ok(merged.document.entries[b]);
  assert.equal(merged.document.entries[USDC.toLowerCase()], undefined);
  assert.deepEqual(merged.refused, [USDC.toLowerCase()]);
  assert.equal(merged.document.listVersion, '2026-02-02');
  assert.throws(() => assertAttackerDocument({ version: 1, listVersion: 'x', entries: [] }), /not an attacker list/);
});

test('downloads must be intact and over HTTPS, and an update is saved where the guard loads it', async (t) => {
  const document = { version: 1, listVersion: '2030-01-01', entries: { [`0x${'c3'.repeat(20)}`]: { sources: ['test'] } } };
  const serve = (hash) => async () => new Response(JSON.stringify(document), { headers: hash ? { 'x-keybound-list-hash': hash } : {} });
  await assert.rejects(fetchAttackerDocument('http://example.test/list.json'), /HTTPS/);
  await assert.rejects(fetchAttackerDocument('https://example.test/list.json', { fetchImpl: serve('wrong') }), /does not match/);
  assert.equal((await fetchAttackerDocument('https://example.test/list.json', { fetchImpl: serve(sha256(document)) })).listVersion, '2030-01-01');
  await assert.rejects(fetchAttackerDocument('https://example.test/list.json', { fetchImpl: async () => new Response('<html>', {}) }));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'kb-feed-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'nested', 'list.json');
  const result = await updateLocalAttackerList(ATTACKER_DOCUMENT, { url: 'https://example.test/list.json', file, fetchImpl: serve(sha256(document)) });
  assert.equal(result.added, 1);
  assert.equal(result.count, ATTACKER_LIST.count + 1);
  assert.ok(JSON.parse(fs.readFileSync(file, 'utf8')).entries[EXPLOITER.toLowerCase()], 'Saved list keeps every shipped address.');
});

test('the default rule set builds a valid policy that allows everyday calls and denies the rest', () => {
  const policy = policyFor();
  assert.deepEqual(validatePolicy(policy), { valid: true, errors: [] });
  const state = signedState(policy);
  const decide = (to, data, overrides) => authorizeIntent(policy, intentFor(to, data, overrides), { now: NOW, protocolState: state });

  assert.equal(decide(ROUTER, swapData(WALLET), { value: '0x38d7ea4c68000' }).decision, 'simulate');
  assert.equal(decide(AAVE, aaveAbi.encodeFunctionData('supply', [USDC, 1000n, WALLET, 0])).decision, 'simulate');
  assert.equal(decide(USDC, erc20Abi.encodeFunctionData('approve', [ROUTER, 1000n]), { gas: '0xfde8' }).decision, 'simulate');

  assert.equal(decide(ROUTER, swapData(ROUTER)).decision, 'deny', 'Swap output must go to the wallet.');
  assert.equal(decide(ROUTER, swapData(WALLET, { amountOutMinimum: 0n })).decision, 'deny', 'A zero minimum output is refused.');
  assert.equal(decide(AAVE, aaveAbi.encodeFunctionData('supply', [USDC, 1000n, ROUTER, 0])).decision, 'deny');
  assert.equal(decide(AAVE, aaveAbi.encodeFunctionData('flashLoanSimple', [WALLET, USDC, 1000n, '0x', 0])).decision, 'deny');
  assert.equal(decide(AAVE, aaveAbi.encodeFunctionData('borrow', [USDC, 1000n, 2, 0, WALLET])).decision, 'deny');
  assert.equal(decide(USDC, erc20Abi.encodeFunctionData('approve', [WALLET, 1000n])).decision, 'deny');
  assert.equal(decide(USDC, erc20Abi.encodeFunctionData('transfer', [ROUTER, 1000n])).decision, 'deny', 'Paying other people is off by default.');
});

test('each user type gets only what it needs', () => {
  assert.deepEqual(Object.keys(ruleSetProfiles()).sort(), ['general', 'lender', 'payments', 'swapper']);
  const targets = (policy) => policy.contracts.map((contract) => contract.address);
  const swapper = policyFor({ profile: 'swapper' });
  assert.equal(validatePolicy(swapper).valid, true);
  assert.ok(targets(swapper).includes(ROUTER));
  assert.ok(!targets(swapper).includes(AAVE));
  const approve = swapper.contracts.find((contract) => contract.address === USDC).methods[0];
  assert.deepEqual(approve.constraints[0].addresses, [ROUTER], 'A swapper must not be able to approve the lending pool.');

  const lender = policyFor({ profile: 'lender' });
  assert.equal(validatePolicy(lender).valid, true);
  assert.ok(targets(lender).includes(AAVE));
  assert.ok(!targets(lender).includes(ROUTER));

  const payee = '0x2222222222222222222222222222222222222222';
  const payments = policyFor({ profile: 'payments', payees: [payee] });
  assert.equal(validatePolicy(payments).valid, true);
  const receipt = authorizeIntent(payments, intentFor(USDC, erc20Abi.encodeFunctionData('transfer', [payee, 1000n]), { gas: '0x13880' }), { now: NOW, protocolState: signedState(payments) });
  assert.equal(receipt.decision, 'simulate', JSON.stringify(deniedIds(receipt)));
  assert.throws(() => policyFor({ profile: 'payments' }), /allows nothing/);
  assert.throws(() => policyFor({ profile: 'nope' }), /Unknown profile/);
});

test('users can set lower limits in the rule set, and the monitor pins measured code', () => {
  const policy = policyFor({ limits: { USDC: { maxOutflow: '5', maxOutflowPerBlock: '5', maxApproval: '5' } }, native: { maxValueWei: '7', maxPerBlockWei: '7' } });
  const usdc = policy.simulation.assetLimits.find((limit) => limit.token === USDC);
  assert.equal(usdc.maxOutflowPerBlock, '5');
  assert.equal(policy.invariants.maxNativeOutflowPerBlockWei, '7');
  assert.equal(validatePolicy(policy).valid, true);
  const monitor = createMonitorFromPolicy(policy, { sources });
  assert.ok(monitor.protocols.length >= 3);
  assert.ok(monitor.protocols.flatMap((protocol) => protocol.contracts).every((contract) => /^0x[0-9a-f]{64}$/.test(contract.codeHash)));
  assert.equal(toBaseUnits('12.5', 6), '12500000');
  assert.equal(toBaseUnits('1', 18), '1000000000000000000');
  assert.throws(() => toBaseUnits('1.1234567', 6), /decimal places/);
  assert.throws(() => toBaseUnits('abc', 6), /Invalid amount/);
});

test('the example default policy matches the rule set, and the builder can edit the new limits', () => {
  const shipped = JSON.parse(fs.readFileSync(new URL('../examples/general-policy.json', import.meta.url), 'utf8'));
  const rebuilt = createPolicyFromRuleSet({ wallet: shipped.wallets[0], trustedKeys: shipped.protocolState.trustedKeys, validUntil: shipped.validUntil, name: shipped.name });
  assert.deepEqual(shipped, rebuilt, 'Run npm run rules:example after changing the rule set.');
  assert.equal(validatePolicy(shipped).valid, true);
  assert.ok(GENERAL_RULE_SET.contracts.length >= 6);
  const html = renderRulesetBuilder({}, shipped);
  for (const field of ['maxOutflowPerBlock', 'maxNativeOutflowPerBlockWei', 'blockedAddresses']) assert.ok(html.includes(field), field);
});

test('the schema documents the new policy fields', () => {
  const schema = JSON.parse(fs.readFileSync(new URL('../schema/wallet-policy.schema.json', import.meta.url), 'utf8'));
  assert.ok(schema.properties.blockedAddresses);
  assert.ok(schema.properties.invariants.properties.maxNativeOutflowPerBlockWei);
  assert.ok(schema.properties.simulation.properties.assetLimits.items.properties.maxOutflowPerBlock);
});
