import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import vm from 'node:vm';
import { id, Interface } from 'ethers';
import { auditPolicy, authorizeIntent, validatePolicy } from '../src/policy.js';
import { addProtocolStateSignature, signProtocolState } from '../src/protocol-state.js';
import { createPolicyFromRuleSet, GENERAL_RULE_SET } from '../src/rule-sets.js';
import { renderRulesetBuilder } from '../src/ruleset-page.js';
import { simulateTransaction } from '../src/transaction-simulator.js';

const ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const QUOTER = '0x61fFE014bA17989E743c5F6cB21bF9697530B21e';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const WALLET = '0x1111111111111111111111111111111111111111';
const POOL = '0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640';
const EXPLOITER = '0x489A8756C18C0b8B24EC2a2b9FF3D4d447F79BEc';
const NOW = new Date('2026-12-01T00:00:00.000Z');
const QUOTE = 2_000_000n;
const TRANSFER = id('Transfer(address,address,uint256)');
const topic = (address) => `0x${address.slice(2).toLowerCase().padStart(64, '0')}`;
const word = (amount) => `0x${BigInt(amount).toString(16).padStart(64, '0')}`;
const swapAbi = new Interface(['function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96)) payable returns (uint256)']);
const quoterAbi = new Interface(['function quoteExactInputSingle((address tokenIn,address tokenOut,uint256 amountIn,uint24 fee,uint160 sqrtPriceLimitX96))']);

const keys = [crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519')];
const trustedKeys = keys.map((pair, index) => ({ id: `k${index}`, algorithm: 'ed25519', publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') }));
const sources = [{ id: 'sim-a', env: 'TEST_SWAP_A' }, { id: 'sim-b', env: 'TEST_SWAP_B' }];
const rpcUrls = { 'sim-a': 'https://a.example', 'sim-b': 'https://b.example' };
const policyFor = (options = {}) => createPolicyFromRuleSet({ wallet: WALLET, trustedKeys, sources, validUntil: '2030-01-01T00:00:00.000Z', ...options });
const policy = policyFor();

function signedState(target = policy) {
  const byProtocol = new Map();
  for (const contract of target.contracts) byProtocol.set(contract.protocolId, [...(byProtocol.get(contract.protocolId) ?? []), contract.address]);
  const at = NOW.toISOString();
  const payload = { version: 1, sequence: 1, issuedAt: at, expiresAt: '2026-12-01T00:05:00.000Z', protocols: [...byProtocol].map(([protocolId, contracts]) => ({ id: protocolId, chainId: 1, status: 'operational', observedAt: at, contracts })) };
  let bundle = { version: 1, payload, signatures: [] };
  keys.forEach((pair, index) => { bundle = addProtocolStateSignature(bundle, signProtocolState(payload, { keyId: `k${index}`, privateKey: pair.privateKey })); });
  return bundle;
}

function swapIntent({ minimum = 1_990_000n, fee = 500, value = '0x0', amountIn = 10n ** 15n, tokenIn = WETH, tokenOut = USDC, priceLimit = 0n } = {}) {
  return { chainId: 1, from: WALLET, to: ROUTER, data: swapAbi.encodeFunctionData('exactInputSingle', [{ tokenIn, tokenOut, fee, recipient: WALLET, amountIn, amountOutMinimum: minimum, sqrtPriceLimitX96: priceLimit }]), value, gas: '0x2bf20', maxFeePerGas: '0x4a817c800', maxPriorityFeePerGas: '0x3b9aca00', nonce: '0x7', type: '0x2' };
}

/** A fake chain where each fee tier quotes its own amount. A tier set to null reverts, like an empty pool. */
function fakeChain({ quotes = { 100: QUOTE, 500: QUOTE, 3000: QUOTE }, received = QUOTE } = {}) {
  const response = (requestId, result) => {
    const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: requestId, result }));
    return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
  };
  const failure = (requestId, message) => {
    const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: requestId, error: { code: 3, message } }));
    return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
  };
  return async (url, options) => {
    const request = JSON.parse(options.body);
    switch (request.method) {
      case 'eth_chainId': return response(request.id, '0x1');
      case 'eth_blockNumber': return response(request.id, '0x100');
      case 'eth_getTransactionCount': return response(request.id, '0x7');
      case 'eth_getCode': return response(request.id, request.params[0].toLowerCase() === WALLET ? '0x' : '0x60016000');
      case 'eth_getStorageAt': return response(request.id, `0x${'0'.repeat(64)}`);
      case 'eth_estimateGas': return response(request.id, '0xc350');
      case 'eth_call': {
        if (request.params[0].to?.toLowerCase() !== QUOTER.toLowerCase()) return response(request.id, '0x');
        const [params] = quoterAbi.decodeFunctionData('quoteExactInputSingle', request.params[0].data);
        const quote = quotes[Number(params.fee)];
        return quote == null ? failure(request.id, 'execution reverted') : response(request.id, `${word(quote)}${'0'.repeat(192)}`);
      }
      case 'debug_traceCall': {
        const tx = request.params[0];
        if (request.params[2].tracer === 'prestateTracer') return response(request.id, { pre: {}, post: {} });
        return response(request.id, { type: 'CALL', from: tx.from, to: tx.to, value: tx.value, input: tx.data, output: '0x', gasUsed: '0xc350', logs: [{ address: USDC, topics: [TRANSFER, topic(POOL), topic(WALLET)], data: word(received) }], calls: [] });
      }
      default: throw new Error(`Unexpected ${request.method}`);
    }
  };
}

const simulate = (intent, chain = {}) => simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fakeChain(chain), now: NOW, protocolState: signedState() });
const failuresOf = (result) => result.summary.sources.flatMap((source) => source.failures ?? []);
const decide = (intent, target = policy) => authorizeIntent(target, intent, { now: NOW, protocolState: signedState(target) });
const deniedIds = (receipt) => receipt.checks.filter((check) => check.status === 'deny').map((check) => check.id);

test('a minimum within the slippage limit of the fresh quote passes, and the numbers are recorded', async () => {
  const result = await simulate(swapIntent());
  assert.equal(result.valid, true, JSON.stringify(failuresOf(result)));
  const [swap] = result.summary.metrics.swaps;
  assert.equal(swap.bestQuote, QUOTE.toString());
  assert.equal(swap.requiredOut, '1980000');
  assert.equal(swap.received, QUOTE.toString());
});

test('a one-unit minimum is denied, the case the old rule allowed', async () => {
  const receipt = decide(swapIntent({ minimum: 1n }));
  assert.equal(receipt.decision, 'simulate', 'One unit gets past the rule stage. The quote check stops it.');
  const result = await simulate(swapIntent({ minimum: 1n }));
  assert.equal(result.valid, false);
  assert.ok(failuresOf(result).some((failure) => /minimum 1 is below the 1980000 required/.test(failure)));
});

test('the limit is exact at the boundary', async () => {
  assert.equal((await simulate(swapIntent({ minimum: 1_980_000n }))).valid, true);
  assert.equal((await simulate(swapIntent({ minimum: 1_979_999n }))).valid, false);
});

test('the user sets the limit, and a tighter limit denies what a looser one allows', async () => {
  const tight = policyFor({ maxSlippageBps: 10 });
  const result = await simulateTransaction(tight, swapIntent({ minimum: 1_990_000n }), { rpcUrls, fetchImpl: fakeChain(), now: NOW, protocolState: signedState(tight) });
  assert.equal(result.valid, false);
  assert.ok(failuresOf(result).some((failure) => /1998000 required/.test(failure)));
});

test('routing through a measured pool with a much worse price is denied', async () => {
  const result = await simulate(swapIntent({ fee: 3000, minimum: 1_000_000n }), { quotes: { 100: null, 500: QUOTE, 3000: 1_000_000n }, received: 1_000_000n });
  assert.equal(result.valid, false);
  assert.ok(failuresOf(result).some((failure) => /best fresh quote is 2000000/.test(failure)));
});

test('an empty listed pool is ignored, but the chosen pool must be quotable', async () => {
  assert.equal((await simulate(swapIntent(), { quotes: { 100: null, 500: QUOTE, 3000: null } })).valid, true);
  const noQuote = await simulate(swapIntent(), { quotes: { 100: QUOTE, 500: null, 3000: QUOTE } });
  assert.equal(noQuote.valid, false);
  assert.ok(failuresOf(noQuote).some((failure) => /Could not get a fresh quote/.test(failure)));
  const none = await simulate(swapIntent(), { quotes: {} });
  assert.equal(none.valid, false);
});

test('a zero quote is treated as no quote', async () => {
  assert.equal((await simulate(swapIntent(), { quotes: { 500: 0n } })).valid, false);
});

test('a swap that would pay the wallet too little is denied, even with a good minimum in calldata', async () => {
  const result = await simulate(swapIntent(), { received: 5n });
  assert.equal(result.valid, false);
  assert.ok(failuresOf(result).some((failure) => /would receive 5/.test(failure)));
});

test('the rule stage refuses unlisted pools, bad amounts and wasted ETH', () => {
  assert.ok(deniedIds(decide(swapIntent({ fee: 10000 }))).includes('swap:pool-listed'));
  assert.ok(deniedIds(decide(swapIntent({ minimum: 0n }))).includes('swap:minimum-set'));
  assert.ok(deniedIds(decide(swapIntent({ amountIn: 0n }))).includes('swap:amount-set'));
  assert.ok(deniedIds(decide(swapIntent({ value: '0x1' }))).includes('swap:native-input'), 'Extra ETH would stay in the router.');
  assert.ok(deniedIds(decide(swapIntent({ tokenIn: USDC, tokenOut: WETH, value: '0x38d7ea4c68000' }))).includes('swap:native-input'), 'ETH cannot pay for a token that is not wrapped ETH.');
  assert.ok(deniedIds(decide(swapIntent({ priceLimit: 1n }))).some((check) => check.startsWith('constraint:')), 'A price limit could leave input stuck in the router.');
  assert.equal(decide(swapIntent({ value: '0x38d7ea4c68000' })).decision, 'simulate');
});

test('the shipped rule set binds swaps to a quote, not a fixed one-unit minimum', () => {
  const router = GENERAL_RULE_SET.contracts.find((contract) => contract.address === ROUTER);
  const [swap] = router.methods;
  assert.ok(!swap.constraints.some((constraint) => constraint.type === 'uint-min'));
  assert.equal(swap.swapQuote.quoter, QUOTER);
  assert.ok(swap.swapQuote.pools.length > 0);
  assert.equal(GENERAL_RULE_SET.invariants.maxSlippageBps, '100');
  const method = policy.contracts.find((contract) => contract.address === ROUTER).methods[0];
  assert.deepEqual(method.swapQuote, swap.swapQuote);
  assert.deepEqual(validatePolicy(policy), { valid: true, errors: [] });
  const listed = new Set(GENERAL_RULE_SET.assetLimits.flatMap((limit) => limit.allowedRecipients).map((address) => address.toLowerCase()));
  assert.ok(listed.has(POOL.toLowerCase()));
});

test('a policy with a quote check must set a sane slippage limit', () => {
  const without = structuredClone(policy);
  delete without.invariants.maxSlippageBps;
  assert.ok(validatePolicy(without).errors.some((error) => error.code === 'missing-slippage-limit'));
  for (const value of ['0', '5001']) {
    const bad = structuredClone(policy);
    bad.invariants.maxSlippageBps = value;
    assert.ok(validatePolicy(bad).errors.some((error) => error.code === 'invalid-slippage-limit'), value);
  }
});

test('a malformed quote rule, or an attacker as the quoter, is refused', () => {
  const edit = (change) => {
    const bad = structuredClone(policy);
    change(bad.contracts.find((contract) => contract.address === ROUTER).methods[0].swapQuote);
    return validatePolicy(bad);
  };
  assert.equal(edit((rule) => { rule.kind = 'unknown'; }).valid, false);
  assert.equal(edit((rule) => { rule.pools = []; }).valid, false);
  assert.equal(edit((rule) => { rule.pools[0].fee = 0; }).valid, false);
  assert.equal(edit((rule) => { rule.arguments.minimumOut = 99; }).valid, false);
  assert.equal(edit((rule) => { rule.extra = true; }).valid, false);
  assert.ok(edit((rule) => { rule.quoter = EXPLOITER; }).errors.some((error) => error.code === 'attacker-in-policy'));
});

test('audit flags a swap with no quote check, and a very loose slippage limit', () => {
  const unquoted = structuredClone(policy);
  delete unquoted.contracts.find((contract) => contract.address === ROUTER).methods[0].swapQuote;
  assert.ok(auditPolicy(unquoted).findings.some((finding) => finding.code === 'swap-without-fresh-quote' && finding.severity === 'high'));
  const loose = policyFor({ maxSlippageBps: 501 });
  assert.ok(auditPolicy(loose).findings.some((finding) => finding.code === 'high-slippage-limit'));
  assert.ok(!auditPolicy(policy).findings.some((finding) => finding.severity === 'high'));
});

/** Run the builder's own script with a stand-in page, so a test can see what it really exports. */
function exportFromBuilder(seed) {
  const html = renderRulesetBuilder({}, seed);
  const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]).join('\n');
  const stub = () => new Proxy(function stand() {}, {
    get(_target, key) {
      if (key === Symbol.toPrimitive) return () => '';
      if (key === Symbol.iterator) return function* empty() {};
      if (key === 'length') return 0;
      if (key === 'value' || key === 'textContent') return '';
      if (key === 'then') return undefined;
      return stub();
    },
    set: () => true,
    apply: () => stub(),
    construct: () => stub(),
  });
  const window = { addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }), location: { hash: '', search: '' } };
  const context = { window, document: stub(), localStorage: { getItem: () => null, setItem() {}, removeItem() {} }, navigator: stub(), location: window.location, requestAnimationFrame() {}, setTimeout() {}, clearTimeout() {}, ResizeObserver: function Observer() { return stub(); }, Blob: function Blob() {}, URL: stub(), confirm: () => false, console };
  vm.runInNewContext(script, context);
  return JSON.parse(JSON.stringify(window.__callScoutPolicyBuilder.compile()));
}

test('the policy builder keeps every safety setting when a user exports', () => {
  const seed = JSON.parse(fs.readFileSync(new URL('../examples/general-policy.json', import.meta.url), 'utf8'));
  seed.blockedAddresses = ['0x0000000000000000000000000000000000000bad'];
  const exported = exportFromBuilder(seed);
  assert.equal(exported.invariants.maxNativeOutflowPerBlockWei, seed.invariants.maxNativeOutflowPerBlockWei, 'ETH per-block limit');
  assert.equal(exported.invariants.maxSlippageBps, seed.invariants.maxSlippageBps, 'Slippage limit');
  assert.deepEqual(exported.blockedAddresses, seed.blockedAddresses);
  const limitOf = (policyDocument, token) => policyDocument.simulation.assetLimits.find((limit) => limit.token === token);
  assert.equal(limitOf(exported, USDC).maxOutflowPerBlock, limitOf(seed, USDC).maxOutflowPerBlock, 'Token per-block limit');
  const swapOf = (policyDocument) => policyDocument.contracts.find((contract) => contract.address === ROUTER).methods[0];
  assert.deepEqual(swapOf(exported).swapQuote, swapOf(seed).swapQuote, 'Swap quote check');
  assert.deepEqual(swapOf(exported).constraints, swapOf(seed).constraints);
  const validation = validatePolicy(exported);
  assert.deepEqual(validation, { valid: true, errors: [] });
});

test('with latest, every read uses one block both nodes have, so a busy pool cannot make them disagree', async () => {
  const headByHost = { 'a.example': 0x105n, 'b.example': 0x104n };
  const tags = [];
  const chain = fakeChain();
  const fetchImpl = async (url, options) => {
    const request = JSON.parse(options.body);
    const host = new URL(url).hostname;
    if (request.method === 'eth_blockNumber') {
      const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: `0x${headByHost[host].toString(16)}` }));
      return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
    }
    if (['eth_call', 'eth_estimateGas', 'debug_traceCall'].includes(request.method)) tags.push(request.params[1]);
    return chain(url, options);
  };
  assert.equal(policy.simulation.blockTag, 'latest');
  const result = await simulateTransaction(policy, swapIntent(), { rpcUrls, fetchImpl, now: NOW, protocolState: signedState() });
  assert.equal(result.valid, true, JSON.stringify(failuresOf(result)));
  assert.ok(tags.length > 6);
  assert.deepEqual([...new Set(tags)], ['0x104']);
  assert.equal(result.summary.blockNumber, '260', 'The per-block limit counts against the block that was really simulated.');
  assert.equal(result.summary.blockTag, 'latest');
});

test('pending is left as it is, because it cannot be pinned', async () => {
  const tags = [];
  const chain = fakeChain();
  const pendingPolicy = structuredClone(policy);
  pendingPolicy.simulation.blockTag = 'pending';
  const fetchImpl = async (url, options) => {
    const request = JSON.parse(options.body);
    if (['eth_call', 'debug_traceCall'].includes(request.method)) tags.push(request.params[1]);
    return chain(url, options);
  };
  await simulateTransaction(pendingPolicy, swapIntent(), { rpcUrls, fetchImpl, now: NOW, protocolState: signedState() });
  assert.deepEqual([...new Set(tags)], ['pending']);
});

test('one node being down still fails closed', async () => {
  const chain = fakeChain();
  const fetchImpl = async (url, options) => { if (new URL(url).hostname === 'b.example') throw new Error('down'); return chain(url, options); };
  const result = await simulateTransaction(policy, swapIntent(), { rpcUrls, fetchImpl, now: NOW, protocolState: signedState() });
  assert.equal(result.valid, false);
});
