import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { id, keccak256, Wallet } from 'ethers';
import { simulateTransaction } from '../src/transaction-simulator.js';

const policy = JSON.parse(fs.readFileSync(new URL('../examples/wallet-policy.json', import.meta.url), 'utf8'));
const intent = JSON.parse(fs.readFileSync(new URL('../examples/transaction-intent.json', import.meta.url), 'utf8'));
const rpcUrls = { 'sim-primary': 'https://primary.example', 'sim-secondary': 'https://secondary.example' };
const ZERO_WORD = `0x${'0'.repeat(64)}`;
const ONE_WORD = `0x${'0'.repeat(63)}1`;
const APPROVAL_TOPIC = id('Approval(address,address,uint256)');
const topicAddress = (address) => `0x${address.slice(2).toLowerCase().padStart(64, '0')}`;

function response(idValue, result) {
  const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: idValue, result }));
  return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
}

function simulationFetch({ delegated = false, delegateAddress = `0x${'44'.repeat(20)}`, delegateCode = '0x6001600055', currentNonce = '0x7', rpcChainId = '0x1', traceFrom = null, unauthorizedInternalCall = false, outputByHost = {} } = {}) {
  const methods = [];
  const transactions = [];
  const fetchImpl = async (url, options) => {
    const request = JSON.parse(options.body);
    methods.push(request.method);
    if (['eth_call', 'eth_estimateGas', 'debug_traceCall'].includes(request.method)) transactions.push(request.params[0]);
    if (request.method === 'eth_chainId') return response(request.id, rpcChainId);
    if (request.method === 'eth_blockNumber') return response(request.id, '0x100');
    if (request.method === 'eth_getCode') {
      const address = request.params[0].toLowerCase();
      const code = address === delegateAddress.toLowerCase() ? delegateCode : delegated ? `0xef0100${delegateAddress.slice(2)}` : '0x';
      return response(request.id, code);
    }
    if (request.method === 'eth_getTransactionCount') return response(request.id, currentNonce);
    if (request.method === 'eth_call') return response(request.id, outputByHost[new URL(url).hostname] ?? '0x');
    if (request.method === 'eth_estimateGas') return response(request.id, '0xea60');
    if (request.method === 'debug_traceCall' && request.params[2].tracer === 'callTracer') {
      const calls = unauthorizedInternalCall ? [{
        type: 'CALL', from: intent.to, to: '0x3333333333333333333333333333333333333333', value: '0x0', input: '0x', output: '0x',
      }] : [];
      const tx = request.params[0];
      return response(request.id, {
        type: 'CALL',
        from: traceFrom ?? tx.from,
        to: tx.to,
        value: '0x0',
        input: tx.data,
        output: outputByHost[new URL(url).hostname] ?? '0x',
        gasUsed: '0xea60',
        logs: [{
          address: intent.to,
          topics: [APPROVAL_TOPIC, topicAddress(tx.from), topicAddress('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')],
          data: `0x${(1_000_000_000n).toString(16).padStart(64, '0')}`,
        }],
        calls,
      });
    }
    if (request.method === 'debug_traceCall' && request.params[2].tracer === 'prestateTracer') {
      const tx = request.params[0];
      const authorization = tx.authorizationList?.[0];
      return response(request.id, {
        pre: {
          [intent.to.toLowerCase()]: { storage: { [ZERO_WORD]: ZERO_WORD } },
          ...(authorization ? { [tx.from.toLowerCase()]: { code: '0x' } } : {}),
        },
        post: {
          [intent.to.toLowerCase()]: { storage: { [ZERO_WORD]: ONE_WORD } },
          ...(authorization ? { [tx.from.toLowerCase()]: { code: `0xef0100${authorization.address.slice(2).toLowerCase()}` } } : {}),
        },
      });
    }
    throw new Error(`Unexpected RPC method ${request.method}`);
  };
  return { fetchImpl, methods, transactions };
}

test('allows only when a quorum agrees on one passing full trace and state diff', async () => {
  const fake = simulationFetch();
  const result = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fake.fetchImpl });
  assert.equal(result.valid, true);
  assert.deepEqual(result.summary.agreeingSources, ['sim-primary', 'sim-secondary']);
  assert.equal(result.summary.metrics.calls, 1);
  assert.equal(result.summary.metrics.storageWrites, 1);
  assert.equal(result.checks.find((check) => check.id === 'eip7702:security').status, 'pass');
  assert.ok(fake.transactions.every((transaction) => transaction.nonce === '0x7' && Array.isArray(transaction.accessList)));
});

test('denies an unauthorized internal call observed by the simulation quorum', async () => {
  const fake = simulationFetch({ unauthorizedInternalCall: true });
  const result = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fake.fetchImpl });
  assert.equal(result.valid, false);
  assert.ok(result.summary.sources.every((source) => source.failures.some((failure) => failure.includes('Internal target'))));
  assert.equal(result.checks.find((check) => check.id === 'simulation:policy').status, 'deny');
});

test('explicitly denies an already-delegated EIP-7702 wallet before tracing', async () => {
  const fake = simulationFetch({ delegated: true });
  const result = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fake.fetchImpl });
  assert.equal(result.valid, false);
  assert.equal(result.checks.find((check) => check.id === 'eip7702:security').status, 'deny');
  assert.ok(result.summary.sources.every((source) => source.failures.some((failure) => failure.includes('delegation is active'))));
  assert.equal(fake.methods.includes('debug_traceCall'), false);
  assert.equal(fake.methods.includes('eth_call'), false);
});

test('fully simulates an explicitly approved existing EIP-7702 delegated wallet', async () => {
  const delegateAddress = `0x${'44'.repeat(20)}`;
  const delegateCode = '0x6001600055';
  const enabledPolicy = structuredClone(policy);
  enabledPolicy.simulation.eip7702 = {
    allowAuthorizationList: false,
    allowDelegatedWallet: true,
    maxAuthorizations: 1,
    delegates: [{ chainId: 1, address: delegateAddress, codeHash: keccak256(delegateCode) }],
  };
  const fake = simulationFetch({ delegated: true, delegateAddress, delegateCode });
  const result = await simulateTransaction(enabledPolicy, intent, { rpcUrls, fetchImpl: fake.fetchImpl });
  assert.equal(result.valid, true);
  assert.equal(result.summary.metrics.eip7702.existingDelegate, delegateAddress);
  assert.ok(fake.methods.includes('debug_traceCall'));
});

test('fails closed when passing simulation sources disagree on trace effects', async () => {
  const fake = simulationFetch({ outputByHost: { 'primary.example': '0x01', 'secondary.example': '0x02' } });
  const result = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fake.fetchImpl });
  assert.equal(result.valid, false);
  assert.equal(result.checks.find((check) => check.id === 'simulation:consensus').status, 'deny');
});

test('fails closed when simulation endpoints are on the wrong chain', async () => {
  const fake = simulationFetch({ rpcChainId: '0x2' });
  const result = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fake.fetchImpl });
  assert.equal(result.valid, false);
  assert.equal(result.checks.find((check) => check.id === 'simulation:available').status, 'deny');
  assert.ok(result.summary.sources.every((source) => source.failures.some((failure) => failure.includes('does not match transaction chain'))));
});

test('denies a trace whose root does not match the exact proposed transaction', async () => {
  const fake = simulationFetch({ traceFrom: '0x2222222222222222222222222222222222222222' });
  const result = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fake.fetchImpl });
  assert.equal(result.valid, false);
  assert.ok(result.summary.sources.every((source) => source.failures.some((failure) => failure.includes('Trace root sender'))));
});

test('denies when simulation sources do not agree with the exact outer nonce', async () => {
  const fake = simulationFetch({ currentNonce: '0x8' });
  const result = await simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fake.fetchImpl });
  assert.equal(result.valid, false);
  assert.ok(result.summary.sources.every((source) => source.failures.some((failure) => failure.includes('does not match pending account nonce'))));
  assert.equal(fake.methods.includes('eth_call'), false);
});

test('fully simulates an opted-in EIP-7702 authorization after signature, nonce, and code-hash checks', async () => {
  const wallet = Wallet.createRandom();
  const delegateAddress = `0x${'44'.repeat(20)}`;
  const delegateCode = '0x6001600055';
  const authorization = wallet.authorizeSync({ chainId: 1, address: delegateAddress, nonce: 8 });
  const setCodeIntent = {
    ...intent,
    from: wallet.address,
    type: '0x4',
    authorizationList: [{
      chainId: '0x1',
      address: delegateAddress,
      nonce: '0x8',
      yParity: `0x${authorization.signature.yParity.toString(16)}`,
      r: authorization.signature.r,
      s: authorization.signature.s,
    }],
  };
  const enabledPolicy = structuredClone(policy);
  enabledPolicy.wallets = [wallet.address];
  enabledPolicy.simulation.eip7702 = {
    allowAuthorizationList: true,
    allowDelegatedWallet: false,
    maxAuthorizations: 1,
    delegates: [{ chainId: 1, address: delegateAddress, codeHash: keccak256(delegateCode) }],
  };
  const fake = simulationFetch({ delegateAddress, delegateCode });
  const result = await simulateTransaction(enabledPolicy, setCodeIntent, { rpcUrls, fetchImpl: fake.fetchImpl });
  assert.equal(result.valid, true);
  assert.equal(result.checks.find((check) => check.id === 'eip7702:security').status, 'pass');
  assert.equal(result.summary.metrics.codeChanges, 1);
  assert.equal(result.summary.metrics.unexpectedCodeChanges, 0);
  assert.ok(fake.methods.includes('debug_traceCall'));
});
