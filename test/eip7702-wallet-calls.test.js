import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { id, Interface, keccak256, Wallet } from 'ethers';
import { auditPolicy } from '../src/policy.js';
import { addProtocolStateSignature, signProtocolState } from '../src/protocol-state.js';
import { simulateTransaction } from '../src/transaction-simulator.js';
import { createGuardedProvider, WalletGuardError } from '../src/wallet-guard.js';

const example = JSON.parse(fs.readFileSync(new URL('../examples/wallet-policy.json', import.meta.url), 'utf8'));
const baseIntent = JSON.parse(fs.readFileSync(new URL('../examples/transaction-intent.json', import.meta.url), 'utf8'));
const NOW = new Date('2026-12-01T00:00:00.000Z');
const FIXED_WALLET = baseIntent.from;
const USDC = baseIntent.to;
const SPENDER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const ATTACKER = '0x000000000000000000000000000000000000bad0';
const VAULT = `0x${'55'.repeat(20)}`;
const DELEGATE = `0x${'44'.repeat(20)}`;
const DELEGATE_CODE = '0x6001600055';
const EXECUTE = id('execute(bytes32,bytes)').slice(0, 10);
const rpcUrls = { 'sim-primary': 'https://primary.example', 'sim-secondary': 'https://secondary.example' };
const token = new Interface(['function approve(address,uint256)', 'function balanceOf(address)', 'function setOperator(address)']);
const goodApprove = token.encodeFunctionData('approve', [SPENDER, 1_000_000_000n]);
const stateKeys = [crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519')];

function protocolState(wallet, { usdcStatus = 'operational' } = {}) {
  const at = NOW.toISOString();
  const payload = {
    version: 1,
    sequence: 7,
    issuedAt: at,
    expiresAt: '2026-12-01T00:05:00.000Z',
    protocols: [
      { id: 'usdc', chainId: 1, status: usdcStatus, observedAt: at, contracts: [USDC] },
      { id: 'agent-wallet', chainId: 1, status: 'operational', observedAt: at, contracts: [wallet] },
      { id: 'vault', chainId: 1, status: 'operational', observedAt: at, contracts: [VAULT] },
    ],
  };
  let bundle = { version: 1, payload, signatures: [] };
  stateKeys.forEach((keys, index) => {
    bundle = addProtocolStateSignature(bundle, signProtocolState(payload, { keyId: `batch-${index}`, privateKey: keys.privateKey }));
  });
  return bundle;
}

function batchPolicy(wallet, { allowAuthorizationList = false, requireCalldata = true } = {}) {
  const policy = structuredClone(example);
  policy.wallets = [wallet];
  policy.protocolState = {
    required: true,
    maxAgeSeconds: 300,
    threshold: 2,
    trustedKeys: stateKeys.map((keys, index) => ({
      id: `batch-${index}`,
      algorithm: 'ed25519',
      publicKey: keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    })),
  };
  policy.simulation.eip7702 = {
    allowAuthorizationList,
    allowDelegatedWallet: !allowAuthorizationList,
    maxAuthorizations: 1,
    delegates: [{ chainId: 1, address: DELEGATE, codeHash: keccak256(DELEGATE_CODE) }],
  };
  policy.invariants.requireCalldata = requireCalldata;
  policy.contracts[0].methods.push({ selector: token.getFunction('balanceOf').selector, name: 'balanceOf(address)', maxGas: '100000' });
  policy.contracts.push(
    { chainId: 1, address: wallet, protocolId: 'agent-wallet', maxNativeValueWei: '0', maxGas: '500000', methods: [{ selector: EXECUTE, name: 'execute(bytes32,bytes)' }] },
    { chainId: 1, address: VAULT, protocolId: 'vault', maxNativeValueWei: '1000', maxGas: '100000', allowEmptyCalldata: true },
  );
  return policy;
}

function batchIntent(wallet) {
  return { ...structuredClone(baseIntent), from: wallet, to: wallet, data: `${EXECUTE}${'00'.repeat(64)}` };
}

function frame(input, { type = 'CALL', from = FIXED_WALLET, to = USDC, value = '0x0', calls } = {}) {
  return { type, from, to, value, input, output: '0x', gasUsed: '0xc350', ...(calls ? { calls } : {}) };
}

function response(idValue, result) {
  const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: idValue, result }));
  return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
}

function fakeChain(frames, { wallet = FIXED_WALLET, existingDelegation = true } = {}) {
  return async (_url, options) => {
    const request = JSON.parse(options.body);
    if (request.method === 'eth_chainId') return response(request.id, '0x1');
    if (request.method === 'eth_blockNumber') return response(request.id, '0x100');
    if (request.method === 'eth_getTransactionCount') return response(request.id, '0x7');
    if (request.method === 'eth_getCode') {
      const address = request.params[0].toLowerCase();
      if (address === DELEGATE.toLowerCase()) return response(request.id, DELEGATE_CODE);
      if (address === wallet.toLowerCase()) return response(request.id, existingDelegation ? `0xef0100${DELEGATE.slice(2)}` : '0x');
      return response(request.id, '0x');
    }
    if (request.method === 'eth_call') return response(request.id, '0x');
    if (request.method === 'eth_estimateGas') return response(request.id, '0xea60');
    if (request.method === 'debug_traceCall' && request.params[2].tracer === 'callTracer') {
      const tx = request.params[0];
      return response(request.id, { type: 'CALL', from: tx.from, to: tx.to, value: tx.value, input: tx.data, output: '0x', gasUsed: '0xea60', calls: frames });
    }
    if (request.method === 'debug_traceCall' && request.params[2].tracer === 'prestateTracer') {
      const tx = request.params[0];
      const authorization = tx.authorizationList?.[0];
      return response(request.id, authorization ? {
        pre: { [tx.from.toLowerCase()]: { code: '0x' } },
        post: { [tx.from.toLowerCase()]: { code: `0xef0100${authorization.address.slice(2).toLowerCase()}` } },
      } : { pre: {}, post: {} });
    }
    throw new Error(`Unexpected RPC method ${request.method}`);
  };
}

function simulate(frames, { wallet = FIXED_WALLET, policy = batchPolicy(wallet), state = protocolState(wallet), intent = batchIntent(wallet), existingDelegation = true } = {}) {
  return simulateTransaction(policy, intent, { rpcUrls, fetchImpl: fakeChain(frames, { wallet, existingDelegation }), protocolState: state, now: NOW });
}

function failures(result) { return result.summary.sources.flatMap((source) => source.failures); }
function assertDenied(result, expected) {
  assert.equal(result.valid, false);
  assert.ok(failures(result).some((failure) => failure.includes(expected)), `Expected ${expected} in: ${failures(result).join(' | ')}`);
}

test('allows an existing delegated-wallet batch only when every wallet call passes', async () => {
  const result = await simulate([frame(goodApprove)]);
  assert.equal(result.valid, true);
  assert.deepEqual(result.summary.metrics.walletCalls, [{ type: 'CALL', to: USDC.toLowerCase(), value: '0', selector: '0x095ea7b3' }]);
});

test('denies hidden methods and calldata violations inside delegated-wallet batches', async () => {
  assertDenied(await simulate([frame(token.encodeFunctionData('setOperator', [ATTACKER]))]), 'method:allowlisted');
  assertDenied(await simulate([frame(token.encodeFunctionData('approve', [ATTACKER, 1n]))]), 'constraint:0:address-in');
  assertDenied(await simulate([frame(token.encodeFunctionData('approve', [SPENDER, (1n << 256n) - 1n]))]), 'erc20:no-unlimited-approval');
});

test('requires exact contract policy and live state for wallet-originated STATICCALL', async () => {
  const read = frame(token.encodeFunctionData('balanceOf', [FIXED_WALLET]), { type: 'STATICCALL' });
  assert.equal((await simulate([read])).valid, true);
  assertDenied(await simulate([read], { state: protocolState(FIXED_WALLET, { usdcStatus: 'paused' }) }), 'state:operational');

  const policy = batchPolicy(FIXED_WALLET);
  policy.simulation.internalTargets.push({ chainId: 1, address: VAULT });
  policy.contracts = policy.contracts.filter((contract) => contract.address.toLowerCase() !== VAULT.toLowerCase());
  assertDenied(await simulate([frame('0x12345678', { type: 'STATICCALL', to: VAULT })], { policy }), 'target:allowlisted');
});

test('denies DELEGATECALL and CALLCODE originating from the wallet', async () => {
  for (const type of ['DELEGATECALL', 'CALLCODE']) assertDenied(await simulate([frame('0x', { type })]), `saw ${type}`);
});

test('aggregates native value per target across a delegated-wallet batch', async () => {
  const policy = batchPolicy(FIXED_WALLET, { requireCalldata: false });
  assert.equal((await simulate([frame('0x', { to: VAULT, value: '0x2bc' })], { policy })).valid, true);
  assertDenied(await simulate([frame('0x', { to: VAULT, value: '0x2bc' }), frame('0x', { to: VAULT, value: '0x2bc' })], { policy }), 'value:contract-limit');
});

test('checks a fresh type-4 delegation that executes a wallet batch in the same transaction', async () => {
  const wallet = Wallet.createRandom();
  const authorization = wallet.authorizeSync({ chainId: 1, address: DELEGATE, nonce: 8 });
  const intent = {
    ...batchIntent(wallet.address),
    type: '0x4',
    authorizationList: [{
      chainId: '0x1', address: DELEGATE, nonce: '0x8',
      yParity: authorization.signature.yParity, r: authorization.signature.r, s: authorization.signature.s,
    }],
  };
  const options = { wallet: wallet.address, policy: batchPolicy(wallet.address, { allowAuthorizationList: true }), state: protocolState(wallet.address), intent, existingDelegation: false };
  assert.equal((await simulate([frame(goodApprove, { from: wallet.address })], options)).valid, true);
  assertDenied(await simulate([frame(token.encodeFunctionData('setOperator', [ATTACKER]), { from: wallet.address })], options), 'method:allowlisted');
});

test('the wallet guard forwards only a delegated batch whose live-state-bound calls pass', async () => {
  const requests = [];
  const provider = { async request(request) { requests.push(request.method); return request.method === 'eth_chainId' ? '0x1' : '0xhash'; } };
  const state = protocolState(FIXED_WALLET);
  const policy = batchPolicy(FIXED_WALLET);
  const guard = createGuardedProvider({
    verification: false,
    provider,
    policy,
    protocolState: state,
    now: NOW,
    simulationOptions: { rpcUrls, fetchImpl: fakeChain([frame(token.encodeFunctionData('setOperator', [ATTACKER]))]) },
  });
  await assert.rejects(guard.request({ method: 'eth_sendTransaction', params: [batchIntent(FIXED_WALLET)] }), WalletGuardError);
  assert.ok(!requests.includes('eth_sendTransaction'));

  const safeGuard = createGuardedProvider({
    verification: false,
    provider,
    policy,
    protocolState: state,
    now: NOW,
    simulationOptions: { rpcUrls, fetchImpl: fakeChain([frame(goodApprove)]) },
  });
  assert.equal(await safeGuard.request({ method: 'eth_sendTransaction', params: [batchIntent(FIXED_WALLET)] }), '0xhash');
  assert.ok(requests.includes('eth_sendTransaction'));
});

test('audit warns when new delegation is enabled but later delegated-wallet use is disabled', () => {
  const policy = batchPolicy(FIXED_WALLET, { allowAuthorizationList: true });
  assert.ok(auditPolicy(policy).findings.some((finding) => finding.code === 'eip7702-wallet-lockout'));
});
