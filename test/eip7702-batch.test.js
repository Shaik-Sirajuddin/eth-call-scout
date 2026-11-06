import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { id, Interface, keccak256 } from 'ethers';
import { auditPolicy } from '../src/policy.js';
import { addProtocolStateSignature, signProtocolState } from '../src/protocol-state.js';
import { simulateTransaction } from '../src/transaction-simulator.js';
import { createGuardedProvider, WalletGuardError } from '../src/wallet-guard.js';

const example = JSON.parse(fs.readFileSync(new URL('../examples/wallet-policy.json', import.meta.url), 'utf8'));
const intent = JSON.parse(fs.readFileSync(new URL('../examples/transaction-intent.json', import.meta.url), 'utf8'));
const NOW = new Date('2026-12-01T00:00:00.000Z');
const WALLET = intent.from;
const USDC = intent.to;
const SPENDER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const ATTACKER = '0x000000000000000000000000000000000000bad0';
const VAULT = `0x${'55'.repeat(20)}`;
const DELEGATE = `0x${'44'.repeat(20)}`;
const DELEGATE_CODE = '0x6001600055';
const EXECUTE = id('execute(bytes32,bytes)').slice(0, 10);
const RUN_ALL = id('runAll(address[],bytes[])').slice(0, 10);
const rpcUrls = { 'sim-primary': 'https://primary.example', 'sim-secondary': 'https://secondary.example' };
const token = new Interface(['function approve(address,uint256)', 'function balanceOf(address)', 'function setOperator(address)']);
const account = new Interface(['function addOwner(address)']);
const goodApprove = token.encodeFunctionData('approve', [SPENDER, 1_000_000_000n]);
const batchTx = { ...intent, to: WALLET, data: `${EXECUTE}${'00'.repeat(64)}` };
const stateKeys = [crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519')];

function signedState({ usdcStatus = 'operational' } = {}) {
  const at = NOW.toISOString();
  const observation = (protocolId, status, contracts) => ({ id: protocolId, chainId: 1, status, observedAt: at, contracts });
  const payload = {
    version: 1,
    sequence: 1,
    issuedAt: at,
    expiresAt: '2026-12-01T00:05:00.000Z',
    protocols: [observation('usdc', usdcStatus, [USDC]), observation('agent-wallet', 'operational', [WALLET]), observation('vault', 'operational', [VAULT])],
  };
  let bundle = { version: 1, payload, signatures: [] };
  stateKeys.forEach((keys, index) => {
    bundle = addProtocolStateSignature(bundle, signProtocolState(payload, { keyId: `test-${index}`, privateKey: keys.privateKey }));
  });
  return bundle;
}

function batchPolicy({ requireCalldata = true } = {}) {
  const policy = structuredClone(example);
  policy.protocolState = {
    required: true,
    maxAgeSeconds: 300,
    threshold: 2,
    trustedKeys: stateKeys.map((keys, index) => ({ id: `test-${index}`, algorithm: 'ed25519', publicKey: keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') })),
  };
  policy.simulation.eip7702 = {
    allowAuthorizationList: false,
    allowDelegatedWallet: true,
    maxAuthorizations: 1,
    delegates: [{ chainId: 1, address: DELEGATE, codeHash: keccak256(DELEGATE_CODE) }],
  };
  policy.invariants.requireCalldata = requireCalldata;
  policy.contracts[0].methods.push({ selector: token.getFunction('balanceOf').selector, name: 'balanceOf(address)' });
  policy.contracts.push(
    { chainId: 1, address: WALLET, protocolId: 'agent-wallet', maxNativeValueWei: '0', methods: [{ selector: EXECUTE, name: 'execute(bytes32,bytes)' }, { selector: RUN_ALL, name: 'runAll(address[],bytes[])' }] },
    { chainId: 1, address: VAULT, protocolId: 'vault', maxNativeValueWei: '1000', allowEmptyCalldata: true },
  );
  return policy;
}

const frame = (input, { type = 'CALL', from = WALLET, to = USDC, value = '0x0' } = {}) => ({ type, from, to, value, input, output: '0x' });

/** A delegated wallet on a fake chain whose simulated call tree contains the given frames. */
function fakeChain(frames) {
  return async (url, options) => {
    const request = JSON.parse(options.body);
    const results = {
      eth_chainId: () => '0x1',
      eth_blockNumber: () => '0x100',
      eth_getTransactionCount: () => '0x7',
      eth_getCode: () => (request.params[0].toLowerCase() === DELEGATE ? DELEGATE_CODE : `0xef0100${DELEGATE.slice(2)}`),
      eth_call: () => '0x',
      eth_estimateGas: () => '0x30d40',
      debug_traceCall: () => {
        if (request.params[2].tracer === 'prestateTracer') return { pre: {}, post: {} };
        const tx = request.params[0];
        return { type: 'CALL', from: tx.from, to: tx.to, value: '0x0', input: tx.data, output: '0x', calls: frames };
      },
    };
    const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: results[request.method]() }));
    return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
  };
}

function simulate(frames, { policy = batchPolicy(), state = signedState(), tx = batchTx } = {}) {
  return simulateTransaction(policy, tx, { rpcUrls, fetchImpl: fakeChain(frames), protocolState: state, now: NOW });
}

const failures = (result) => result.summary.sources.flatMap((source) => source.failures);
const assertDenied = (result, expected) => {
  assert.equal(result.valid, false);
  assert.ok(failures(result).some((failure) => failure.includes(expected)), `expected "${expected}" in: ${failures(result).join(' | ')}`);
};

test('allows a delegated wallet batch whose calls all pass policy and records them', async () => {
  const result = await simulate([frame(goodApprove)]);
  assert.equal(result.valid, true);
  assert.deepEqual(result.summary.metrics.walletCalls, [{ type: 'CALL', to: USDC.toLowerCase(), value: '0', selector: '0x095ea7b3' }]);
});

test('denies a method hidden in a batch even when it emits no token event', async () => {
  assertDenied(await simulate([frame(goodApprove), frame(token.encodeFunctionData('setOperator', [ATTACKER]))]), 'method:allowlisted');
});

test('checks hidden calls the same way for any batch function the delegate uses', async () => {
  const tx = { ...batchTx, data: `${RUN_ALL}${'00'.repeat(64)}` };
  assertDenied(await simulate([frame(token.encodeFunctionData('setOperator', [ATTACKER]))], { tx }), 'method:allowlisted');
});

test('applies ABI constraints to calls inside a batch without relying on emitted events', async () => {
  assertDenied(await simulate([frame(token.encodeFunctionData('approve', [ATTACKER, 1n]))]), 'constraint:0:address-in');
  assertDenied(await simulate([frame(token.encodeFunctionData('approve', [SPENDER, 1_000_000_001n]))]), 'constraint:1:uint-max');
});

test('blocks unlimited approval inside a batch', async () => {
  assertDenied(await simulate([frame(token.encodeFunctionData('approve', [SPENDER, (1n << 256n) - 1n]))]), 'erc20:no-unlimited-approval');
});

test('denies a nested self-call to a wallet function policy does not list', async () => {
  assertDenied(await simulate([frame(account.encodeFunctionData('addOwner', [ATTACKER]), { to: WALLET })]), 'method:allowlisted');
});

test('requires a full contract entry: internalTargets does not permit a call sent by the wallet', async () => {
  const policy = batchPolicy();
  policy.simulation.internalTargets.push({ chainId: 1, address: VAULT });
  policy.contracts = policy.contracts.filter((contract) => contract.address !== VAULT);
  assertDenied(await simulate([frame(goodApprove, { to: VAULT })], { policy }), 'target:allowlisted');
});

test('denies DELEGATECALL and CALLCODE from the wallet even when policy allows those call types', async () => {
  for (const type of ['DELEGATECALL', 'CALLCODE']) {
    const policy = batchPolicy();
    policy.simulation.allowedCallTypes = ['CALL', 'STATICCALL', 'DELEGATECALL', 'CALLCODE'];
    assertDenied(await simulate([frame('0x', { type })], { policy }), `saw ${type}`);
  }
});

test('allows read-only calls from the wallet to an allowed target', async () => {
  const result = await simulate([frame(token.encodeFunctionData('balanceOf', [WALLET]), { type: 'STATICCALL' })]);
  assert.equal(result.valid, true);
});

test('adds native value per target across a batch', async () => {
  const policy = batchPolicy({ requireCalldata: false });
  assert.equal((await simulate([frame('0x', { to: VAULT, value: '0x2bc' })], { policy })).valid, true);
  assertDenied(await simulate([frame('0x', { to: VAULT, value: '0x2bc' }), frame('0x', { to: VAULT, value: '0x2bc' })], { policy }), 'value:contract-limit');
});

test('applies the live-state veto to calls inside a batch', async () => {
  assertDenied(await simulate([frame(goodApprove)], { state: signedState({ usdcStatus: 'paused' }) }), 'state:operational');
  assertDenied(await simulate([frame(goodApprove)], { state: null }), 'state:present');
});

test('leaves calls made by other contracts to the existing internal-call rules', async () => {
  const policy = batchPolicy();
  const implementation = `0x${'66'.repeat(20)}`;
  policy.simulation.internalTargets.push({ chainId: 1, address: implementation });
  const proxyCall = frame(goodApprove, { type: 'DELEGATECALL', from: USDC, to: implementation });
  const result = await simulate([{ ...frame(goodApprove), calls: [proxyCall] }], { policy });
  assert.equal(result.valid, true);
});

test('the guard never forwards a batch that hides a disallowed call', async () => {
  const requests = [];
  const provider = { async request(request) { requests.push(request.method); return request.method === 'eth_chainId' ? '0x1' : '0xhash'; } };
  const guardFor = (frames, state = signedState()) => createGuardedProvider({ provider, policy: batchPolicy(), protocolState: state, now: NOW, simulationOptions: { rpcUrls, fetchImpl: fakeChain(frames) } });
  const request = { method: 'eth_sendTransaction', params: [batchTx] };

  await assert.rejects(guardFor([frame(token.encodeFunctionData('setOperator', [ATTACKER]))]).request(request), WalletGuardError);
  await assert.rejects(guardFor([frame(goodApprove)], signedState({ usdcStatus: 'paused' })).request(request), WalletGuardError);
  assert.ok(!requests.includes('eth_sendTransaction'));

  assert.equal(await guardFor([frame(goodApprove)]).request(request), '0xhash');
  assert.ok(requests.includes('eth_sendTransaction'));
});

test('the guard gives the simulator the live state it just evaluated', async () => {
  const provider = { async request() { return '0x1'; } };
  const state = signedState();
  let received;
  const simulator = async (_policy, _intent, options) => {
    received = options;
    return { valid: false, checks: [{ id: 'simulation:policy', status: 'deny', detail: 'test' }], summary: {} };
  };
  const guard = createGuardedProvider({ provider, policy: batchPolicy(), protocolState: state, now: NOW, simulator, simulationOptions: { rpcUrls } });
  await assert.rejects(guard.request({ method: 'eth_sendTransaction', params: [batchTx] }), WalletGuardError);
  assert.equal(received.protocolState, state);
  assert.equal(received.minimumStateSequence, 1);
  assert.equal(received.now, NOW);
  assert.equal(received.rpcUrls, rpcUrls);
});

test('audit warns when a policy allows upgrading but not using the upgraded wallet', () => {
  const policy = batchPolicy();
  assert.ok(!auditPolicy(policy).findings.some((finding) => finding.code === 'eip7702-wallet-lockout'));
  policy.simulation.eip7702.allowAuthorizationList = true;
  policy.simulation.eip7702.allowDelegatedWallet = false;
  assert.ok(auditPolicy(policy).findings.some((finding) => finding.code === 'eip7702-wallet-lockout'));
});
