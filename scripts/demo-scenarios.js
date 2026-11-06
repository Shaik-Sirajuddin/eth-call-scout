import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { id, keccak256 } from 'ethers';
import { createAuditLog } from '../src/audit-log.js';
import { createGasRules } from '../src/gas-limits.js';
import { collectProtocolState } from '../src/protocol-monitor.js';
import { addProtocolStateSignature, signProtocolState } from '../src/protocol-state.js';
import { createGuardedProvider, WalletGuardError } from '../src/wallet-guard.js';

const policy = JSON.parse(fs.readFileSync(new URL('../examples/wallet-policy.json', import.meta.url), 'utf8'));
const intent = JSON.parse(fs.readFileSync(new URL('../examples/transaction-intent.json', import.meta.url), 'utf8'));
const monitor = JSON.parse(fs.readFileSync(new URL('../examples/protocol-monitor.demo.json', import.meta.url), 'utf8'));
const GOOD_CODE = '0x60016000';
const BAD_CODE = '0x60026000';
const ZERO_WORD = `0x${'0'.repeat(64)}`;
const ONE_WORD = `0x${'0'.repeat(63)}1`;
const rpcUrls = { primary: 'https://primary.demo.invalid', secondary: 'https://secondary.demo.invalid' };
const simulationUrls = { 'sim-primary': 'https://sim-primary.demo.invalid', 'sim-secondary': 'https://sim-secondary.demo.invalid' };
const APPROVAL_TOPIC = id('Approval(address,address,uint256)');
const topicAddress = (address) => `0x${address.slice(2).toLowerCase().padStart(64, '0')}`;
let simulationMode = 'safe';
// The demo chain reports empty code, so its rule pins that. The real rule set pins the live contract code.
const demoGasRules = createGasRules({
  version: 1,
  rulesVersion: 'demo',
  validUntil: '2100-01-01T00:00:00.000Z',
  rules: [{ chainId: 1, address: intent.to, protocolId: 'usdc', versionTag: 'usdc-erc20', selector: intent.data.slice(0, 10), maxGas: '100000', codeVersion: { codeHash: keccak256('0x'), implementation: null } }],
});
const simulatedGas = () => (simulationMode === 'wasteful-gas' ? '0x493e0' : '0xea60');

const signers = ['operations', 'security'].map((id) => {
  const pair = crypto.generateKeyPairSync('ed25519');
  return {
    id,
    privateKey: pair.privateKey,
    trusted: { id, algorithm: 'ed25519', publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') },
  };
});
policy.protocolState.trustedKeys = signers.map((signer) => signer.trusted);

function demoRpc(mode) {
  return async (_url, options) => {
    const request = JSON.parse(options.body);
    const result = request.method === 'eth_blockNumber' ? '0x16b23f0'
      : request.method === 'eth_getCode' ? (mode === 'compromised' ? BAD_CODE : GOOD_CODE)
        : request.method === 'eth_getStorageAt' ? ZERO_WORD
          : request.method === 'eth_call' ? ONE_WORD
            : null;
    if (result == null) throw new Error(`Unexpected demo RPC method ${request.method}`);
    const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }));
    return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
  };
}

async function signedState(sequence, mode, now = new Date()) {
  const payload = await collectProtocolState(monitor, { sequence, now, rpcUrls, fetchImpl: demoRpc(mode) });
  let bundle = { version: 1, payload, signatures: [] };
  for (const signer of signers) bundle = addProtocolStateSignature(bundle, signProtocolState(payload, { keyId: signer.id, privateKey: signer.privateKey }));
  return bundle;
}

async function simulationRpc(_url, options) {
  const request = JSON.parse(options.body);
  let result;
  if (request.method === 'eth_chainId') result = '0x1';
  else if (request.method === 'eth_blockNumber') result = '0x16b23f0';
  else if (request.method === 'eth_getTransactionCount') result = intent.nonce;
  else if (request.method === 'eth_getCode') result = '0x';
  else if (request.method === 'eth_call') result = '0x';
  else if (request.method === 'eth_estimateGas') result = simulatedGas();
  else if (request.method === 'debug_traceCall' && request.params[2].tracer === 'callTracer') {
    const child = simulationMode === 'unsafe-internal-call' ? [{
      type: 'CALL',
      from: intent.to,
      to: '0x3333333333333333333333333333333333333333',
      value: '0x0',
      input: '0x',
      output: '0x',
    }] : [];
    result = {
      type: 'CALL',
      from: intent.from,
      to: intent.to,
      value: '0x0',
      input: intent.data,
      output: '0x',
      gasUsed: simulatedGas(),
      logs: [{
        address: intent.to,
        topics: [APPROVAL_TOPIC, topicAddress(intent.from), topicAddress('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45')],
        data: `0x${(1_000_000_000n).toString(16).padStart(64, '0')}`,
      }],
      calls: child,
    };
  } else if (request.method === 'debug_traceCall' && request.params[2].tracer === 'prestateTracer') {
    result = {
      pre: { [intent.to.toLowerCase()]: { storage: { [ZERO_WORD]: ZERO_WORD } } },
      post: { [intent.to.toLowerCase()]: { storage: { [ZERO_WORD]: ONE_WORD } } },
    };
  } else throw new Error(`Unexpected simulation RPC method ${request.method}`);
  const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }));
  return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
}

const states = [
  await signedState(1, 'healthy'),
  await signedState(2, 'compromised'),
  await signedState(3, 'healthy'),
  await signedState(4, 'healthy'),
  await signedState(5, 'healthy'),
  await signedState(6, 'healthy', new Date(Date.now() - 10 * 60_000)),
];
const results = [];
let forwarded = 0;
let sequence = 0;
const auditDirectory = await fsp.mkdtemp(path.join(os.tmpdir(), 'callscout-demo-'));
const audit = createAuditLog(path.join(auditDirectory, 'receipts.jsonl'));
const wallet = {
  async request(request) {
    if (request.method === 'eth_chainId') return '0x1';
    if (request.method === 'eth_sendTransaction') { forwarded++; return `0xdemo${forwarded}`; }
    throw new Error(`Unexpected wallet RPC method ${request.method}`);
  },
};
const guard = createGuardedProvider({
  provider: wallet,
  policy,
  stateSource: async () => states.shift(),
  simulationOptions: { rpcUrls: simulationUrls, fetchImpl: simulationRpc, gasRules: demoGasRules },
  stateSequenceStore: {
    async read() { return sequence; },
    async write(next) { if (next < sequence) throw new Error('rollback'); sequence = next; },
  },
  onDecision: (receipt) => audit.append(receipt),
});

async function scenario(name, request, { simulation = 'safe' } = {}) {
  simulationMode = simulation;
  const before = forwarded;
  try {
    const transactionHash = await guard.request(request);
    results.push({ scenario: name, decision: 'allow', walletForwarded: forwarded > before, transactionHash });
  } catch (error) {
    if (!(error instanceof WalletGuardError)) throw error;
    const failed = error.receipt.checks.filter((check) => check.status === 'deny').map((check) => check.id);
    results.push({ scenario: name, decision: 'deny', walletForwarded: forwarded > before, failedChecks: failed });
  }
}

await scenario('Healthy protocol + bounded approval', { method: 'eth_sendTransaction', params: [intent] });
await scenario('Whitelisted but code hash changed', { method: 'eth_sendTransaction', params: [intent] });
const wrongSpender = structuredClone(intent);
wrongSpender.data = `${wrongSpender.data.slice(0, 34)}2222222222222222222222222222222222222222${wrongSpender.data.slice(74)}`;
await scenario('Healthy protocol + unapproved spender', { method: 'eth_sendTransaction', params: [wrongSpender] });
await scenario('Simulation reveals unauthorized internal call', { method: 'eth_sendTransaction', params: [intent] }, { simulation: 'unsafe-internal-call' });
await scenario('Valid call that wastes gas', { method: 'eth_sendTransaction', params: [{ ...intent, gas: '0x55730' }] }, { simulation: 'wasteful-gas' });
await scenario('Stale signed state', { method: 'eth_sendTransaction', params: [intent] });
await scenario('Opaque message signing request', { method: 'personal_sign', params: ['0xdeadbeef', intent.from] });

const auditStatus = await audit.verify();
await fsp.rm(auditDirectory, { recursive: true });
process.stdout.write(`${JSON.stringify({ product: 'CallScout', forwardedTransactions: forwarded, scenarios: results, audit: auditStatus }, null, 2)}\n`);
