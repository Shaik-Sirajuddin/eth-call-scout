import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createAuditLog } from '../src/audit-log.js';
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

const states = [
  await signedState(1, 'healthy'),
  await signedState(2, 'compromised'),
  await signedState(3, 'healthy'),
  await signedState(4, 'healthy', new Date(Date.now() - 10 * 60_000)),
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
  stateSequenceStore: {
    async read() { return sequence; },
    async write(next) { if (next < sequence) throw new Error('rollback'); sequence = next; },
  },
  onDecision: (receipt) => audit.append(receipt),
});

async function scenario(name, request) {
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
await scenario('Stale signed state', { method: 'eth_sendTransaction', params: [intent] });
await scenario('Opaque message signing request', { method: 'personal_sign', params: ['0xdeadbeef', intent.from] });

const auditStatus = await audit.verify();
await fsp.rm(auditDirectory, { recursive: true });
process.stdout.write(`${JSON.stringify({ product: 'CallScout', forwardedTransactions: forwarded, scenarios: results, audit: auditStatus }, null, 2)}\n`);
