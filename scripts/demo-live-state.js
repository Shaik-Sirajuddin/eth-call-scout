import crypto from 'node:crypto';
import fs from 'node:fs';
import { addProtocolStateSignature, signProtocolState } from '../src/protocol-state.js';
import { createGuardedProvider } from '../src/wallet-guard.js';

const policy = JSON.parse(fs.readFileSync(new URL('../examples/wallet-policy.json', import.meta.url), 'utf8'));
const intent = JSON.parse(fs.readFileSync(new URL('../examples/transaction-intent.json', import.meta.url), 'utf8'));

const signers = ['operations', 'security'].map((id) => {
  const pair = crypto.generateKeyPairSync('ed25519');
  return {
    id,
    privateKey: pair.privateKey,
    trusted: { id, algorithm: 'ed25519', publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') },
  };
});

policy.protocolState = {
  required: true,
  maxAgeSeconds: 300,
  maxClockSkewSeconds: 15,
  minimumSequence: 1,
  threshold: 2,
  trustedKeys: signers.map((signer) => signer.trusted),
};

const now = new Date();
const payload = {
  version: 1,
  sequence: 1,
  issuedAt: now.toISOString(),
  expiresAt: new Date(now.getTime() + 5 * 60_000).toISOString(),
  protocols: [{
    id: 'usdc',
    chainId: 1,
    status: 'operational',
    observedAt: now.toISOString(),
    contracts: [intent.to],
    blockNumber: '23800000',
    evidence: ['demo-code-hash-monitor', 'demo-incident-feed'],
  }],
};

let state = { version: 1, payload, signatures: [] };
for (const signer of signers) {
  const signature = signProtocolState(payload, { keyId: signer.id, privateKey: signer.privateKey });
  state = addProtocolStateSignature(state, signature);
}

let receipt;
const wallet = {
  async request(request) {
    if (request.method === 'eth_chainId') return '0x1';
    if (request.method === 'eth_sendTransaction') return '0xdemo-transaction-hash';
    throw new Error(`Unexpected demo RPC method: ${request.method}`);
  },
};
const guarded = createGuardedProvider({ provider: wallet, policy, protocolState: state, onDecision: (value) => { receipt = value; } });
const transactionHash = await guarded.request({ method: 'eth_sendTransaction', params: [intent] });
process.stdout.write(`${JSON.stringify({ transactionHash, receipt }, null, 2)}\n`);
