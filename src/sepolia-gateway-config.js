import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { Wallet } from 'ethers';
import { validatePolicy } from './policy.js';
import { validateMonitorConfig } from './protocol-monitor.js';
import { validateUrl } from './transaction-simulator.js';

export const SEPOLIA_CHAIN_ID = 11_155_111;
const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const ALLOWED_CONFIG_KEYS = new Set(['version', 'network', 'contracts', 'policy', 'monitor']);
const ALLOWED_CONTRACT_KEYS = new Set(['tokenIn', 'tokenOut', 'safeRouter', 'maliciousRouter', 'unsafeTarget']);

function requireSecret(name, minimum = 32) {
  const value = process.env[name];
  if (typeof value !== 'string' || value.length < minimum) throw new Error(`${name} must be configured with at least ${minimum} characters.`);
  return value;
}

function readPrivateKey(name) {
  const encoded = requireSecret(name, 40);
  let key;
  try {
    key = crypto.createPrivateKey({ key: Buffer.from(encoded, 'base64'), format: 'der', type: 'pkcs8' });
  } catch { throw new Error(`${name} must be a base64 PKCS#8 private key.`); }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error(`${name} must contain an Ed25519 private key.`);
  return key;
}

function publicKeyBase64(privateKey) {
  return crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64');
}

function validateTopLevel(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Gateway config must be an object.');
  for (const key of Object.keys(config)) if (!ALLOWED_CONFIG_KEYS.has(key)) throw new Error(`Unknown Gateway config field ${key}.`);
  if (config.version !== 1) throw new Error('Gateway config version must be 1.');
  if (config.network?.name !== 'sepolia' || config.network?.chainId !== SEPOLIA_CHAIN_ID) throw new Error('Gateway config must pin Ethereum Sepolia chain 11155111.');
  if (!config.contracts || typeof config.contracts !== 'object' || Array.isArray(config.contracts)) throw new Error('Gateway config requires contracts.');
  for (const key of Object.keys(config.contracts)) if (!ALLOWED_CONTRACT_KEYS.has(key)) throw new Error(`Unknown Gateway contract ${key}.`);
  for (const key of ALLOWED_CONTRACT_KEYS) if (!ADDRESS.test(String(config.contracts[key] ?? ''))) throw new Error(`Gateway contract ${key} must be an address.`);
  if (new Set(Object.values(config.contracts).map((value) => value.toLowerCase())).size !== ALLOWED_CONTRACT_KEYS.size) throw new Error('Gateway contract addresses must be unique.');
}

function validateSecurityPosture(config, wallet, stateSigners) {
  const activation = validatePolicy(config.policy, { activation: true });
  if (!activation.valid) throw new Error(`Sepolia policy is invalid:\n${activation.errors.map((entry) => `${entry.path}: ${entry.message}`).join('\n')}`);
  const monitor = validateMonitorConfig(config.monitor);
  if (!monitor.valid) throw new Error(`Sepolia monitor is invalid:\n${monitor.errors.map((entry) => `${entry.path}: ${entry.message}`).join('\n')}`);
  if (!config.policy.chains.includes(SEPOLIA_CHAIN_ID) || config.policy.chains.length !== 1) throw new Error('Sepolia policy must contain only chain 11155111.');
  if (config.policy.wallets.length !== 1 || config.policy.wallets[0].toLowerCase() !== wallet.address.toLowerCase()) throw new Error('Sepolia policy must bind only the configured signer wallet.');
  if (config.policy.simulation?.eip7702?.allowAuthorizationList !== false || config.policy.simulation?.eip7702?.allowDelegatedWallet !== false) throw new Error('Sepolia beta requires EIP-7702 to remain denied.');
  if (config.monitor.chainId !== SEPOLIA_CHAIN_ID) throw new Error('Sepolia monitor has the wrong chain.');
  const trusted = new Map(config.policy.protocolState.trustedKeys.map((key) => [key.id, key]));
  const signerPublicKeys = stateSigners.map((signer) => publicKeyBase64(signer.privateKey));
  if (new Set(signerPublicKeys).size !== stateSigners.length) throw new Error('Protocol-state signers must use distinct Ed25519 keys.');
  for (const signer of stateSigners) {
    const pinned = trusted.get(signer.id);
    if (!pinned || pinned.algorithm !== 'ed25519' || pinned.publicKey !== publicKeyBase64(signer.privateKey)) {
      throw new Error(`Protocol-state signer ${signer.id} does not match the public key pinned in policy.`);
    }
  }
  if (trusted.size !== stateSigners.length || config.policy.protocolState.threshold !== stateSigners.length) throw new Error('Sepolia beta requires both configured state signers and a full threshold.');
  const policyTargets = new Set(config.policy.contracts.map((contract) => contract.address.toLowerCase()));
  for (const router of [config.contracts.safeRouter, config.contracts.maliciousRouter]) {
    if (!policyTargets.has(router.toLowerCase())) throw new Error(`Policy does not include router ${router}.`);
  }
}

export async function loadSepoliaGatewayEnvironment() {
  if (process.env.VERCEL) throw new Error('The signer Gateway must not run inside Vercel. Deploy it as an isolated persistent service.');
  const configPath = path.resolve(process.env.WALLETCORDON_GATEWAY_CONFIG ?? 'deployments/sepolia.json');
  const bytes = await fs.readFile(configPath);
  if (bytes.length > 1_000_000) throw new Error('Gateway config exceeds 1 MB.');
  const config = JSON.parse(bytes.toString('utf8'));
  validateTopLevel(config);

  const walletSecret = requireSecret('WALLETCORDON_WALLET_PRIVATE_KEY', 64);
  let wallet;
  try { wallet = new Wallet(walletSecret); }
  catch { throw new Error('WALLETCORDON_WALLET_PRIVATE_KEY is not a valid Ethereum private key.'); }
  const stateSigners = [
    { id: 'operations', privateKey: readPrivateKey('WALLETCORDON_STATE_SIGNER_OPERATIONS') },
    { id: 'security', privateKey: readPrivateKey('WALLETCORDON_STATE_SIGNER_SECURITY') },
  ];
  validateSecurityPosture(config, wallet, stateSigners);

  const rpcUrls = {
    'sepolia-primary': validateUrl(requireSecret('WALLETCORDON_SEPOLIA_RPC_PRIMARY', 12)).href,
    'sepolia-secondary': validateUrl(requireSecret('WALLETCORDON_SEPOLIA_RPC_SECONDARY', 12)).href,
  };
  if (rpcUrls['sepolia-primary'] === rpcUrls['sepolia-secondary']) throw new Error('Sepolia RPC sources must be independent URLs.');

  return {
    config,
    configPath,
    wallet,
    stateSigners,
    rpcUrls,
    serviceToken: requireSecret('WALLETCORDON_GATEWAY_TOKEN'),
    runtimeDirectory: path.resolve(process.env.WALLETCORDON_GATEWAY_DATA_DIR ?? '.walletcordon/sepolia'),
  };
}

export function exportEd25519PrivateKey(key) {
  return key.export({ format: 'der', type: 'pkcs8' }).toString('base64');
}

export function exportEd25519PublicKey(key) {
  return publicKeyBase64(key);
}
