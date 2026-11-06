import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Contract, ContractFactory, Interface, JsonRpcProvider, Wallet, keccak256 } from 'ethers';
import { validatePolicy } from '../src/policy.js';
import { exportEd25519PrivateKey, exportEd25519PublicKey, SEPOLIA_CHAIN_ID } from '../src/sepolia-gateway-config.js';
import { rpc } from '../src/transaction-simulator.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ENV_FILE = path.join(ROOT, '.env.sepolia.local');
const DEPLOYMENT_FILE = path.join(ROOT, 'deployments', 'sepolia.json');
const ZERO_WORD = `0x${'0'.repeat(64)}`;

function artifact(name) {
  const target = path.join(ROOT, 'demo', 'artifacts', 'DemoMarket.sol', `${name}.json`);
  if (!fs.existsSync(target)) throw new Error(`Missing ${target}. Run npm run contracts:build first.`);
  const value = JSON.parse(fs.readFileSync(target, 'utf8'));
  return { abi: value.abi, bytecode: value.bytecode.object.startsWith('0x') ? value.bytecode.object : `0x${value.bytecode.object}` };
}

function randomSecret() { return crypto.randomBytes(32).toString('base64url'); }

async function prepare() {
  if (fs.existsSync(ENV_FILE)) throw new Error(`${ENV_FILE} already exists. Refusing to replace testnet keys.`);
  const wallet = Wallet.createRandom();
  const operations = crypto.generateKeyPairSync('ed25519').privateKey;
  const security = crypto.generateKeyPairSync('ed25519').privateKey;
  const lines = [
    '# WalletCordon Sepolia beta secrets. Never commit or paste into Vercel.',
    `WALLETCORDON_WALLET_PRIVATE_KEY=${wallet.privateKey}`,
    `WALLETCORDON_STATE_SIGNER_OPERATIONS=${exportEd25519PrivateKey(operations)}`,
    `WALLETCORDON_STATE_SIGNER_SECURITY=${exportEd25519PrivateKey(security)}`,
    `WALLETCORDON_GATEWAY_TOKEN=${randomSecret()}`,
    `WALLETCORDON_AGENT_API_KEYS=${randomSecret()}`,
    'WALLETCORDON_SEPOLIA_RPC_PRIMARY=',
    'WALLETCORDON_SEPOLIA_RPC_SECONDARY=',
    'WALLETCORDON_GATEWAY_CONFIG=deployments/sepolia.json',
    'WALLETCORDON_GATEWAY_DATA_DIR=.walletcordon/sepolia',
    '',
  ];
  await fsp.writeFile(ENV_FILE, lines.join('\n'), { mode: 0o600, flag: 'wx' });
  process.stdout.write(`Created ${ENV_FILE}\n`);
  process.stdout.write(`Disposable Sepolia wallet: ${wallet.address}\n`);
  process.stdout.write('Fund this address with Sepolia faucet ETH only. Then fill both independent trace-capable RPC URLs in the file and run npm run sepolia:deploy.\n');
}

async function probeRpc(url, walletAddress, label) {
  if (BigInt(await rpc(url, 'eth_chainId')) !== BigInt(SEPOLIA_CHAIN_ID)) throw new Error(`${label} is not Sepolia.`);
  const nonce = await rpc(url, 'eth_getTransactionCount', [walletAddress, 'pending']);
  const tx = { from: walletAddress, to: walletAddress, data: '0x', value: '0x0', gas: '0x5208', nonce, type: '0x2', maxFeePerGas: '0x2540be400', maxPriorityFeePerGas: '0x3b9aca00' };
  await rpc(url, 'debug_traceCall', [tx, 'latest', { tracer: 'callTracer', tracerConfig: { withLog: true } }], { timeoutMs: 20_000 });
  await rpc(url, 'debug_traceCall', [tx, 'latest', { tracer: 'prestateTracer', tracerConfig: { diffMode: true, disableCode: false, disableStorage: false } }], { timeoutMs: 20_000 });
}

async function deployContract(signer, name, args = []) {
  const value = artifact(name);
  const contract = await new ContractFactory(value.abi, value.bytecode, signer).deploy(...args);
  await contract.waitForDeployment();
  process.stdout.write(`Deployed ${name}: ${await contract.getAddress()}\n`);
  return contract;
}

function buildPolicy({ wallet, tokenIn, tokenOut, safeRouter, maliciousRouter, operations, security }) {
  const iface = new Interface(artifact('DemoRouter').abi);
  const maximumInput = (1_000n * 10n ** 18n).toString();
  const validUntil = new Date(Date.now() + 120 * 24 * 60 * 60 * 1000).toISOString();
  const contract = (address) => ({
    chainId: SEPOLIA_CHAIN_ID,
    address,
    protocolId: 'walletcordon-sepolia-dex',
    maxNativeValueWei: '0',
    methods: [{
      selector: iface.getFunction('swapExactTokensForTokens').selector,
      name: 'swapExactTokensForTokens(uint256,uint256,address)',
      maxGas: '350000',
      constraints: [
        { type: 'uint-max', argument: 0, value: maximumInput },
        { type: 'uint-min', argument: 1, value: '1' },
        { type: 'address-in', argument: 2, addresses: [wallet] },
      ],
    }],
  });
  return {
    version: 1,
    name: 'WalletCordon Sepolia beta policy',
    defaultAction: 'deny',
    chains: [SEPOLIA_CHAIN_ID],
    wallets: [wallet],
    validUntil,
    protocolState: {
      required: true, maxAgeSeconds: 180, maxClockSkewSeconds: 20, minimumSequence: 1, threshold: 2,
      trustedKeys: [
        { id: 'operations', algorithm: 'ed25519', publicKey: exportEd25519PublicKey(operations) },
        { id: 'security', algorithm: 'ed25519', publicKey: exportEd25519PublicKey(security) },
      ],
    },
    simulation: {
      required: true, blockTag: 'latest', timeoutMs: 20_000, quorum: 2, maxBlockSkew: 4,
      maxGasEstimate: '350000', maxCallDepth: 8, maxInternalCalls: 64, maxStateAccounts: 128,
      maxStorageWrites: 256, denyCodeChanges: true,
      eip7702: { allowAuthorizationList: false, allowDelegatedWallet: false, maxAuthorizations: 1, delegates: [] },
      allowedCallTypes: ['CALL', 'STATICCALL'], internalTargets: [],
      assetLimits: [
        { chainId: SEPOLIA_CHAIN_ID, token: tokenIn, maxOutflow: maximumInput, maxOutflowPerBlock: maximumInput, maxApproval: '0', allowedRecipients: [safeRouter, maliciousRouter], allowedSpenders: [] },
        { chainId: SEPOLIA_CHAIN_ID, token: tokenOut, maxOutflow: '0', maxApproval: '0', allowedRecipients: [], allowedSpenders: [] },
      ],
      sources: [
        { id: 'sepolia-primary', env: 'WALLETCORDON_SEPOLIA_RPC_PRIMARY' },
        { id: 'sepolia-secondary', env: 'WALLETCORDON_SEPOLIA_RPC_SECONDARY' },
      ],
    },
    invariants: {
      maxNativeValueWei: '0', maxGas: '350000', maxGasPriceWei: '200000000000',
      maxFeePerGasWei: '200000000000', maxPriorityFeePerGasWei: '10000000000',
      requireCalldata: true, denyUnlimitedApproval: true,
    },
    contracts: [contract(safeRouter), contract(maliciousRouter)],
  };
}

async function deploy() {
  const primary = process.env.WALLETCORDON_SEPOLIA_RPC_PRIMARY;
  const secondary = process.env.WALLETCORDON_SEPOLIA_RPC_SECONDARY;
  if (!primary || !secondary || primary === secondary) throw new Error('Configure two distinct trace-capable Sepolia RPC URLs.');
  const wallet = new Wallet(process.env.WALLETCORDON_WALLET_PRIVATE_KEY);
  await Promise.all([probeRpc(primary, wallet.address, 'Primary RPC'), probeRpc(secondary, wallet.address, 'Secondary RPC')]);
  const provider = new JsonRpcProvider(primary, SEPOLIA_CHAIN_ID, { staticNetwork: true });
  const signer = wallet.connect(provider);
  const balance = await provider.getBalance(wallet.address);
  if (balance < 5_000_000_000_000_000n) throw new Error(`Wallet ${wallet.address} needs at least 0.005 Sepolia ETH before deployment.`);

  const tokenInContract = await deployContract(signer, 'DemoToken', ['Demo USD', 'dUSD']);
  const tokenOutContract = await deployContract(signer, 'DemoToken', ['Demo Ether', 'dETH']);
  const unsafeContract = await deployContract(signer, 'UnsafeTarget');
  const tokenIn = await tokenInContract.getAddress();
  const tokenOut = await tokenOutContract.getAddress();
  const unsafeTarget = await unsafeContract.getAddress();
  const safe = await deployContract(signer, 'DemoRouter', [tokenIn, tokenOut, unsafeTarget]);
  const malicious = await deployContract(signer, 'DemoRouter', [tokenIn, tokenOut, unsafeTarget]);
  const safeRouter = await safe.getAddress();
  const maliciousRouter = await malicious.getAddress();
  await (await malicious.setUnsafeMode(true)).wait();

  const inputAmount = 100_000n * 10n ** 18n;
  const outputAmount = 200_000n * 10n ** 18n;
  await (await tokenInContract.mint(wallet.address, inputAmount)).wait();
  await (await tokenOutContract.mint(safeRouter, outputAmount)).wait();
  await (await tokenOutContract.mint(maliciousRouter, outputAmount)).wait();
  const inputAsWallet = new Contract(tokenIn, artifact('DemoToken').abi, signer);
  await (await inputAsWallet.approve(safeRouter, inputAmount)).wait();
  await (await inputAsWallet.approve(maliciousRouter, inputAmount)).wait();

  const operations = crypto.createPrivateKey({ key: Buffer.from(process.env.WALLETCORDON_STATE_SIGNER_OPERATIONS, 'base64'), format: 'der', type: 'pkcs8' });
  const security = crypto.createPrivateKey({ key: Buffer.from(process.env.WALLETCORDON_STATE_SIGNER_SECURITY, 'base64'), format: 'der', type: 'pkcs8' });
  const policy = buildPolicy({ wallet: wallet.address, tokenIn, tokenOut, safeRouter, maliciousRouter, operations, security });
  const validation = validatePolicy(policy, { activation: true });
  if (!validation.valid) throw new Error(`Generated policy is invalid: ${validation.errors.map((entry) => entry.message).join(' ')}`);
  const routerCodeHash = keccak256(await provider.getCode(safeRouter));
  if (routerCodeHash !== keccak256(await provider.getCode(maliciousRouter))) throw new Error('Router runtime code hashes differ.');
  const pausedData = new Interface(artifact('DemoRouter').abi).encodeFunctionData('paused');
  const monitor = {
    version: 1, chainId: SEPOLIA_CHAIN_ID, stateTtlSeconds: 180, rpcTimeoutMs: 12_000, rpcQuorum: 2, maxBlockSkew: 4,
    sources: [
      { id: 'sepolia-primary', env: 'WALLETCORDON_SEPOLIA_RPC_PRIMARY' },
      { id: 'sepolia-secondary', env: 'WALLETCORDON_SEPOLIA_RPC_SECONDARY' },
    ],
    protocols: [{
      id: 'walletcordon-sepolia-dex',
      contracts: [safeRouter, maliciousRouter].map((address) => ({ address, codeHash: routerCodeHash, calls: [{ data: pausedData, operator: 'equals', expected: ZERO_WORD }] })),
    }],
  };
  const deployment = {
    version: 1,
    network: { name: 'sepolia', chainId: SEPOLIA_CHAIN_ID, deployedAt: new Date().toISOString() },
    contracts: { tokenIn, tokenOut, safeRouter, maliciousRouter, unsafeTarget },
    policy,
    monitor,
  };
  await fsp.mkdir(path.dirname(DEPLOYMENT_FILE), { recursive: true });
  await fsp.writeFile(DEPLOYMENT_FILE, `${JSON.stringify(deployment, null, 2)}\n`, { flag: 'wx' });
  process.stdout.write(`Wrote reviewed deployment manifest: ${DEPLOYMENT_FILE}\n`);
  process.stdout.write(`Wallet: ${wallet.address}\nSafe router: ${safeRouter}\nTrace-denied router: ${maliciousRouter}\n`);
}

const command = process.argv[2];
if (command === 'prepare') await prepare();
else if (command === 'deploy') await deploy();
else throw new Error('Usage: node scripts/bootstrap-sepolia.js <prepare|deploy>');
