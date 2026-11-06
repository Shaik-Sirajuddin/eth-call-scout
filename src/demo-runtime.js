import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  Contract,
  ContractFactory,
  Interface,
  JsonRpcProvider,
  formatUnits,
  keccak256,
  toBeHex,
} from 'ethers';
import { createAuditLog } from './audit-log.js';
import { parseDemoTradePrompt } from './demo-agent.js';
import { auditPolicy, sha256, validatePolicy } from './policy.js';
import { collectProtocolState } from './protocol-monitor.js';
import { addProtocolStateSignature, signProtocolState } from './protocol-state.js';
import { createGuardedProvider, WalletGuardError } from './wallet-guard.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DEMO_ROOT = path.join(ROOT, 'demo');
const RUNTIME_ROOT = path.join(DEMO_ROOT, 'runtime');
const CHAIN_ID = 31_337;
const DEFAULT_MNEMONIC = 'test test test test test test test test test test test junk';
const ZERO_WORD = `0x${'0'.repeat(64)}`;
const RUN_SCENARIOS = new Set(['safe', 'compromised', 'hidden-call', 'slippage']);

function artifactPath(contract) {
  return path.join(DEMO_ROOT, 'artifacts', 'DemoMarket.sol', `${contract}.json`);
}

function readArtifact(contract) {
  const target = artifactPath(contract);
  if (!fs.existsSync(target)) throw new Error(`Missing ${target}. Run npm run demo:build first.`);
  const artifact = JSON.parse(fs.readFileSync(target, 'utf8'));
  const object = artifact.bytecode?.object;
  if (typeof object !== 'string' || !object.length) throw new Error(`Artifact ${contract} has no deployable bytecode.`);
  return { abi: artifact.abi, bytecode: object.startsWith('0x') ? object : `0x${object}` };
}

function jsonSafe(value) {
  return JSON.parse(JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? item.toString() : item));
}

async function rpc(url, method, params = []) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const payload = await response.json();
  if (!response.ok || payload.error) throw new Error(payload.error?.message ?? `RPC ${response.status}`);
  return payload.result;
}

async function waitForRpc(url, child, timeoutMs = 12_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (child?.exitCode != null) throw new Error(`Anvil ${child.label ?? ''} exited with code ${child.exitCode}${child.failureDetail?.() ? `: ${child.failureDetail()}` : '.'}`);
    try {
      if (await rpc(url, 'eth_chainId') === toBeHex(CHAIN_ID)) return;
    } catch { /* Retry while Anvil starts. */ }
    await new Promise((resolve) => setTimeout(resolve, 80));
  }
  throw new Error(`Timed out waiting for Anvil at ${url}.`);
}

function startAnvil(port, label) {
  const executable = process.env.ANVIL_BIN || 'anvil';
  const child = spawn(executable, [
    '--host', '127.0.0.1',
    '--port', String(port),
    '--chain-id', String(CHAIN_ID),
    '--mnemonic', DEFAULT_MNEMONIC,
    '--silent',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-4000); });
  child.label = label;
  child.failureDetail = () => stderr.trim();
  return child;
}

async function deployContract(signer, name, args = []) {
  const artifact = readArtifact(name);
  const contract = await new ContractFactory(artifact.abi, artifact.bytecode, signer).deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

async function deployDemoChain(url) {
  const provider = new JsonRpcProvider(url, CHAIN_ID, { staticNetwork: true });
  const deployer = await provider.getSigner(0);
  const walletSigner = await provider.getSigner(1);
  const wallet = await walletSigner.getAddress();
  const tokenIn = await deployContract(deployer, 'DemoToken', ['Demo USD', 'dUSD']);
  const tokenOut = await deployContract(deployer, 'DemoToken', ['Demo Ether', 'dETH']);
  const unsafeTarget = await deployContract(deployer, 'UnsafeTarget');
  const router = await deployContract(deployer, 'DemoRouter', [await tokenIn.getAddress(), await tokenOut.getAddress(), await unsafeTarget.getAddress()]);
  const inputAmount = 10_000n * 10n ** 18n;
  const outputAmount = 20_000n * 10n ** 18n;
  await (await tokenIn.mint(wallet, inputAmount)).wait();
  await (await tokenOut.mint(await router.getAddress(), outputAmount)).wait();
  await (await new Contract(await tokenIn.getAddress(), readArtifact('DemoToken').abi, walletSigner).approve(await router.getAddress(), inputAmount)).wait();
  const snapshot = await provider.send('evm_snapshot', []);
  return {
    url,
    provider,
    deployer,
    walletSigner,
    wallet,
    contracts: {
      tokenIn: await tokenIn.getAddress(),
      tokenOut: await tokenOut.getAddress(),
      unsafeTarget: await unsafeTarget.getAddress(),
      router: await router.getAddress(),
    },
    router: new Contract(await router.getAddress(), readArtifact('DemoRouter').abi, deployer),
    snapshot,
  };
}

function assertMatchingDeployments(primary, secondary) {
  if (primary.wallet.toLowerCase() !== secondary.wallet.toLowerCase()) throw new Error('Anvil wallet addresses do not match.');
  for (const [name, address] of Object.entries(primary.contracts)) {
    if (address.toLowerCase() !== secondary.contracts[name].toLowerCase()) throw new Error(`Anvil ${name} deployments do not match.`);
  }
}

function createStateSigners() {
  return ['operations', 'security'].map((id) => {
    const pair = crypto.generateKeyPairSync('ed25519');
    return {
      id,
      privateKey: pair.privateKey,
      trusted: {
        id,
        algorithm: 'ed25519',
        publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      },
    };
  });
}

function buildPolicy(deployment, stateSigners) {
  const routerInterface = new Interface(readArtifact('DemoRouter').abi);
  const maximumInput = (1_000n * 10n ** 18n).toString();
  return {
    version: 1,
    name: 'ETHGlobal dual-Anvil trading agent',
    defaultAction: 'deny',
    chains: [CHAIN_ID],
    wallets: [deployment.wallet],
    validUntil: '2035-01-01T00:00:00.000Z',
    protocolState: {
      required: true,
      maxAgeSeconds: 120,
      maxClockSkewSeconds: 15,
      minimumSequence: 1,
      threshold: 2,
      trustedKeys: stateSigners.map((signer) => signer.trusted),
    },
    simulation: {
      required: true,
      blockTag: 'pending',
      timeoutMs: 12_000,
      quorum: 2,
      maxBlockSkew: 1,
      maxGasEstimate: '350000',
      maxCallDepth: 8,
      maxInternalCalls: 64,
      maxStateAccounts: 128,
      maxStorageWrites: 256,
      denyCodeChanges: true,
      eip7702: { allowAuthorizationList: false, allowDelegatedWallet: false, maxAuthorizations: 1, delegates: [] },
      allowedCallTypes: ['CALL', 'STATICCALL'],
      internalTargets: [],
      assetLimits: [
        {
          chainId: CHAIN_ID,
          token: deployment.contracts.tokenIn,
          maxOutflow: maximumInput,
          maxApproval: '0',
          allowedRecipients: [deployment.contracts.router],
          allowedSpenders: [],
        },
        {
          chainId: CHAIN_ID,
          token: deployment.contracts.tokenOut,
          maxOutflow: '0',
          maxApproval: '0',
          allowedRecipients: [],
          allowedSpenders: [],
        },
      ],
      sources: [
        { id: 'anvil-primary', env: 'CALLSCOUT_DEMO_SIM_PRIMARY' },
        { id: 'anvil-secondary', env: 'CALLSCOUT_DEMO_SIM_SECONDARY' },
      ],
    },
    invariants: {
      maxNativeValueWei: '0',
      maxGas: '350000',
      maxGasPriceWei: '100000000000',
      maxFeePerGasWei: '100000000000',
      maxPriorityFeePerGasWei: '5000000000',
      requireCalldata: true,
      denyUnlimitedApproval: true,
    },
    contracts: [{
      chainId: CHAIN_ID,
      address: deployment.contracts.router,
      protocolId: 'demo-dex',
      maxNativeValueWei: '0',
      methods: [{
        selector: routerInterface.getFunction('swapExactTokensForTokens').selector,
        name: 'swapExactTokensForTokens(uint256,uint256,address)',
        constraints: [
          { type: 'uint-max', argument: 0, value: maximumInput },
          { type: 'uint-min', argument: 1, value: '1' },
          { type: 'address-in', argument: 2, addresses: [deployment.wallet] },
        ],
      }],
    }],
  };
}

async function buildMonitor(deployment) {
  const runtimeCode = await deployment.provider.getCode(deployment.contracts.router);
  return {
    version: 1,
    chainId: CHAIN_ID,
    stateTtlSeconds: 120,
    rpcTimeoutMs: 8_000,
    rpcQuorum: 2,
    maxBlockSkew: 1,
    sources: [
      { id: 'anvil-primary', env: 'CALLSCOUT_DEMO_RPC_PRIMARY' },
      { id: 'anvil-secondary', env: 'CALLSCOUT_DEMO_RPC_SECONDARY' },
    ],
    protocols: [{
      id: 'demo-dex',
      contracts: [{
        address: deployment.contracts.router,
        codeHash: keccak256(runtimeCode),
        calls: [{ data: new Interface(readArtifact('DemoRouter').abi).encodeFunctionData('paused'), operator: 'equals', expected: ZERO_WORD }],
      }],
    }],
  };
}

function toRpcTransaction(intent) {
  const quantity = (value) => toBeHex(BigInt(value));
  return {
    from: intent.from,
    to: intent.to,
    data: intent.data,
    value: quantity(intent.value ?? 0),
    gas: quantity(intent.gas),
    maxFeePerGas: quantity(intent.maxFeePerGas),
    maxPriorityFeePerGas: quantity(intent.maxPriorityFeePerGas),
    nonce: quantity(intent.nonce),
    type: quantity(intent.type),
  };
}

function publicRun(run) {
  return jsonSafe(run);
}

export class DemoRuntime {
  constructor({ primaryUrl, secondaryUrl, primaryPort = 9545, secondaryPort = 9546, runtimeDirectory = RUNTIME_ROOT } = {}) {
    this.urls = {
      primary: primaryUrl ?? process.env.CALLSCOUT_DEMO_RPC_PRIMARY ?? `http://127.0.0.1:${primaryPort}`,
      secondary: secondaryUrl ?? process.env.CALLSCOUT_DEMO_RPC_SECONDARY ?? `http://127.0.0.1:${secondaryPort}`,
    };
    this.external = Boolean(primaryUrl || secondaryUrl || process.env.CALLSCOUT_DEMO_RPC_PRIMARY || process.env.CALLSCOUT_DEMO_RPC_SECONDARY);
    this.ports = { primary: primaryPort, secondary: secondaryPort };
    this.runtimeDirectory = runtimeDirectory;
    this.children = [];
    this.runs = [];
    this.runCounter = 0;
    this.sequence = 0;
    this.highestStateSequence = 0;
    this.started = false;
  }

  async start() {
    if (this.started) return this.describe();
    if (this.external && (!this.urls.primary || !this.urls.secondary)) throw new Error('Both external demo RPC URLs are required.');
    if (!this.external) {
      const primary = startAnvil(this.ports.primary, 'primary');
      const secondary = startAnvil(this.ports.secondary, 'secondary');
      this.children.push(primary, secondary);
      await Promise.all([waitForRpc(this.urls.primary, primary), waitForRpc(this.urls.secondary, secondary)]);
    } else {
      await Promise.all([waitForRpc(this.urls.primary), waitForRpc(this.urls.secondary)]);
    }
    const [primary, secondary] = await Promise.all([deployDemoChain(this.urls.primary), deployDemoChain(this.urls.secondary)]);
    assertMatchingDeployments(primary, secondary);
    this.chains = { primary, secondary };
    this.stateSigners = createStateSigners();
    this.policy = buildPolicy(primary, this.stateSigners);
    const validation = validatePolicy(this.policy, { activation: true });
    if (!validation.valid) throw new Error(`Generated demo policy is invalid: ${validation.errors.map((entry) => entry.message).join(' ')}`);
    this.policyAudit = auditPolicy(this.policy);
    this.monitor = await buildMonitor(primary);
    await fsp.mkdir(this.runtimeDirectory, { recursive: true });
    this.sessionId = `session_${Date.now().toString(36)}_${process.pid}`;
    this.audit = createAuditLog(path.join(this.runtimeDirectory, `${this.sessionId}.receipts.jsonl`));
    this.started = true;
    return this.describe();
  }

  describe() {
    if (!this.started) return { ready: false };
    return publicRun({
      ready: true,
      chainId: CHAIN_ID,
      rpcSources: [this.urls.primary, this.urls.secondary],
      wallet: this.chains.primary.wallet,
      contracts: this.chains.primary.contracts,
      policy: { name: this.policy.name, hash: sha256(this.policy), valid: true, findings: this.policyAudit.findings },
      monitor: { protocolId: 'demo-dex', threshold: this.monitor.rpcQuorum },
      eip7702: 'denied-by-policy',
    });
  }

  listRuns() {
    return this.runs.map((run) => publicRun({
      id: run.id,
      createdAt: run.createdAt,
      updatedAt: run.updatedAt,
      prompt: run.prompt,
      scenario: run.scenario,
      status: run.status,
      decision: run.decision,
      eventCount: run.events.length,
      transactionHash: run.transactionHash ?? null,
    }));
  }

  getRun(id) {
    const run = this.runs.find((entry) => entry.id === id);
    return run ? publicRun(run) : null;
  }

  createRun(prompt, { scenario = 'safe' } = {}) {
    if (!this.started) throw new Error('Demo runtime is not ready.');
    if (!RUN_SCENARIOS.has(scenario)) throw new Error(`Unknown demo scenario ${scenario}.`);
    const now = new Date().toISOString();
    const run = {
      id: `run_${Date.now().toString(36)}_${String(++this.runCounter).padStart(3, '0')}`,
      createdAt: now,
      updatedAt: now,
      prompt,
      scenario,
      status: 'queued',
      decision: null,
      agent: null,
      transaction: null,
      receipt: null,
      transactionHash: null,
      chainReceipt: null,
      events: [],
    };
    this.runs.unshift(run);
    this.executeRun(run).catch((error) => {
      run.status = 'error';
      run.decision = 'error';
      this.addEvent(run, 'system', 'error', 'Run failed closed', error.message);
    });
    return this.getRun(run.id);
  }

  async waitForRun(id, { timeoutMs = 30_000 } = {}) {
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {
      const run = this.getRun(id);
      if (!run) throw new Error(`Unknown run ${id}.`);
      if (['complete', 'error'].includes(run.status)) return run;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`Timed out waiting for ${id}.`);
  }

  addEvent(run, phase, status, title, detail, data = null) {
    run.events.push({ index: run.events.length + 1, at: new Date().toISOString(), phase, status, title, detail, data: data == null ? null : jsonSafe(data) });
    run.updatedAt = new Date().toISOString();
  }

  async resetChains(scenario) {
    for (const chain of Object.values(this.chains)) {
      const reverted = await chain.provider.send('evm_revert', [chain.snapshot]);
      if (!reverted) throw new Error(`Could not restore ${chain.url}.`);
      chain.snapshot = await chain.provider.send('evm_snapshot', []);
    }
    if (scenario === 'compromised') {
      await Promise.all(Object.values(this.chains).map(async (chain) => (await chain.router.setPaused(true)).wait()));
    } else if (scenario === 'hidden-call') {
      await Promise.all(Object.values(this.chains).map(async (chain) => (await chain.router.setUnsafeMode(true)).wait()));
    }
  }

  async signedState(now) {
    const payload = await collectProtocolState(this.monitor, {
      sequence: ++this.sequence,
      now,
      rpcUrls: { 'anvil-primary': this.urls.primary, 'anvil-secondary': this.urls.secondary },
    });
    let bundle = { version: 1, payload, signatures: [] };
    for (const signer of this.stateSigners) bundle = addProtocolStateSignature(bundle, signProtocolState(payload, { keyId: signer.id, privateKey: signer.privateKey }));
    return bundle;
  }

  async buildTransaction(parsed, scenario) {
    const routerInterface = new Interface(readArtifact('DemoRouter').abi);
    const minimumOut = scenario === 'slippage' ? (BigInt(parsed.amountIn) * 3n).toString() : parsed.minimumOut;
    const nonce = await this.chains.primary.provider.getTransactionCount(this.chains.primary.wallet, 'pending');
    const secondaryNonce = await this.chains.secondary.provider.getTransactionCount(this.chains.secondary.wallet, 'pending');
    if (nonce !== secondaryNonce) throw new Error('Simulation wallet nonces disagree across Anvil sources.');
    return {
      chainId: CHAIN_ID,
      from: this.chains.primary.wallet,
      to: this.chains.primary.contracts.router,
      data: routerInterface.encodeFunctionData('swapExactTokensForTokens', [parsed.amountIn, minimumOut, this.chains.primary.wallet]),
      value: '0',
      gas: '350000',
      maxFeePerGas: '10000000000',
      maxPriorityFeePerGas: '1000000000',
      nonce: String(nonce),
      type: '2',
    };
  }

  async executeRun(run) {
    run.status = 'running';
    this.addEvent(run, 'request', 'pass', 'Prompt received', 'The agent received a user goal, not wallet authority.', { prompt: run.prompt, scenario: run.scenario });
    await this.resetChains(run.scenario);
    this.addEvent(run, 'chain', 'pass', 'Dual-Anvil state restored', 'Both independent local nodes started from the same deterministic snapshot.', { sources: [this.urls.primary, this.urls.secondary] });

    const parsed = parseDemoTradePrompt(run.prompt, { wallet: this.chains.primary.wallet });
    run.agent = parsed;
    this.addEvent(run, 'agent', 'pass', 'Agent built structured intent', parsed.summary, parsed);
    const transaction = await this.buildTransaction(parsed, run.scenario);
    run.transaction = transaction;
    this.addEvent(run, 'agent', 'pass', 'Exact transaction proposed', 'Calldata, recipient, fees, gas, chain, and nonce are fixed before authorization.', transaction);

    const now = new Date();
    const protocolState = await this.signedState(now);
    const protocol = protocolState.payload.protocols[0];
    this.addEvent(run, 'live-state', protocol.status === 'operational' ? 'pass' : 'deny', `Protocol ${protocol.status}`, protocol.reason, {
      sequence: protocolState.payload.sequence,
      signatures: protocolState.signatures.map((signature) => signature.keyId),
      evidence: protocol.evidence,
      blockNumber: protocol.blockNumber ?? null,
    });

    let capturedReceipt = null;
    const walletProvider = {
      request: async (request) => {
        if (request.method === 'eth_chainId') return toBeHex(CHAIN_ID);
        if (request.method === 'eth_sendTransaction') return rpc(this.urls.primary, 'eth_sendTransaction', [toRpcTransaction(request.params[0])]);
        throw new Error(`Demo wallet does not expose ${request.method}.`);
      },
    };
    const guard = createGuardedProvider({
      provider: walletProvider,
      policy: this.policy,
      protocolState,
      simulationOptions: {
        rpcUrls: { 'anvil-primary': this.urls.primary, 'anvil-secondary': this.urls.secondary },
      },
      stateSequenceStore: {
        read: async () => this.highestStateSequence,
        write: async (next) => { if (next < this.highestStateSequence) throw new Error('rollback'); this.highestStateSequence = next; },
      },
      onDecision: async (receipt) => {
        capturedReceipt = receipt;
        await this.audit.append(receipt);
      },
      now,
    });

    try {
      run.transactionHash = await guard.request({ method: 'eth_sendTransaction', params: [transaction] });
      run.chainReceipt = jsonSafe(await this.chains.primary.provider.waitForTransaction(run.transactionHash));
    } catch (error) {
      if (!(error instanceof WalletGuardError)) throw error;
    }
    run.receipt = capturedReceipt;
    if (!capturedReceipt) throw new Error('Wallet guard produced no decision receipt.');
    const policyDenials = capturedReceipt.checks.filter((check) => check.status === 'deny' && !check.id.startsWith('simulation:'));
    this.addEvent(run, 'policy', policyDenials.length ? 'deny' : 'pass', policyDenials.length ? 'Policy or live-state vetoed' : 'Executable policy passed', `${capturedReceipt.checks.filter((check) => check.status === 'pass').length} checks passed; ${policyDenials.length} denied.`, { checks: capturedReceipt.checks.filter((check) => !check.id.startsWith('simulation:')) });
    if (capturedReceipt.simulation) {
      this.addEvent(run, 'simulation', capturedReceipt.decision === 'allow' ? 'pass' : 'deny', capturedReceipt.decision === 'allow' ? 'Full simulation quorum matched' : 'Simulation vetoed the proposal', `${capturedReceipt.simulation.agreeingSources.length}/2 sources agreed on one effect fingerprint.`, capturedReceipt.simulation);
    } else if (capturedReceipt.checks.some((check) => check.id.startsWith('simulation:'))) {
      this.addEvent(run, 'simulation', 'deny', 'Simulation failed closed', capturedReceipt.checks.find((check) => check.id.startsWith('simulation:') && check.status === 'deny')?.detail ?? 'No passing trace quorum.', { checks: capturedReceipt.checks.filter((check) => check.id.startsWith('simulation:')) });
    } else {
      this.addEvent(run, 'simulation', 'skip', 'Simulation not reached', 'An earlier deterministic veto stopped the request before simulation.');
    }

    const auditStatus = await this.audit.verify();
    this.addEvent(run, 'audit', auditStatus.valid ? 'pass' : 'deny', 'Receipt appended to hash chain', `${auditStatus.count} decision receipt${auditStatus.count === 1 ? '' : 's'} verified.`, auditStatus);
    run.decision = capturedReceipt.decision;
    if (capturedReceipt.decision === 'allow') {
      this.addEvent(run, 'wallet', 'pass', 'Wallet forwarded one exact request', `Transaction ${run.transactionHash} was mined on the primary Anvil node.`, { transactionHash: run.transactionHash, blockNumber: run.chainReceipt?.blockNumber ?? null });
    } else {
      this.addEvent(run, 'wallet', 'deny', 'Wallet never received the transaction', 'The guarded provider returned a denial and did not call eth_sendTransaction.');
    }
    run.status = 'complete';
    run.updatedAt = new Date().toISOString();
  }

  async stop() {
    for (const child of this.children) {
      if (child.exitCode == null) child.kill('SIGTERM');
    }
    await Promise.all(this.children.map((child) => child.exitCode == null ? new Promise((resolve) => child.once('exit', resolve)) : Promise.resolve()));
    this.children = [];
    this.started = false;
  }
}

export const DEMO_SCENARIOS = Object.freeze([...RUN_SCENARIOS]);
export const DEMO_CHAIN_ID = CHAIN_ID;
export function formatDemoAmount(value) { return formatUnits(value, 18); }
