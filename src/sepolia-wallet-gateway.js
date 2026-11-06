import fs from 'node:fs/promises';
import path from 'node:path';
import { Interface, toBeHex } from 'ethers';
import { createAlertLog } from './alerts.js';
import { createAuditLog } from './audit-log.js';
import { createBlockSpendTracker } from './block-spend.js';
import { sha256 } from './canonical.js';
import { parseDemoTradePrompt } from './demo-agent.js';
import { auditPolicy, normalizeIntent } from './policy.js';
import { collectProtocolState } from './protocol-monitor.js';
import { addProtocolStateSignature, createFileSequenceStore, signProtocolState } from './protocol-state.js';
import { rpc } from './transaction-simulator.js';
import { createGuardedProvider, WalletGuardError } from './wallet-guard.js';
import { SEPOLIA_CHAIN_ID } from './sepolia-gateway-config.js';

const AGENT_REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const RUN_SCENARIOS = new Set(['safe', 'hidden-call']);
const ROUTER = new Interface(['function swapExactTokensForTokens(uint256 amountIn,uint256 minimumOut,address recipient) returns (uint256 amountOut)']);
const STORY = Object.freeze([
  Object.freeze({ step: 1, scenario: 'safe', title: 'Policy-compliant Sepolia swap', expected: 'allow', prompt: 'Swap 100 dUSD for at least 190 dETH to my wallet', reason: 'The exact request passes policy, live state, and two independent Sepolia traces before the isolated signer submits it.' }),
  Object.freeze({ step: 2, scenario: 'hidden-call', title: 'Hidden call blocked', expected: 'deny', prompt: 'Swap 75 dUSD for at least 140 dETH to my wallet', reason: 'The whitelisted router has valid outer calldata, but both full traces expose its call to an unauthorized contract.' }),
]);

function jsonSafe(value) {
  return JSON.parse(JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? item.toString() : item));
}

function sanitizeProposal(proposal) {
  const normalized = normalizeIntent(proposal);
  if (!normalized.valid) throw new Error(`Invalid agent proposal: ${normalized.errors.map((entry) => entry.message).join(' ')}`);
  if (normalized.intent.type !== 2n || normalized.intent.authorizationList != null) throw new Error('Sepolia beta accepts only type-2 transactions and denies EIP-7702.');
  const fields = ['chainId', 'from', 'to', 'data', 'value', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce', 'type'];
  return Object.fromEntries(fields.map((field) => [field, field === 'chainId' ? Number(proposal[field]) : String(proposal[field]) ]));
}

function signerRequest(wallet, primaryUrl) {
  return Object.freeze({
    async request(request) {
      if (request?.method === 'eth_chainId') return toBeHex(SEPOLIA_CHAIN_ID);
      if (request?.method !== 'eth_sendTransaction') throw new Error(`Isolated signer does not expose ${request?.method ?? '(missing)'}.`);
      const proposal = sanitizeProposal(request.params?.[0]);
      if (proposal.from.toLowerCase() !== wallet.address.toLowerCase()) throw new Error('Signer refused a transaction from another wallet.');
      const raw = await wallet.signTransaction({
        chainId: SEPOLIA_CHAIN_ID,
        type: 2,
        to: proposal.to,
        data: proposal.data,
        value: BigInt(proposal.value),
        gasLimit: BigInt(proposal.gas),
        maxFeePerGas: BigInt(proposal.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(proposal.maxPriorityFeePerGas),
        nonce: Number(BigInt(proposal.nonce)),
      });
      return rpc(primaryUrl, 'eth_sendRawTransaction', [raw], { timeoutMs: 20_000 });
    },
  });
}

async function waitForReceipt(url, transactionHash, timeoutMs = 90_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const receipt = await rpc(url, 'eth_getTransactionReceipt', [transactionHash], { timeoutMs: 12_000 });
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 1_500));
  }
  throw new Error(`Timed out waiting for Sepolia transaction ${transactionHash}.`);
}

export class SepoliaWalletGateway {
  constructor({ config, wallet, stateSigners, rpcUrls, runtimeDirectory }) {
    this.config = config;
    this.policy = config.policy;
    this.monitor = config.monitor;
    this.wallet = wallet;
    this.stateSigners = stateSigners;
    this.rpcUrls = rpcUrls;
    this.runtimeDirectory = runtimeDirectory;
    this.runDirectory = path.join(runtimeDirectory, 'runs');
    this.audit = createAuditLog(path.join(runtimeDirectory, 'receipts.jsonl'));
    this.alerts = createAlertLog(path.join(runtimeDirectory, 'alerts.jsonl'), { echo: true });
    this.sequenceStore = createFileSequenceStore(path.join(runtimeDirectory, 'state-sequence.json'));
    this.blockSpend = createBlockSpendTracker();
    this.runs = [];
    this.runCounter = 0;
    this.executionTail = Promise.resolve();
    this.pendingWrites = new Map();
    this.started = false;
  }

  async loadRuns() {
    await fs.mkdir(this.runDirectory, { recursive: true });
    const entries = await fs.readdir(this.runDirectory, { withFileTypes: true });
    const loaded = [];
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
      try {
        const run = JSON.parse(await fs.readFile(path.join(this.runDirectory, entry.name), 'utf8'));
        if (!run?.id || !Array.isArray(run.events)) continue;
        if (run.status === 'queued' || run.status === 'running') {
          run.status = 'error';
          run.decision = 'error';
          run.updatedAt = new Date().toISOString();
          run.events.push({ index: run.events.length + 1, at: run.updatedAt, phase: 'system', status: 'error', title: 'Run interrupted before completion', detail: 'The persistent Gateway restarted before reaching a wallet decision.', data: null });
        }
        loaded.push(run);
      } catch { /* Malformed history never becomes wallet authority. */ }
    }
    this.runs = loaded.sort((left, right) => String(right.createdAt).localeCompare(String(left.createdAt)));
    await Promise.all(this.runs.map((run) => this.persistRun(run)));
  }

  persistRun(run) {
    const target = path.join(this.runDirectory, `${run.id}.json`);
    const temporary = `${target}.${process.pid}.tmp`;
    const previous = this.pendingWrites.get(run.id) ?? Promise.resolve();
    const next = previous.then(async () => {
      await fs.mkdir(this.runDirectory, { recursive: true });
      await fs.writeFile(temporary, `${JSON.stringify(jsonSafe(run), null, 2)}\n`, { mode: 0o600 });
      await fs.rename(temporary, target);
    });
    this.pendingWrites.set(run.id, next);
    next.then(
      () => { if (this.pendingWrites.get(run.id) === next) this.pendingWrites.delete(run.id); },
      () => { if (this.pendingWrites.get(run.id) === next) this.pendingWrites.delete(run.id); },
    );
    return next;
  }

  schedulePersist(run) { void this.persistRun(run).catch((error) => { process.stderr.write(`[walletcordon] run persistence failed: ${error.message}\n`); }); }

  async start() {
    if (this.started) return this.describe();
    const sources = Object.entries(this.rpcUrls);
    const chainIds = await Promise.all(sources.map(([, url]) => rpc(url, 'eth_chainId')));
    if (chainIds.some((chainId) => BigInt(chainId) !== BigInt(SEPOLIA_CHAIN_ID))) throw new Error('Every Gateway RPC source must report Sepolia chain 11155111.');
    const nonces = await Promise.all(sources.map(([, url]) => rpc(url, 'eth_getTransactionCount', [this.wallet.address, 'pending'])));
    if (new Set(nonces.map((value) => BigInt(value).toString())).size !== 1) throw new Error('Sepolia RPC sources disagree on the wallet pending nonce.');
    const initial = await collectProtocolState(this.monitor, { sequence: (await this.sequenceStore.read()) + 1, rpcUrls: this.rpcUrls });
    if (initial.protocols.some((protocol) => protocol.status !== 'operational')) throw new Error(`Protocol monitor is not operational: ${initial.protocols.map((protocol) => protocol.reason).join(' ')}`);
    await fs.mkdir(this.runtimeDirectory, { recursive: true });
    await this.loadRuns();
    this.started = true;
    return this.describe();
  }

  describe() {
    return jsonSafe({
      ready: this.started,
      mode: 'sepolia-beta',
      history: 'durable-remote',
      chainId: SEPOLIA_CHAIN_ID,
      rpcSources: Object.keys(this.rpcUrls),
      wallet: this.wallet.address,
      contracts: this.config.contracts,
      policy: { name: this.policy.name, hash: sha256(this.policy), valid: true, findings: auditPolicy(this.policy).findings },
      monitor: { protocolId: this.monitor.protocols[0].id, threshold: this.monitor.rpcQuorum },
      eip7702: 'denied-by-policy',
    });
  }

  async capabilities() {
    if (!this.started) throw new Error('WalletCordon Sepolia Gateway is not ready.');
    const nonces = await Promise.all(Object.values(this.rpcUrls).map((url) => rpc(url, 'eth_getTransactionCount', [this.wallet.address, 'pending'])));
    if (new Set(nonces.map((value) => BigInt(value).toString())).size !== 1) throw new Error('Sepolia sources disagree on the pending wallet nonce.');
    const selector = ROUTER.getFunction('swapExactTokensForTokens').selector;
    return jsonSafe({
      apiVersion: 'v1',
      chainId: SEPOLIA_CHAIN_ID,
      wallet: this.wallet.address,
      nextNonce: BigInt(nonces[0]).toString(),
      contracts: this.config.contracts,
      actions: [
        { name: 'swapExactTokensForTokens', target: this.config.contracts.safeRouter, selector, signature: 'swapExactTokensForTokens(uint256,uint256,address)', demo: 'policy-compliant' },
        { name: 'swapExactTokensForTokens', target: this.config.contracts.maliciousRouter, selector, signature: 'swapExactTokensForTokens(uint256,uint256,address)', demo: 'trace-denied' },
      ],
      transactionTypes: ['2'],
      deniedMethods: ['eth_sign', 'personal_sign', 'eth_signTypedData_v4', 'eth_sendRawTransaction', 'wallet_switchEthereumChain'],
      policy: { name: this.policy.name, hash: sha256(this.policy), expiresAt: this.policy.validUntil },
      eip7702: 'denied-by-policy',
    });
  }

  listRuns() {
    return this.runs.map((run) => jsonSafe({
      id: run.id, createdAt: run.createdAt, updatedAt: run.updatedAt, prompt: run.prompt,
      scenario: run.scenario, source: run.source, requestId: run.requestId, status: run.status,
      decision: run.decision, eventCount: run.events.length, transactionHash: run.transactionHash, demo: run.demo,
    }));
  }

  getRun(id) { const run = this.runs.find((entry) => entry.id === id); return run ? jsonSafe(run) : null; }
  findByRequestId(requestId) { return this.runs.find((entry) => entry.requestId === requestId) ?? null; }

  createRun(prompt, { scenario = 'safe', source = 'operator', requestId = null, proposal = null, demo = null } = {}) {
    if (!this.started) throw new Error('WalletCordon Sepolia Gateway is not ready.');
    if (!RUN_SCENARIOS.has(scenario)) throw new Error(`Unknown Sepolia scenario ${scenario}.`);
    const goal = String(prompt ?? '').trim();
    if (!goal || goal.length > 500) throw new Error('Goal must be between 1 and 500 characters.');
    if (source === 'agent-api') {
      if (!AGENT_REQUEST_ID.test(requestId ?? '')) throw new Error('Agent requestId must be 8-128 URL-safe characters.');
      const existing = this.findByRequestId(requestId);
      if (existing) return this.getRun(existing.id);
    }
    const now = new Date().toISOString();
    const run = {
      id: `run_${Date.now().toString(36)}_${String(++this.runCounter).padStart(3, '0')}`,
      createdAt: now, updatedAt: now, prompt: goal, scenario, source, requestId,
      demo: demo == null ? null : jsonSafe(demo), submittedProposal: proposal == null ? null : sanitizeProposal(proposal),
      status: 'queued', decision: null, agent: null, transaction: null, receipt: null,
      transactionHash: null, chainReceipt: null, verification: null, events: [],
    };
    this.runs.unshift(run);
    this.schedulePersist(run);
    const execute = async () => {
      try { await this.executeRun(run); }
      catch (error) {
        run.status = 'error'; run.decision = 'error';
        this.addEvent(run, 'system', 'error', 'Run failed closed', error.message);
        await this.persistRun(run);
      }
    };
    this.executionTail = this.executionTail.then(execute, execute);
    return this.getRun(run.id);
  }

  createAgentRun({ requestId, goal, proposal }) { return this.createRun(goal, { scenario: 'safe', source: 'agent-api', requestId, proposal }); }

  createTwoTransactionDemo() {
    const id = `demo_${Date.now().toString(36)}_${String(++this.runCounter).padStart(3, '0')}`;
    const runs = STORY.map((entry) => this.createRun(entry.prompt, { scenario: entry.scenario, source: 'guided-demo', demo: { id, ...entry, total: STORY.length } }));
    return { id, runs };
  }

  addEvent(run, phase, status, title, detail, data = null) {
    run.events.push({ index: run.events.length + 1, at: new Date().toISOString(), phase, status, title, detail, data: data == null ? null : jsonSafe(data) });
    run.updatedAt = new Date().toISOString();
    this.schedulePersist(run);
  }

  async signedState() {
    const sequence = (await this.sequenceStore.read()) + 1;
    const payload = await collectProtocolState(this.monitor, { sequence, rpcUrls: this.rpcUrls });
    await this.sequenceStore.write(sequence);
    let bundle = { version: 1, payload, signatures: [] };
    for (const signer of this.stateSigners) bundle = addProtocolStateSignature(bundle, signProtocolState(payload, { keyId: signer.id, privateKey: signer.privateKey }));
    return bundle;
  }

  async buildDemoTransaction(prompt, scenario) {
    const parsed = parseDemoTradePrompt(prompt, { wallet: this.wallet.address });
    const nonces = await Promise.all(Object.values(this.rpcUrls).map((url) => rpc(url, 'eth_getTransactionCount', [this.wallet.address, 'pending'])));
    if (new Set(nonces.map((value) => BigInt(value).toString())).size !== 1) throw new Error('Sepolia sources disagree on the pending wallet nonce.');
    const [block, priorityHex] = await Promise.all([
      rpc(this.rpcUrls['sepolia-primary'], 'eth_getBlockByNumber', ['latest', false]),
      rpc(this.rpcUrls['sepolia-primary'], 'eth_maxPriorityFeePerGas'),
    ]);
    const priority = BigInt(priorityHex);
    const maximumFee = BigInt(block.baseFeePerGas) * 2n + priority;
    return {
      agent: parsed,
      transaction: {
        chainId: SEPOLIA_CHAIN_ID,
        from: this.wallet.address,
        to: scenario === 'hidden-call' ? this.config.contracts.maliciousRouter : this.config.contracts.safeRouter,
        data: ROUTER.encodeFunctionData('swapExactTokensForTokens', [parsed.amountIn, parsed.minimumOut, this.wallet.address]),
        value: '0', gas: toBeHex(350_000n), maxFeePerGas: toBeHex(maximumFee),
        maxPriorityFeePerGas: toBeHex(priority), nonce: BigInt(nonces[0]).toString(), type: '2',
      },
    };
  }

  async executeRun(run) {
    run.status = 'running';
    this.addEvent(run, 'request', 'pass', 'Request fixed before authorization', 'The Gateway recorded the user goal and will not let it grant wallet authority.', { source: run.source, requestId: run.requestId });
    const built = run.submittedProposal ? { agent: { source: 'external-agent-api', requestId: run.requestId, summary: run.prompt }, transaction: run.submittedProposal } : await this.buildDemoTransaction(run.prompt, run.scenario);
    run.agent = built.agent; run.transaction = built.transaction;
    this.addEvent(run, 'agent', 'pass', run.submittedProposal ? 'Agent submitted exact proposal' : 'Demo agent built exact proposal', built.agent.summary, built.agent);
    this.addEvent(run, 'agent', 'pass', 'Exact Sepolia transaction proposed', 'Target, calldata, value, gas, fees, chain, type, and pending nonce are fixed.', built.transaction);

    const protocolState = await this.signedState();
    const protocol = protocolState.payload.protocols[0];
    this.addEvent(run, 'live-state', protocol.status === 'operational' ? 'pass' : 'deny', `Protocol ${protocol.status}`, protocol.reason, { sequence: protocolState.payload.sequence, signatures: protocolState.signatures.map((signature) => signature.keyId), blockNumber: protocol.blockNumber, evidence: protocol.evidence });

    let capturedReceipt = null;
    const guard = createGuardedProvider({
      provider: signerRequest(this.wallet, this.rpcUrls['sepolia-primary']),
      policy: this.policy,
      protocolState,
      simulationOptions: { rpcUrls: this.rpcUrls },
      blockSpend: this.blockSpend,
      alerts: { append: async (alert) => { this.addEvent(run, 'alert', alert.severity === 'critical' ? 'deny' : 'pass', `Alert: ${alert.code}`, alert.message, alert); return this.alerts.append(alert); } },
      stateSequenceStore: this.sequenceStore,
      verification: { request: (method, params) => rpc(this.rpcUrls['sepolia-primary'], method, params), timeoutMs: 90_000, pollMs: 1_500 },
      onDecision: async (receipt) => { capturedReceipt = receipt; await this.audit.append(receipt); },
      onVerification: async (verification) => this.audit.append(verification),
    });

    try { run.transactionHash = await guard.request({ method: 'eth_sendTransaction', params: [built.transaction] }); }
    catch (error) { if (!(error instanceof WalletGuardError)) throw error; }
    run.receipt = capturedReceipt;
    if (!capturedReceipt) throw new Error('Wallet guard produced no decision receipt.');
    const policyDenials = capturedReceipt.checks.filter((check) => check.status === 'deny' && !check.id.startsWith('simulation:'));
    this.addEvent(run, 'policy', policyDenials.length ? 'deny' : 'pass', policyDenials.length ? 'Policy or live-state vetoed' : 'Executable policy passed', `${capturedReceipt.checks.filter((check) => check.status === 'pass').length} checks passed; ${policyDenials.length} denied.`, { checks: capturedReceipt.checks.filter((check) => !check.id.startsWith('simulation:')) });
    if (capturedReceipt.simulation) {
      const denied = capturedReceipt.checks.some((check) => check.id.startsWith('simulation:') && check.status === 'deny');
      const failure = capturedReceipt.simulation.sources?.flatMap((source) => source.failures ?? []).find(Boolean);
      this.addEvent(run, 'simulation', denied ? 'deny' : 'pass', denied ? 'Full simulation exposed forbidden behavior' : 'Two-source simulation quorum matched', denied ? failure ?? 'No all-pass trace quorum.' : `${capturedReceipt.simulation.agreeingSources.length}/2 sources agreed on one effect fingerprint.`, capturedReceipt.simulation);
    } else {
      this.addEvent(run, 'simulation', 'skip', 'Simulation not reached', 'An earlier deterministic veto stopped the request before simulation.');
    }
    if (run.transactionHash) {
      this.addEvent(run, 'wallet', 'pass', 'Isolated signer forwarded the approved bytes', `Sepolia transaction ${run.transactionHash} was broadcast only after every gate passed.`, { transactionHash: run.transactionHash });
      const [chainReceipt, verification] = await Promise.all([waitForReceipt(this.rpcUrls['sepolia-primary'], run.transactionHash), guard.verification(run.transactionHash)]);
      run.chainReceipt = jsonSafe(chainReceipt); run.verification = jsonSafe(verification);
      const verified = verification?.status === 'verified';
      this.addEvent(run, 'onchain', verified ? 'pass' : 'deny', verified ? 'Mined transaction matches authorization' : 'On-chain verification needs attention', verified ? 'The mined Sepolia transaction matches the exact approved envelope and effects.' : verification?.status ?? 'Verification unavailable.', verification);
    } else {
      this.addEvent(run, 'wallet', 'deny', 'Signer never received the transaction', 'WalletCordon returned a denial before the isolated signer boundary.');
    }
    const audit = await this.audit.verify();
    this.addEvent(run, 'audit', audit.valid ? 'pass' : 'deny', 'Evidence appended to hash chain', `${audit.count} records verified.`, audit);
    run.decision = capturedReceipt.decision; run.status = 'complete'; run.updatedAt = new Date().toISOString();
    await this.persistRun(run);
  }

  async stop() {
    await this.executionTail;
    await Promise.all(this.pendingWrites.values());
    this.started = false;
  }
}

export const SEPOLIA_DEMO_STORY = STORY;
