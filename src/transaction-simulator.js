import { id, keccak256 } from 'ethers';
import { sha256 } from './canonical.js';
import { normalizeIntent, validatePolicy } from './policy.js';

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const HEX_DATA = /^0x(?:[a-fA-F0-9]{2})*$/;
const TRANSFER_TOPIC = id('Transfer(address,address,uint256)').toLowerCase();
const APPROVAL_TOPIC = id('Approval(address,address,uint256)').toLowerCase();
const APPROVAL_FOR_ALL_TOPIC = id('ApprovalForAll(address,address,bool)').toLowerCase();
const TRANSFER_SINGLE_TOPIC = id('TransferSingle(address,address,address,uint256,uint256)').toLowerCase();
const TRANSFER_BATCH_TOPIC = id('TransferBatch(address,address,address,uint256[],uint256[])').toLowerCase();

function quantity(value) { return `0x${value.toString(16)}`; }
function addressTopic(value) { return /^0x[0-9a-fA-F]{64}$/.test(String(value)) ? `0x${value.slice(-40).toLowerCase()}` : null; }
function rpcTransaction(intent) {
  return {
    from: intent.from,
    to: intent.to,
    data: intent.data,
    value: quantity(intent.value),
    ...(intent.gas != null ? { gas: quantity(intent.gas) } : {}),
    ...(intent.gasPrice != null ? { gasPrice: quantity(intent.gasPrice) } : {}),
    ...(intent.maxFeePerGas != null ? { maxFeePerGas: quantity(intent.maxFeePerGas) } : {}),
    ...(intent.maxPriorityFeePerGas != null ? { maxPriorityFeePerGas: quantity(intent.maxPriorityFeePerGas) } : {}),
    ...(intent.type != null ? { type: quantity(intent.type) } : {}),
    ...(intent.authorizationList != null ? {
      authorizationList: intent.authorizationList.map((authorization) => ({
        chainId: quantity(authorization.chainId),
        address: authorization.address,
        nonce: quantity(authorization.nonce),
        yParity: quantity(authorization.yParity),
        r: quantity(BigInt(authorization.r)),
        s: quantity(BigInt(authorization.s)),
      })),
    } : {}),
  };
}

function validateUrl(value) {
  const url = new URL(value);
  const local = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !local) throw new Error('Simulation endpoints must use HTTPS; HTTP is allowed only for loopback development.');
  if (url.username || url.password) throw new Error('Simulation URLs must not contain credentials.');
  return url;
}

async function rpc(url, method, params, { fetchImpl, timeoutMs }) {
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': 'callscout-simulator/0.1' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    redirect: 'error',
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const length = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(length) && length > 4_000_000) throw new Error('Simulation response exceeds 4 MB.');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 4_000_000) throw new Error('Simulation response exceeds 4 MB.');
  const payload = JSON.parse(bytes.toString('utf8'));
  if (payload.error) throw new Error(`RPC ${payload.error.code ?? 'error'}: ${payload.error.message ?? 'unknown error'}`);
  if (!Object.hasOwn(payload, 'result')) throw new Error('RPC response has no result.');
  return payload.result;
}

function normalizeLog(log) {
  if (!log || !ADDRESS.test(String(log.address)) || !Array.isArray(log.topics) || !HEX_DATA.test(String(log.data ?? ''))) throw new Error('Malformed trace log.');
  if (log.topics.some((topic) => !/^0x[0-9a-fA-F]{64}$/.test(String(topic)))) throw new Error('Malformed trace log topic.');
  return { address: log.address.toLowerCase(), topics: log.topics.map((topic) => topic.toLowerCase()), data: log.data.toLowerCase() };
}

function normalizeTrace(node, depth, aggregate) {
  if (!node || typeof node !== 'object') throw new Error('Malformed call trace.');
  const type = String(node.type ?? 'CALL').toUpperCase();
  const from = ADDRESS.test(String(node.from ?? '')) ? node.from.toLowerCase() : null;
  const to = ADDRESS.test(String(node.to ?? '')) ? node.to.toLowerCase() : null;
  if (node.value != null && (typeof node.value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(node.value))) throw new Error('Malformed call trace value.');
  if (node.input != null && !HEX_DATA.test(String(node.input))) throw new Error('Malformed call trace input.');
  if (node.output != null && !HEX_DATA.test(String(node.output))) throw new Error('Malformed call trace output.');
  const value = node.value == null ? 0n : BigInt(node.value);
  const logs = (node.logs ?? []).map(normalizeLog);
  const base = {
    type, from, to, value: value.toString(),
    input: HEX_DATA.test(String(node.input ?? '')) ? node.input.toLowerCase() : '0x',
    output: HEX_DATA.test(String(node.output ?? '')) ? node.output.toLowerCase() : '0x',
    error: node.error ? String(node.error) : null,
    revertReason: node.revertReason ? String(node.revertReason) : null,
    logs,
  };
  aggregate.nodes.push({ ...base, depth });
  aggregate.logs.push(...logs);
  const calls = (node.calls ?? []).map((call) => normalizeTrace(call, depth + 1, aggregate));
  return { ...base, calls };
}

function stateDiffStats(diff, denyCodeChanges, expectedCodeChanges = new Map(), wallet = null) {
  if (!diff || typeof diff !== 'object' || Array.isArray(diff) || !diff.pre || !diff.post || typeof diff.pre !== 'object' || Array.isArray(diff.pre) || typeof diff.post !== 'object' || Array.isArray(diff.post)) throw new Error('Malformed prestate diff trace.');
  const accountKeys = [...Object.keys(diff.pre), ...Object.keys(diff.post)];
  if (accountKeys.some((address) => !ADDRESS.test(address))) throw new Error('Malformed account address in prestate diff trace.');
  const accounts = new Set(accountKeys.map((address) => address.toLowerCase()));
  let storageWrites = 0;
  let codeChanges = 0;
  let unexpectedCodeChanges = 0;
  let walletBalanceDecrease = 0n;
  const observedCodeChanges = new Map();
  for (const address of accounts) {
    const pre = diff.pre[address] ?? diff.pre[Object.keys(diff.pre).find((key) => key.toLowerCase() === address)] ?? {};
    const post = diff.post[address] ?? diff.post[Object.keys(diff.post).find((key) => key.toLowerCase() === address)] ?? {};
    if (!pre || typeof pre !== 'object' || Array.isArray(pre) || !post || typeof post !== 'object' || Array.isArray(post)) throw new Error('Malformed account record in prestate diff trace.');
    if ((pre.storage != null && (typeof pre.storage !== 'object' || Array.isArray(pre.storage))) || (post.storage != null && (typeof post.storage !== 'object' || Array.isArray(post.storage)))) throw new Error('Malformed storage record in prestate diff trace.');
    const slots = new Set([...Object.keys(pre.storage ?? {}), ...Object.keys(post.storage ?? {})]);
    if ([...slots].some((slot) => !/^0x[a-fA-F0-9]{64}$/.test(slot))) throw new Error('Malformed storage slot in prestate diff trace.');
    for (const slot of slots) if ((pre.storage?.[slot] ?? null) !== (post.storage?.[slot] ?? null)) storageWrites++;
    if (pre.code != null && !HEX_DATA.test(String(pre.code))) throw new Error('Malformed prestate code.');
    if (post.code != null && !HEX_DATA.test(String(post.code))) throw new Error('Malformed poststate code.');
    if (post.code != null && String(post.code).toLowerCase() !== String(pre.code ?? '0x').toLowerCase()) {
      codeChanges++;
      const nextCode = String(post.code).toLowerCase();
      observedCodeChanges.set(address, nextCode);
      if (expectedCodeChanges.get(address) !== nextCode) unexpectedCodeChanges++;
    }
    if (address === wallet && (pre.balance != null || post.balance != null)) {
      if (!/^0x[0-9a-fA-F]+$/.test(String(pre.balance ?? '')) || !/^0x[0-9a-fA-F]+$/.test(String(post.balance ?? ''))) throw new Error('Malformed wallet balance in prestate diff trace.');
      const before = BigInt(pre.balance);
      const after = BigInt(post.balance);
      if (before > after) walletBalanceDecrease = before - after;
    }
  }
  const missingExpectedCodeChanges = [...expectedCodeChanges].filter(([address, code]) => observedCodeChanges.get(address) !== code).map(([address]) => address);
  return { accounts: accounts.size, storageWrites, codeChanges, unexpectedCodeChanges, missingExpectedCodeChanges, walletBalanceDecrease: walletBalanceDecrease.toString(), deniedCodeChange: denyCodeChanges && unexpectedCodeChanges > 0 };
}

function analyzeAssets(logs, wallet, limits, chainId) {
  const byToken = new Map(limits.filter((limit) => limit.chainId === chainId).map((limit) => [limit.token.toLowerCase(), limit]));
  const outflows = new Map();
  const approvals = [];
  const violations = [];
  for (const log of logs) {
    const topic = log.topics[0];
    if (topic === APPROVAL_FOR_ALL_TOPIC && addressTopic(log.topics[1]) === wallet) {
      violations.push(`Operator-wide token approval is not supported for ${log.address}.`);
      continue;
    }
    if ((topic === TRANSFER_SINGLE_TOPIC || topic === TRANSFER_BATCH_TOPIC) && addressTopic(log.topics[2]) === wallet) {
      violations.push(`ERC-1155 wallet outflow is not supported for ${log.address}.`);
      continue;
    }
    if (topic !== TRANSFER_TOPIC && topic !== APPROVAL_TOPIC) continue;
    const owner = addressTopic(log.topics[1]);
    const counterparty = addressTopic(log.topics[2]);
    if (owner !== wallet) continue;
    const limit = byToken.get(log.address);
    if (!limit) { violations.push(`Wallet asset event from unconfigured token ${log.address}.`); continue; }
    if (!/^0x[0-9a-f]{64}$/.test(log.data)) { violations.push(`Unsupported non-ERC20 asset event from ${log.address}.`); continue; }
    const amount = BigInt(log.data);
    if (topic === TRANSFER_TOPIC) {
      const total = (outflows.get(log.address) ?? 0n) + amount;
      outflows.set(log.address, total);
      if (total > BigInt(limit.maxOutflow)) violations.push(`Token outflow ${total} exceeds ${limit.maxOutflow} for ${log.address}.`);
      if (!limit.allowedRecipients.some((address) => address.toLowerCase() === counterparty)) violations.push(`Token recipient ${counterparty} is not allowed for ${log.address}.`);
    } else {
      approvals.push({ token: log.address, spender: counterparty, amount: amount.toString() });
      if (amount > BigInt(limit.maxApproval)) violations.push(`Approval ${amount} exceeds ${limit.maxApproval} for ${log.address}.`);
      if (!limit.allowedSpenders.some((address) => address.toLowerCase() === counterparty)) violations.push(`Approval spender ${counterparty} is not allowed for ${log.address}.`);
    }
  }
  return { outflows: Object.fromEntries([...outflows].map(([token, amount]) => [token, amount.toString()])), approvals, violations };
}

function analyzeTrace(policy, intent, callTrace, diffTrace, gasEstimate) {
  const config = policy.simulation;
  const aggregate = { nodes: [], logs: [] };
  const normalizedTrace = normalizeTrace(callTrace, 0, aggregate);
  const failures = [];
  const root = aggregate.nodes[0];
  if (root.from !== intent.from) failures.push(`Trace root sender ${root.from ?? '(missing)'} does not match ${intent.from}.`);
  if (root.to !== intent.to) failures.push(`Trace root target ${root.to ?? '(missing)'} does not match ${intent.to}.`);
  if (root.input !== intent.data) failures.push('Trace root calldata does not match the proposed transaction.');
  if (BigInt(root.value) !== intent.value) failures.push(`Trace root value ${root.value} does not match ${intent.value}.`);
  if (aggregate.nodes.length > config.maxInternalCalls) failures.push(`Trace has ${aggregate.nodes.length} calls; maximum is ${config.maxInternalCalls}.`);
  const depth = Math.max(...aggregate.nodes.map((node) => node.depth));
  if (depth > config.maxCallDepth) failures.push(`Trace depth ${depth} exceeds ${config.maxCallDepth}.`);
  const allowedTypes = new Set(config.allowedCallTypes);
  const allowedTargets = new Set([
    ...policy.contracts.filter((contract) => contract.chainId === intent.chainId).map((contract) => contract.address.toLowerCase()),
    ...config.internalTargets.filter((target) => target.chainId === intent.chainId).map((target) => target.address.toLowerCase()),
    ...config.assetLimits.filter((limit) => limit.chainId === intent.chainId).map((limit) => limit.token.toLowerCase()),
  ]);
  let nativeOutflow = 0n;
  for (const [index, node] of aggregate.nodes.entries()) {
    if (node.error) failures.push(`Trace node ${index} reverted: ${node.error}.`);
    if (!allowedTypes.has(node.type)) failures.push(`Call type ${node.type} is not allowed.`);
    if (index > 0 && node.to && !allowedTargets.has(node.to)) failures.push(`Internal target ${node.to} is not allowed.`);
    if (index > 0 && !node.to) failures.push(`Trace node ${index} creates or targets an unresolved contract.`);
    if (node.from === intent.from) nativeOutflow += BigInt(node.value);
  }
  if (nativeOutflow > BigInt(policy.invariants.maxNativeValueWei)) failures.push(`Simulated native outflow ${nativeOutflow} exceeds policy limit ${policy.invariants.maxNativeValueWei}.`);
  if (gasEstimate > BigInt(config.maxGasEstimate)) failures.push(`Estimated gas ${gasEstimate} exceeds simulation limit ${config.maxGasEstimate}.`);
  if (intent.gas != null && gasEstimate > intent.gas) failures.push(`Estimated gas ${gasEstimate} exceeds transaction gas ${intent.gas}.`);
  const expectedCodeChanges = new Map((intent.authorizationList ?? []).map((authorization) => [intent.from, `0xef0100${authorization.address.slice(2)}`]));
  const state = stateDiffStats(diffTrace, config.denyCodeChanges, expectedCodeChanges, intent.from);
  if (state.accounts > config.maxStateAccounts) failures.push(`State diff touches ${state.accounts} accounts; maximum is ${config.maxStateAccounts}.`);
  if (state.storageWrites > config.maxStorageWrites) failures.push(`State diff has ${state.storageWrites} storage writes; maximum is ${config.maxStorageWrites}.`);
  if (state.deniedCodeChange) failures.push(`State diff contains ${state.unexpectedCodeChanges} unexpected code change(s).`);
  if (state.missingExpectedCodeChanges.length) failures.push(`State diff did not prove the expected EIP-7702 delegation change for ${state.missingExpectedCodeChanges.join(', ')}.`);
  if (BigInt(state.walletBalanceDecrease) > BigInt(policy.invariants.maxNativeValueWei)) failures.push(`Wallet balance decrease ${state.walletBalanceDecrease} exceeds policy limit ${policy.invariants.maxNativeValueWei}.`);
  const assets = analyzeAssets(aggregate.logs, intent.from, config.assetLimits, intent.chainId);
  failures.push(...assets.violations);
  return {
    failures,
    metrics: { calls: aggregate.nodes.length, depth, nativeOutflow: nativeOutflow.toString(), gasEstimate: gasEstimate.toString(), ...state, outflows: assets.outflows, approvals: assets.approvals },
    fingerprint: sha256({ callResult: normalizedTrace.output, trace: normalizedTrace, stateDiff: diffTrace }),
  };
}

async function inspectDelegate(policy, address, chainId, source, fetchImpl, timeoutMs, cache) {
  if (cache.has(address)) return cache.get(address);
  const pinned = policy.simulation.eip7702.delegates.find((entry) => entry.chainId === chainId && entry.address.toLowerCase() === address);
  if (!pinned) return { valid: false, address, failure: `EIP-7702 delegate ${address} is not allowlisted.` };
  const code = String(await rpc(source.url, 'eth_getCode', [address, policy.simulation.blockTag], { fetchImpl, timeoutMs })).toLowerCase();
  if (!HEX_DATA.test(code) || code === '0x') return { valid: false, address, failure: `EIP-7702 delegate ${address} has missing or malformed runtime code.` };
  if (/^0xef0100[0-9a-f]{40}$/.test(code)) return { valid: false, address, failure: `EIP-7702 delegate ${address} is itself delegated; delegation chains are denied.` };
  const codeHash = keccak256(code).toLowerCase();
  const valid = codeHash === pinned.codeHash.toLowerCase();
  const result = { valid, address, codeHash, failure: valid ? null : `EIP-7702 delegate ${address} code hash ${codeHash} does not match pinned ${pinned.codeHash.toLowerCase()}.` };
  cache.set(address, result);
  return result;
}

async function inspectEip7702(policy, intent, senderCode, source, fetchImpl, timeoutMs) {
  const config = policy.simulation.eip7702;
  const failures = [];
  const delegates = [];
  const cache = new Map();
  let existingDelegate = null;
  if (senderCode !== '0x') {
    if (!/^0xef0100[0-9a-f]{40}$/.test(senderCode)) failures.push(`Sender ${intent.from} has runtime code and is not a valid EIP-7702 delegated EOA.`);
    else {
      existingDelegate = `0x${senderCode.slice(8)}`;
      if (!config.allowDelegatedWallet) failures.push(`EIP-7702 delegation is active for wallet ${intent.from}, but delegated wallets are disabled by policy.`);
      const inspected = await inspectDelegate(policy, existingDelegate, intent.chainId, source, fetchImpl, timeoutMs, cache);
      delegates.push(inspected);
      if (!inspected.valid) failures.push(inspected.failure);
    }
  }
  if (intent.authorizationList != null) {
    if (!config.allowAuthorizationList) failures.push('EIP-7702 authorization lists are disabled by policy.');
    const currentNonce = BigInt(await rpc(source.url, 'eth_getTransactionCount', [intent.from, policy.simulation.blockTag], { fetchImpl, timeoutMs }));
    for (const authorization of intent.authorizationList) {
      const expectedNonce = currentNonce + 1n;
      if (authorization.nonce !== expectedNonce) failures.push(`EIP-7702 authorization nonce ${authorization.nonce} must equal sender nonce plus one (${expectedNonce}).`);
      const inspected = await inspectDelegate(policy, authorization.address, intent.chainId, source, fetchImpl, timeoutMs, cache);
      delegates.push(inspected);
      if (!inspected.valid) failures.push(inspected.failure);
    }
  }
  return { failures, existingDelegate, delegates: [...new Map(delegates.map((delegate) => [delegate.address, delegate])).values()].map(({ address, codeHash, valid }) => ({ address, codeHash: codeHash ?? null, valid })) };
}

async function simulateSource(policy, intent, source, fetchImpl) {
  const config = policy.simulation;
  const tx = rpcTransaction(intent);
  const timeoutMs = config.timeoutMs ?? 12_000;
  const rpcChainId = BigInt(await rpc(source.url, 'eth_chainId', [], { fetchImpl, timeoutMs }));
  if (rpcChainId !== BigInt(intent.chainId)) throw new Error(`Simulation source chain ${rpcChainId} does not match transaction chain ${intent.chainId}.`);
  const blockNumber = BigInt(await rpc(source.url, 'eth_blockNumber', [], { fetchImpl, timeoutMs }));
  const senderCode = String(await rpc(source.url, 'eth_getCode', [intent.from, config.blockTag], { fetchImpl, timeoutMs })).toLowerCase();
  if (!HEX_DATA.test(senderCode)) throw new Error('eth_getCode returned malformed sender code.');
  const eip7702 = await inspectEip7702(policy, intent, senderCode, source, fetchImpl, timeoutMs);
  if (eip7702.failures.length) {
    return {
      sourceId: source.id,
      blockNumber,
      kind: 'violation',
      failures: eip7702.failures,
      fingerprint: sha256({ senderCode, eip7702 }),
      metrics: { senderCode, eip7702, calls: 0, depth: 0 },
      eip7702Violation: true,
    };
  }
  const callResult = await rpc(source.url, 'eth_call', [tx, config.blockTag], { fetchImpl, timeoutMs });
  if (!HEX_DATA.test(String(callResult))) throw new Error('eth_call returned malformed data.');
  const gasEstimate = BigInt(await rpc(source.url, 'eth_estimateGas', [tx, config.blockTag], { fetchImpl, timeoutMs }));
  const callTrace = await rpc(source.url, 'debug_traceCall', [tx, config.blockTag, { tracer: 'callTracer', timeout: `${Math.ceil(timeoutMs / 1000)}s`, tracerConfig: { withLog: true } }], { fetchImpl, timeoutMs });
  if (callTrace?.output != null && (!HEX_DATA.test(String(callTrace.output)) || String(callTrace.output).toLowerCase() !== String(callResult).toLowerCase())) throw new Error('eth_call and call trace returned different outputs.');
  const diffTrace = await rpc(source.url, 'debug_traceCall', [tx, config.blockTag, { tracer: 'prestateTracer', timeout: `${Math.ceil(timeoutMs / 1000)}s`, tracerConfig: { diffMode: true, disableCode: false, disableStorage: false } }], { fetchImpl, timeoutMs });
  const analysis = analyzeTrace(policy, intent, { ...callTrace, output: callTrace.output ?? callResult }, diffTrace, gasEstimate);
  analysis.fingerprint = sha256({ trace: analysis.fingerprint, senderCode, eip7702 });
  analysis.metrics = { ...analysis.metrics, senderCode, eip7702 };
  return { sourceId: source.id, blockNumber, kind: analysis.failures.length ? 'violation' : 'pass', ...analysis, eip7702Violation: false };
}

/** Run exact-transaction call, gas, full call-trace, log, and state-diff simulation through a quorum. */
export async function simulateTransaction(policy, rawIntent, { rpcUrls = {}, fetchImpl = fetch } = {}) {
  const policyValidation = validatePolicy(policy);
  if (!policyValidation.valid) throw new Error(`Invalid simulation policy: ${policyValidation.errors.map((entry) => entry.message).join(' ')}`);
  const normalized = normalizeIntent(rawIntent);
  if (!normalized.valid) throw new Error(`Invalid simulation intent: ${normalized.errors.map((entry) => entry.message).join(' ')}`);
  const intent = normalized.intent;
  const config = policy.simulation;
  if (!config?.required) throw new Error('Policy does not contain required simulation configuration.');
  const sources = config.sources.map((source) => {
    const value = rpcUrls[source.id] ?? process.env[source.env];
    if (!value) throw new Error(`Missing simulation URL for ${source.id}; set ${source.env}.`);
    return { ...source, url: validateUrl(value) };
  });
  if (new Set(sources.map((source) => source.url.href)).size !== sources.length) throw new Error('Simulation sources must use distinct endpoint URLs.');
  const results = await Promise.all(sources.map(async (source) => {
    try { return await simulateSource(policy, intent, source, fetchImpl); }
    catch (cause) { return { sourceId: source.id, kind: 'error', failures: [cause.message], fingerprint: null, metrics: null, blockNumber: null, eip7702Violation: false }; }
  }));
  const blocks = results.map((result) => result.blockNumber).filter((value) => value != null);
  const highestBlock = blocks.length ? blocks.reduce((maximum, value) => value > maximum ? value : maximum) : null;
  for (const result of results) {
    if (result.blockNumber != null && highestBlock - result.blockNumber > BigInt(config.maxBlockSkew)) {
      result.kind = 'error';
      result.failures.push(`Simulation source lags by ${highestBlock - result.blockNumber} blocks.`);
    }
  }
  const passes = results.filter((result) => result.kind === 'pass');
  const violations = results.filter((result) => result.kind === 'violation');
  const fingerprints = new Map();
  for (const result of passes) fingerprints.set(result.fingerprint, [...(fingerprints.get(result.fingerprint) ?? []), result]);
  const consensus = [...fingerprints.entries()].sort((a, b) => b[1].length - a[1].length)[0] ?? [null, []];
  const conflictingPassQuorums = [...fingerprints.values()].filter((group) => group.length >= config.quorum).length > 1;
  const passQuorum = consensus[1].length >= config.quorum && !conflictingPassQuorums;
  const violationQuorum = violations.length >= config.quorum;
  const valid = passQuorum && !violationQuorum;
  const checks = [
    { id: 'eip7702:security', status: results.filter((result) => result.eip7702Violation).length >= config.quorum ? 'deny' : 'pass', detail: `${results.filter((result) => result.eip7702Violation).length}/${sources.length} sources observed an unsafe or unauthorized EIP-7702 state; deny quorum is ${config.quorum}.` },
    { id: 'simulation:available', status: results.some((result) => result.kind !== 'error') ? 'pass' : 'deny', detail: `${results.filter((result) => result.kind !== 'error').length}/${sources.length} simulation sources responded.` },
    { id: 'simulation:policy', status: violationQuorum ? 'deny' : 'pass', detail: `${violations.length}/${sources.length} sources observed policy violations; deny quorum is ${config.quorum}.` },
    { id: 'simulation:consensus', status: passQuorum ? 'pass' : 'deny', detail: `${consensus[1].length}/${sources.length} sources agreed on one passing trace fingerprint; quorum is ${config.quorum}.` },
  ];
  const selected = consensus[1][0];
  return {
    valid,
    checks,
    summary: {
      blockTag: config.blockTag,
      blockNumber: selected?.blockNumber?.toString() ?? null,
      fingerprint: passQuorum ? consensus[0] : null,
      quorum: config.quorum,
      agreeingSources: consensus[1].map((result) => result.sourceId),
      metrics: selected?.metrics ?? null,
      sources: results.map((result) => ({ id: result.sourceId, status: result.kind, failures: result.failures })),
    },
  };
}

export function finalizeSimulation(receipt, result) {
  if (receipt.decision === 'deny') return receipt;
  return {
    ...receipt,
    decision: result.valid ? 'allow' : 'deny',
    simulation: result.summary,
    checks: [...receipt.checks, ...result.checks],
  };
}

export function failedSimulation(receipt, cause) {
  if (receipt.decision === 'deny') return receipt;
  return {
    ...receipt,
    decision: 'deny',
    simulation: null,
    checks: [...receipt.checks, { id: 'simulation:available', status: 'deny', detail: `Simulation failed closed: ${cause.message}` }],
  };
}
