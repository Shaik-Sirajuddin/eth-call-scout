import { id } from 'ethers';
import { ALERT_CODES, raiseAlert } from './alerts.js';
import { attackerLookup, describeAttacker, findAttackersInEffects } from './attacker-list.js';
import { blockSpendLimits, spendByAsset } from './block-spend.js';
import { analyzeAssets } from './transaction-simulator.js';

const TRANSFER_TOPIC = id('Transfer(address,address,uint256)').toLowerCase();
const TRACE_ATTEMPTS = 3;

const sameHex = (a, b) => String(a ?? '').toLowerCase() === String(b ?? '').toLowerCase();
const quantity = (value) => { try { return BigInt(value ?? 0).toString(); } catch { return null; } };
/** Unlike quantity, a missing field stays missing, so a node that leaves one out cannot look like a match. */
const exactQuantity = (value) => { if (value == null) return null; try { return BigInt(value).toString(); } catch { return null; } };

function delay(milliseconds) {
  // Keep the process alive while a check is running, so its alerts always reach the log.
  return new Promise((resolve) => { setTimeout(resolve, milliseconds); });
}

/** Order inside an access list changes nothing on-chain, so compare it sorted. An empty list equals none. */
function canonicalAccessList(list) {
  return JSON.stringify((Array.isArray(list) ? list : [])
    .map((entry) => ({ address: String(entry?.address ?? '').toLowerCase(), storageKeys: (Array.isArray(entry?.storageKeys) ? entry.storageKeys : []).map((key) => String(key).toLowerCase()).sort() }))
    .sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0)));
}

/** Authorizations apply in order, so their order is part of what was approved. */
function canonicalAuthorizationList(list) {
  return JSON.stringify((Array.isArray(list) ? list : []).map((entry) => ({
    chainId: exactQuantity(entry?.chainId),
    address: String(entry?.address ?? '').toLowerCase(),
    nonce: exactQuantity(entry?.nonce),
    yParity: exactQuantity(entry?.yParity ?? entry?.v),
    r: exactQuantity(entry?.r),
    s: exactQuantity(entry?.s),
  })));
}

/** The type the guard approved. An omitted type is still fixed by the fee model the policy allowed. */
function expectedType(intent) {
  if (intent.type != null) return String(intent.type);
  if (intent.authorizationList != null) return '4';
  return intent.maxFeePerGas != null ? '2' : '0';
}

/**
 * List every way a mined transaction differs from what was approved. This covers each field the wallet signed,
 * so a wallet cannot raise the gas or fees of an approved call without an alert.
 */
export function envelopeDifferences(transaction, intent, transactionHash = null) {
  if (!transaction) return ['the node returned no transaction'];
  const differences = [];
  const compare = (label, actual, expected) => { if (actual !== expected) differences.push(`${label} is ${actual ?? '(missing)'}, expected ${expected ?? '(none)'}`); };
  if (transactionHash && transaction.hash != null && !sameHex(transaction.hash, transactionHash)) differences.push(`hash is ${transaction.hash}, expected ${transactionHash}`);
  compare('chain ID', exactQuantity(transaction.chainId), String(intent.chainId));
  if (!sameHex(transaction.from, intent.from)) differences.push(`sender is ${transaction.from ?? '(missing)'}, expected ${intent.from}`);
  if (!sameHex(transaction.to, intent.to)) differences.push(`target is ${transaction.to ?? '(missing)'}, expected ${intent.to}`);
  if (!sameHex(transaction.input ?? transaction.data, intent.data)) differences.push('calldata differs from what was approved');
  compare('value', exactQuantity(transaction.value), String(intent.value));
  compare('nonce', exactQuantity(transaction.nonce), String(intent.nonce));
  compare('type', exactQuantity(transaction.type), expectedType(intent));
  if (intent.gas != null) compare('gas limit', exactQuantity(transaction.gas ?? transaction.gasLimit), String(intent.gas));
  // On a mined EIP-1559 transaction, gasPrice is the price paid, so it is only an approved field on a legacy one.
  if (intent.gasPrice != null) compare('gas price', exactQuantity(transaction.gasPrice), String(intent.gasPrice));
  if (intent.maxFeePerGas != null) compare('max fee per gas', exactQuantity(transaction.maxFeePerGas), String(intent.maxFeePerGas));
  if (intent.maxPriorityFeePerGas != null) compare('max priority fee', exactQuantity(transaction.maxPriorityFeePerGas), String(intent.maxPriorityFeePerGas));
  if (canonicalAccessList(transaction.accessList) !== canonicalAccessList(intent.accessList)) differences.push('access list differs from what was approved');
  if (canonicalAuthorizationList(transaction.authorizationList) !== canonicalAuthorizationList(intent.authorizationList)) differences.push('authorization list differs from what was approved');
  return differences;
}

/** Flatten a call trace. Returns null for anything malformed, so a bad trace can never count as a clean one. */
export function flattenCallTrace(trace) {
  const calls = [];
  const visit = (node, reverted) => {
    if (!node || typeof node !== 'object' || Array.isArray(node) || typeof node.from !== 'string') return false;
    const failed = reverted || Boolean(node.error);
    calls.push({ type: String(node.type ?? 'CALL').toUpperCase(), from: node.from.toLowerCase(), to: node.to ? String(node.to).toLowerCase() : null, value: node.value ?? '0x0', input: node.input ?? '0x', reverted: failed });
    return (node.calls ?? []).every((child) => visit(child, failed));
  };
  return visit(trace, false) ? calls : null;
}

/** ETH the wallet really sent. Reverted frames moved nothing, and a delegatecall only reports its parent's value. */
function nativeSentBy(wallet, calls) {
  return calls
    .filter((call) => call.from === wallet && !call.reverted && !['DELEGATECALL', 'CALLCODE', 'STATICCALL'].includes(call.type))
    .reduce((total, call) => total + BigInt(call.value ?? '0x0'), 0n);
}

function tokensReceivedBy(wallet, logs) {
  const received = new Map();
  for (const log of logs) {
    if (log.topics[0] !== TRANSFER_TOPIC || `0x${String(log.topics[2] ?? '').slice(-40)}` !== wallet || !/^0x[0-9a-f]{64}$/.test(log.data)) continue;
    received.set(log.address, (received.get(log.address) ?? 0n) + BigInt(log.data));
  }
  return received;
}

/**
 * Check a forwarded transaction against the chain after it lands. Simulation predicts; this confirms.
 * It never blocks the agent. Every failure becomes an alert for the operator to read in the logs.
 */
export function createOnChainVerifier({ request, policy, attackerList, alerts, tracker = null, timeoutMs = 180_000, pollMs = 2_000, now = () => new Date() }) {
  if (typeof request !== 'function') throw new TypeError('request is required');
  const knownNonces = new Set();
  const lookup = attackerLookup(attackerList, policy);

  async function waitForReceipt(transactionHash) {
    const deadline = Date.now() + timeoutMs;
    let lastError = null;
    for (;;) {
      try {
        const receipt = await request('eth_getTransactionReceipt', [transactionHash]);
        if (receipt) return { receipt };
      } catch (error) { lastError = error; }
      if (Date.now() >= deadline) return { receipt: null, lastError };
      await delay(pollMs);
    }
  }

  /** Some nodes need a moment before they can trace a new block, so try a few times. */
  async function readInternalCalls(transactionHash) {
    let reason = 'the node returned a malformed trace';
    for (let attempt = 0; attempt < TRACE_ATTEMPTS; attempt++) {
      if (attempt) await delay(pollMs);
      try {
        const calls = flattenCallTrace(await request('debug_traceTransaction', [transactionHash, { tracer: 'callTracer' }]));
        if (calls) return { calls, reason: null };
      } catch (error) { reason = error.message; }
    }
    return { calls: null, reason };
  }

  async function verify(transactionHash, decision) {
    const checks = [];
    const raised = [];
    const add = (checkId, ok, detail) => { checks.push({ id: checkId, status: ok ? 'pass' : 'fail', detail }); return ok; };
    const alert = async (severity, code, message, details = null, blockNumber = null) => {
      raised.push(await raiseAlert(alerts, { severity, code, message, transactionHash, blockNumber, details }, now));
    };
    const finish = (status, extra = {}) => ({ version: 1, kind: 'onchain-verification', transactionHash, status, verifiedAt: new Date(now()).toISOString(), policy: decision?.policy ?? null, checks, alerts: raised, ...extra });

    try {
      const { receipt, lastError } = await waitForReceipt(transactionHash);
      if (!receipt) {
        const unavailable = Boolean(lastError);
        await alert('warning', unavailable ? ALERT_CODES.ONCHAIN_UNAVAILABLE : ALERT_CODES.ONCHAIN_NOT_MINED, unavailable ? `Could not read the transaction from the chain: ${lastError.message}` : `Transaction was not mined within ${Math.round(timeoutMs / 1000)} seconds. Check it by hand.`);
        return finish(unavailable ? 'unavailable' : 'not-mined');
      }
      const transaction = await request('eth_getTransactionByHash', [transactionHash]);
      const intent = decision.intent;
      const wallet = String(intent.from).toLowerCase();
      const blockNumber = quantity(receipt.blockNumber);
      const logs = receipt.logs ?? [];
      const succeeded = sameHex(receipt.status, '0x1');

      if (!add('onchain:status', succeeded, `Receipt status is ${receipt.status}.`)) {
        await alert('critical', ALERT_CODES.ONCHAIN_REVERTED, `Transaction reverted on-chain after passing simulation, and it still cost ${quantity(receipt.gasUsed)} gas.`, { gasUsed: quantity(receipt.gasUsed) }, blockNumber);
      }

      const differences = envelopeDifferences(transaction, intent, transactionHash);
      if (!add('onchain:transaction-match', differences.length === 0, differences.length ? `On-chain transaction differs: ${differences.join('; ')}.` : 'Every signed field matches what was approved: chain, sender, target, calldata, value, nonce, type, gas, fees, access list and authorizations.')) {
        await alert('critical', ALERT_CODES.ONCHAIN_MISMATCH, `The wallet sent something other than what was approved: ${differences.join('; ')}.`, { differences }, blockNumber);
      }

      const normalizedLogs = logs.map((log) => ({ address: String(log.address).toLowerCase(), topics: (log.topics ?? []).map((topic) => String(topic).toLowerCase()), data: String(log.data ?? '0x').toLowerCase() }));
      const outerCall = { type: 'CALL', from: wallet, to: transaction?.to, value: transaction?.value ?? '0x0', input: transaction?.input ?? transaction?.data ?? '0x', reverted: !succeeded };
      const trace = await readInternalCalls(transactionHash);
      const calls = trace.calls ?? [outerCall];
      const hits = findAttackersInEffects({ calls, logs: normalizedLogs }, lookup);
      if (hits.length) {
        add('onchain:attacker', false, `Attacker address in the mined transaction: ${hits.map((hit) => `${describeAttacker(hit)}, ${hit.reasons.join('; ')}`).join(' | ')}.`);
        await alert('critical', ALERT_CODES.ONCHAIN_ATTACKER, `Funds or approvals reached a listed attacker on-chain: ${hits.map(describeAttacker).join(', ')}. Revoke approvals and move funds.`, { hits }, blockNumber);
      } else if (trace.calls) {
        add('onchain:attacker', true, `No listed attacker was called, paid or approved across ${calls.length} call(s) and ${normalizedLogs.length} log(s), including internal ETH transfers.`);
      } else {
        // Logs do not show internal ETH transfers, so a clean result here would claim more than was checked.
        checks.push({ id: 'onchain:attacker', status: 'unknown', detail: `The outer call and logs show no listed attacker, but internal calls could not be read (${trace.reason}), so internal ETH transfers were not checked.` });
        await alert('warning', ALERT_CODES.ONCHAIN_TRACE_UNAVAILABLE, `Could not trace this transaction (${trace.reason}), so internal ETH transfers were not checked for attackers. Check it by hand.`, null, blockNumber);
      }

      const assets = analyzeAssets(normalizedLogs, wallet, policy.simulation?.assetLimits ?? [], intent.chainId);
      if (!add('onchain:asset-limits', assets.violations.length === 0, assets.violations.length ? assets.violations.join(' ') : 'Token outflows and approvals stayed within policy limits.')) {
        await alert('critical', ALERT_CODES.ONCHAIN_LIMIT_EXCEEDED, assets.violations.join(' '), { violations: assets.violations }, blockNumber);
      }

      const nativeOutflow = nativeSentBy(wallet, calls);
      const nativeLimit = policy.invariants?.maxNativeValueWei;
      if (nativeLimit != null && !add('onchain:native-limit', nativeOutflow <= BigInt(nativeLimit), `The wallet sent ${nativeOutflow} wei; the policy allows ${nativeLimit} per transaction.`)) {
        await alert('critical', ALERT_CODES.ONCHAIN_LIMIT_EXCEEDED, `The wallet sent ${nativeOutflow} wei, over the policy limit of ${nativeLimit}.`, null, blockNumber);
      }

      const limits = blockSpendLimits(policy, intent.chainId);
      if (tracker && limits.size) {
        const breaches = tracker.recordOnChain({ chainId: intent.chainId, wallet, block: blockNumber, spend: spendByAsset({ nativeOutflow: nativeOutflow.toString(), outflows: assets.outflows }), limits });
        if (!add('onchain:block-limit', breaches.length === 0, breaches.length ? `Block ${blockNumber} went over a spend limit for ${breaches[0].assetName}.` : `Spend in block ${blockNumber} stayed within every per-block limit.`)) {
          await alert('critical', ALERT_CODES.ONCHAIN_LIMIT_EXCEEDED, `Block ${blockNumber} spent ${breaches[0].total} of ${breaches[0].assetName}, over the limit of ${breaches[0].limit}.`, { breaches }, blockNumber);
        }
      }

      const metrics = decision.simulation?.metrics;
      if (metrics?.gasLimit != null) {
        if (!add('onchain:gas', BigInt(receipt.gasUsed ?? 0) <= BigInt(metrics.gasLimit), `Used ${quantity(receipt.gasUsed)} gas; this function allows ${metrics.gasLimit}.`)) {
          await alert('warning', ALERT_CODES.ONCHAIN_GAS_EXCEEDED, `Used ${quantity(receipt.gasUsed)} gas, over this function's limit of ${metrics.gasLimit}.`, null, blockNumber);
        }
      }
      if (metrics?.outflows) {
        const moved = Object.entries(assets.outflows).filter(([token, amount]) => BigInt(amount) > BigInt(metrics.outflows[token] ?? 0)).map(([token, amount]) => `${amount} of ${token}, simulated ${metrics.outflows[token] ?? 0}`);
        if (metrics.nativeOutflow != null && nativeOutflow > BigInt(metrics.nativeOutflow)) moved.push(`${nativeOutflow} wei, simulated ${metrics.nativeOutflow}`);
        if (!add('onchain:matches-simulation', moved.length === 0, moved.length ? `More left the wallet than simulation showed: ${moved.join('; ')}.` : 'Nothing left the wallet beyond what simulation showed.')) {
          await alert('warning', ALERT_CODES.ONCHAIN_DIFFERS_FROM_SIMULATION, `More left the wallet than simulation showed: ${moved.join('; ')}. State may have changed before this transaction was mined.`, null, blockNumber);
        }
      }
      if (succeeded && metrics?.swaps?.length) {
        const received = tokensReceivedBy(wallet, normalizedLogs);
        const required = new Map();
        for (const swap of metrics.swaps) required.set(swap.tokenOut, (required.get(swap.tokenOut) ?? 0n) + BigInt(swap.requiredOut));
        const short = [...required].filter(([token, amount]) => (received.get(token) ?? 0n) < amount).map(([token, amount]) => `${received.get(token) ?? 0n} of ${token}, needed at least ${amount}`);
        if (!add('onchain:swap-output', short.length === 0, short.length ? `The wallet received too little: ${short.join('; ')}.` : 'The wallet received at least the minimum set from the fresh quote.')) {
          await alert('critical', ALERT_CODES.ONCHAIN_SWAP_OUTPUT, `The wallet received too little from a swap: ${short.join('; ')}.`, null, blockNumber);
        }
      }

      // A nonce the guard never handled means something signed for this wallet without going through it.
      const latestCount = BigInt(await request('eth_getTransactionCount', [wallet, 'latest']));
      const unknown = [];
      for (let nonce = BigInt(intent.nonce) + 1n; nonce < latestCount; nonce++) if (!knownNonces.has(nonce.toString())) unknown.push(nonce.toString());
      if (!add('onchain:all-transactions-approved', unknown.length === 0, unknown.length ? `Nonces ${unknown.join(', ')} did not come through the guard.` : 'Every transaction seen from this wallet came through the guard.')) {
        await alert('critical', ALERT_CODES.UNAPPROVED_TRANSACTION, `Wallet ${wallet} sent ${unknown.length} transaction(s) that did not go through the guard (nonces ${unknown.join(', ')}). The key may be exposed.`, { nonces: unknown }, blockNumber);
      }

      const status = checks.some((check) => check.status === 'fail') ? 'failed' : checks.some((check) => check.status === 'unknown') ? 'incomplete' : 'verified';
      return finish(status, { blockNumber, gasUsed: quantity(receipt.gasUsed), nativeOutflow: nativeOutflow.toString(), outflows: assets.outflows, internalCallsChecked: trace.calls ? calls.length : null });
    } catch (error) {
      await alert('warning', ALERT_CODES.ONCHAIN_UNAVAILABLE, `On-chain verification could not finish: ${error.message}`);
      return finish('unavailable');
    }
  }

  return Object.freeze({
    /** Note a nonce before forwarding, so it can never be mistaken for a transaction sent around the guard. */
    expectNonce(nonce) { knownNonces.add(String(nonce)); },
    forgetNonce(nonce) { knownNonces.delete(String(nonce)); },
    verify,
  });
}
