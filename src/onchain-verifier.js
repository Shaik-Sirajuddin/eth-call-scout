import { ALERT_CODES, raiseAlert } from './alerts.js';
import { attackerLookup, describeAttacker, findAttackersInEffects } from './attacker-list.js';
import { blockSpendLimits, spendByAsset } from './block-spend.js';
import { analyzeAssets } from './transaction-simulator.js';

const sameHex = (a, b) => String(a ?? '').toLowerCase() === String(b ?? '').toLowerCase();
const quantity = (value) => { try { return BigInt(value ?? 0).toString(); } catch { return null; } };

function delay(milliseconds) {
  // Keep the process alive while a check is running, so its alerts always reach the log.
  return new Promise((resolve) => { setTimeout(resolve, milliseconds); });
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

  async function verify(transactionHash, decision) {
    const checks = [];
    const raised = [];
    const add = (id, ok, detail) => { checks.push({ id, status: ok ? 'pass' : 'fail', detail }); return ok; };
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
      const blockNumber = quantity(receipt.blockNumber);
      const logs = receipt.logs ?? [];

      if (!add('onchain:status', sameHex(receipt.status, '0x1'), `Receipt status is ${receipt.status}.`)) {
        await alert('critical', ALERT_CODES.ONCHAIN_REVERTED, `Transaction reverted on-chain after passing simulation, and it still cost ${quantity(receipt.gasUsed)} gas.`, { gasUsed: quantity(receipt.gasUsed) }, blockNumber);
      }

      const differences = [];
      if (!transaction) differences.push('the node returned no transaction');
      else {
        if (!sameHex(transaction.from, intent.from)) differences.push(`sender is ${transaction.from}, expected ${intent.from}`);
        if (!sameHex(transaction.to, intent.to)) differences.push(`target is ${transaction.to}, expected ${intent.to}`);
        if (!sameHex(transaction.input ?? transaction.data, intent.data)) differences.push('calldata differs from what was approved');
        if (quantity(transaction.value) !== String(intent.value)) differences.push(`value is ${quantity(transaction.value)}, expected ${intent.value}`);
        if (quantity(transaction.nonce) !== String(intent.nonce)) differences.push(`nonce is ${quantity(transaction.nonce)}, expected ${intent.nonce}`);
      }
      if (!add('onchain:transaction-match', differences.length === 0, differences.length ? `On-chain transaction differs: ${differences.join('; ')}.` : 'Sender, target, calldata, value and nonce match what was approved.')) {
        await alert('critical', ALERT_CODES.ONCHAIN_MISMATCH, `The wallet sent something other than what was approved: ${differences.join('; ')}.`, { differences }, blockNumber);
      }

      const normalizedLogs = logs.map((log) => ({ address: String(log.address).toLowerCase(), topics: (log.topics ?? []).map((topic) => String(topic).toLowerCase()), data: String(log.data ?? '0x').toLowerCase() }));
      const hits = findAttackersInEffects({ calls: [{ to: transaction?.to, input: transaction?.input ?? transaction?.data }], logs: normalizedLogs }, lookup);
      if (!add('onchain:attacker', hits.length === 0, hits.length ? `Attacker address in the mined transaction: ${hits.map(describeAttacker).join(', ')}.` : 'No listed attacker address received value or approval.')) {
        await alert('critical', ALERT_CODES.ONCHAIN_ATTACKER, `Funds or approvals reached a listed attacker on-chain: ${hits.map(describeAttacker).join(', ')}. Revoke approvals and move funds.`, { hits }, blockNumber);
      }

      const wallet = String(intent.from).toLowerCase();
      const assets = analyzeAssets(normalizedLogs, wallet, policy.simulation?.assetLimits ?? [], intent.chainId);
      if (!add('onchain:asset-limits', assets.violations.length === 0, assets.violations.length ? assets.violations.join(' ') : 'Token outflows and approvals stayed within policy limits.')) {
        await alert('critical', ALERT_CODES.ONCHAIN_LIMIT_EXCEEDED, assets.violations.join(' '), { violations: assets.violations }, blockNumber);
      }

      const nativeOutflow = quantity(transaction?.value) ?? '0';
      const limits = blockSpendLimits(policy, intent.chainId);
      if (tracker && limits.size) {
        const breaches = tracker.recordOnChain({ chainId: intent.chainId, wallet, block: blockNumber, spend: spendByAsset({ nativeOutflow, outflows: assets.outflows }), limits });
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
        const moved = Object.entries(assets.outflows).filter(([token, amount]) => BigInt(amount) > BigInt(metrics.outflows[token] ?? 0));
        if (!add('onchain:matches-simulation', moved.length === 0, moved.length ? `More left the wallet than simulation showed: ${moved.map(([token, amount]) => `${amount} of ${token}, simulated ${metrics.outflows[token] ?? 0}`).join('; ')}.` : 'Nothing left the wallet beyond what simulation showed.')) {
          await alert('warning', ALERT_CODES.ONCHAIN_DIFFERS_FROM_SIMULATION, `More left the wallet than simulation showed: ${moved.map(([token, amount]) => `${amount} of ${token}`).join('; ')}. State may have changed before this transaction was mined.`, null, blockNumber);
        }
      }

      // A nonce the guard never handled means something signed for this wallet without going through it.
      const latestCount = BigInt(await request('eth_getTransactionCount', [wallet, 'latest']));
      const unknown = [];
      for (let nonce = BigInt(intent.nonce) + 1n; nonce < latestCount; nonce++) if (!knownNonces.has(nonce.toString())) unknown.push(nonce.toString());
      if (!add('onchain:all-transactions-approved', unknown.length === 0, unknown.length ? `Nonces ${unknown.join(', ')} did not come through the guard.` : 'Every transaction seen from this wallet came through the guard.')) {
        await alert('critical', ALERT_CODES.UNAPPROVED_TRANSACTION, `Wallet ${wallet} sent ${unknown.length} transaction(s) that did not go through the guard (nonces ${unknown.join(', ')}). The key may be exposed.`, { nonces: unknown }, blockNumber);
      }

      return finish(checks.every((check) => check.status === 'pass') ? 'verified' : 'failed', { blockNumber, gasUsed: quantity(receipt.gasUsed), outflows: assets.outflows });
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

