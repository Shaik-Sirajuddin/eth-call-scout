import { ALERT_CODES, createConsoleAlerts, raiseAlert } from './alerts.js';
import { assertAttackerList, ATTACKER_LIST } from './attacker-list.js';
import { applyBlockSpendLimits, createBlockSpendTracker } from './block-spend.js';
import { assertGasRules, GAS_RULES } from './gas-limits.js';
import { createOnChainVerifier } from './onchain-verifier.js';
import { authorizeIntent, sha256 } from './policy.js';
import { failedSimulation, finalizeSimulation, rpc, simulateTransaction, validateUrl } from './transaction-simulator.js';

const READ_ONLY_METHODS = new Set([
  'eth_accounts', 'eth_blockNumber', 'eth_call', 'eth_chainId', 'eth_estimateGas',
  'eth_feeHistory', 'eth_gasPrice', 'eth_getBalance', 'eth_getBlockByHash',
  'eth_getBlockByNumber', 'eth_getCode', 'eth_getLogs', 'eth_getStorageAt',
  'eth_getTransactionByHash', 'eth_getTransactionCount', 'eth_getTransactionReceipt',
  'eth_maxPriorityFeePerGas', 'net_version', 'web3_clientVersion',
]);

function cloneJson(value) {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value));
}

function parseChainId(value) {
  try {
    if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return value;
    if (typeof value !== 'string' || (!/^0x[0-9a-fA-F]+$/.test(value) && !/^[1-9][0-9]*$/.test(value))) return null;
    const parsed = BigInt(value);
    return parsed > 0n && parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : null;
  } catch { return null; }
}

function deniedRpcReceipt(method, detail) {
  return {
    version: 1,
    decision: 'deny',
    evaluatedAt: new Date().toISOString(),
    policy: null,
    intent: { rpcMethod: method, hash: sha256({ method }) },
    checks: [{ id: 'rpc:method', status: 'deny', detail }],
  };
}

/**
 * Read the chain through a simulation source, not the wallet being checked. Returns null when none is set
 * up, as with a stubbed simulator, because then there is no independent place to confirm a result.
 */
function independentChainReader(policy, simulationOptions) {
  for (const source of policy?.simulation?.sources ?? []) {
    const value = simulationOptions.rpcUrls?.[source.id] ?? process.env[source.env];
    if (!value) continue;
    const url = validateUrl(value);
    return (method, params) => rpc(url, method, params, { fetchImpl: simulationOptions.fetchImpl ?? fetch, timeoutMs: 12_000 });
  }
  return null;
}

export class WalletGuardError extends Error {
  constructor(message, receipt) {
    super(message);
    this.name = 'WalletGuardError';
    this.code = 4100;
    this.receipt = receipt;
  }
}

/**
 * Wrap an EIP-1193 provider so the agent can read chain state but can only submit an
 * exact eth_sendTransaction after deterministic policy authorization. Raw signing,
 * chain mutation, permissions, and opaque/batched wallet calls are denied.
 */
export function createGuardedProvider({ provider, policy, authorize = authorizeIntent, simulator = simulateTransaction, simulationOptions = {}, protocolState = null, stateSource = null, stateSequenceStore = null, gasRules = GAS_RULES, attackerList = ATTACKER_LIST, alerts = createConsoleAlerts(), blockSpend = createBlockSpendTracker(), verification = {}, onDecision = () => {}, onVerification = () => {}, now } = {}) {
  if (!provider || typeof provider.request !== 'function') throw new TypeError('provider.request is required');
  if (!policy) throw new TypeError('wallet policy is required');
  assertGasRules(gasRules);
  assertAttackerList(attackerList);
  if (simulationOptions.gasRules !== undefined) throw new TypeError('Pass gasRules to createGuardedProvider. Authorization and simulation must use the same set.');
  if (simulationOptions.attackerList !== undefined) throw new TypeError('Pass attackerList to createGuardedProvider. Authorization and simulation must use the same list.');
  if (typeof alerts?.append !== 'function') throw new TypeError('alerts requires an append function');
  const chainRequest = verification === false ? null : verification.request ?? independentChainReader(policy, simulationOptions);
  const verifier = chainRequest ? createOnChainVerifier({ request: chainRequest, policy, attackerList, alerts, tracker: blockSpend, timeoutMs: verification.timeoutMs, pollMs: verification.pollMs, now: now ? () => now : undefined }) : null;
  const verifications = new Map();
  if (stateSource != null && typeof stateSource !== 'function') throw new TypeError('stateSource must be a function');
  if (stateSequenceStore != null && (typeof stateSequenceStore.read !== 'function' || typeof stateSequenceStore.write !== 'function')) throw new TypeError('stateSequenceStore requires read and write functions');
  let highestStateSequence = policy.protocolState?.minimumSequence ?? 0;
  async function raiseDecisionAlerts(receipt, spendBreaches) {
    if (receipt.decision === 'allow') return;
    const attackerChecks = receipt.checks.filter((check) => check.status === 'deny' && check.id.startsWith('attacker:') && check.id !== 'attacker:list-match');
    if (attackerChecks.length) {
      await raiseAlert(alerts, { severity: 'critical', code: ALERT_CODES.ATTACKER_BLOCKED, message: `Blocked a transaction involving a listed attacker. ${attackerChecks[0].detail} The agent may be compromised.`, details: { intentHash: receipt.intent?.hash ?? null, to: receipt.intent?.to ?? null, checks: attackerChecks } }, () => new Date());
    }
    if (spendBreaches.length) {
      await raiseAlert(alerts, { severity: 'warning', code: ALERT_CODES.BLOCK_LIMIT_REACHED, message: receipt.checks.find((check) => check.id === 'spend:block-limit')?.detail ?? 'Per-block spend limit reached.', blockNumber: receipt.simulation?.blockNumber ?? null, details: { intentHash: receipt.intent?.hash ?? null, breaches: spendBreaches } }, () => new Date());
    }
  }

  return Object.freeze({
    async request(request) {
      let safeRequest;
      try { safeRequest = cloneJson(request); }
      catch {
        const receipt = deniedRpcReceipt('(unreadable)', 'RPC request must be plain JSON data.');
        await onDecision(receipt);
        throw new WalletGuardError('Wallet guard denied a non-serializable RPC request.', receipt);
      }
      const method = safeRequest?.method;
      if (READ_ONLY_METHODS.has(method)) return provider.request(safeRequest);
      if (method !== 'eth_sendTransaction') {
        const receipt = deniedRpcReceipt(method ?? '(missing)', 'Only read-only RPC methods and guarded eth_sendTransaction are exposed to the agent.');
        await onDecision(receipt);
        throw new WalletGuardError(`Wallet guard denied RPC method ${method ?? '(missing)'}.`, receipt);
      }
      const transaction = safeRequest.params?.[0];
      let chainId;
      try { chainId = await provider.request({ method: 'eth_chainId', params: [] }); }
      catch {
        const receipt = deniedRpcReceipt(method, 'Could not establish the wallet network before authorization.');
        await onDecision(receipt);
        throw new WalletGuardError('Wallet guard could not establish the active chain.', receipt);
      }
      const activeChainId = parseChainId(chainId);
      if (activeChainId == null) {
        const receipt = deniedRpcReceipt(method, 'Wallet returned a malformed or unsupported active chain ID.');
        await onDecision(receipt);
        throw new WalletGuardError('Wallet guard could not validate the active chain.', receipt);
      }
      let currentState = protocolState;
      if (stateSource) {
        try { currentState = await stateSource(); }
        catch { currentState = null; }
      }
      let sequenceStoreError = null;
      if (stateSequenceStore) {
        try { highestStateSequence = Math.max(highestStateSequence, await stateSequenceStore.read()); }
        catch (error) { sequenceStoreError = error; }
      }
      const exactIntent = transaction;
      let receipt = await authorize(policy, exactIntent, {
        now,
        protocolState: currentState,
        minimumStateSequence: highestStateSequence,
        gasRules,
        attackerList,
      });
      if (receipt.intent) {
        const activeChainMatches = receipt.intent.chainId === activeChainId;
        receipt = {
          ...receipt,
          decision: activeChainMatches ? receipt.decision : 'deny',
          checks: [...receipt.checks, {
            id: 'wallet:active-chain',
            status: activeChainMatches ? 'pass' : 'deny',
            detail: `Transaction chain ${receipt.intent.chainId} must exactly match active wallet chain ${activeChainId}.`,
          }],
        };
      }
      if (receipt.protocolState?.authenticated && Number.isSafeInteger(receipt.protocolState.sequence)) {
        const nextSequence = Math.max(highestStateSequence, receipt.protocolState.sequence);
        if (stateSequenceStore && !sequenceStoreError) {
          try { await stateSequenceStore.write(nextSequence); }
          catch (error) { sequenceStoreError = error; }
        }
        highestStateSequence = nextSequence;
      }
      if (sequenceStoreError && policy.protocolState?.required) {
        receipt = { ...receipt, decision: 'deny', checks: [...receipt.checks, { id: 'state:sequence-store', status: 'deny', detail: `Could not persist rollback protection: ${sequenceStoreError.message}` }] };
      }
      if (receipt.decision !== 'deny' && policy.simulation?.required) {
        try {
          receipt = finalizeSimulation(receipt, await simulator(policy, exactIntent, {
            ...simulationOptions,
            protocolState: currentState,
            minimumStateSequence: highestStateSequence,
            now,
            gasRules,
            attackerList,
          }));
        }
        catch (error) { receipt = failedSimulation(receipt, error); }
      }
      let reservation = null;
      let spendBreaches = [];
      if (receipt.decision === 'allow') {
        ({ receipt, reservation, breaches: spendBreaches } = applyBlockSpendLimits(policy, receipt, blockSpend));
      }
      try { await onDecision(receipt); }
      catch (error) { blockSpend.release(reservation); throw error; }
      await raiseDecisionAlerts(receipt, spendBreaches);
      if (receipt.decision !== 'allow') throw new WalletGuardError('Wallet guard denied the transaction.', receipt);

      const nonce = receipt.intent?.nonce;
      if (nonce != null) verifier?.expectNonce(nonce);
      let transactionHash;
      try { transactionHash = await provider.request(safeRequest); }
      catch (error) {
        blockSpend.release(reservation);
        if (nonce != null) verifier?.forgetNonce(nonce);
        throw error;
      }
      // Runs in the background so the agent is not held up. Failures become alerts for the operator.
      if (verifier && typeof transactionHash === 'string') {
        const pending = verifier.verify(transactionHash, receipt).then(async (result) => {
          try { await onVerification(result); }
          catch (error) { process.stderr.write(`[keybound] onVerification failed: ${error.message}\n`); }
          return result;
        });
        verifications.set(transactionHash.toLowerCase(), pending);
      }
      return transactionHash;
    },
    /** The on-chain check for one forwarded transaction. Null when verification is not set up. */
    verification(transactionHash) { return verifications.get(String(transactionHash).toLowerCase()) ?? null; },
    /** Wait for every on-chain check started so far. */
    async settled() { return Promise.all(verifications.values()); },
  });
}

export { READ_ONLY_METHODS };
