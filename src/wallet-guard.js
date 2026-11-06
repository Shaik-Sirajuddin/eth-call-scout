import { authorizeIntent, sha256 } from './policy.js';
import { failedSimulation, finalizeSimulation, simulateTransaction } from './transaction-simulator.js';

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
export function createGuardedProvider({ provider, policy, authorize = authorizeIntent, simulator = simulateTransaction, simulationOptions = {}, protocolState = null, stateSource = null, stateSequenceStore = null, onDecision = () => {}, now } = {}) {
  if (!provider || typeof provider.request !== 'function') throw new TypeError('provider.request is required');
  if (!policy) throw new TypeError('wallet policy is required');
  if (stateSource != null && typeof stateSource !== 'function') throw new TypeError('stateSource must be a function');
  if (stateSequenceStore != null && (typeof stateSequenceStore.read !== 'function' || typeof stateSequenceStore.write !== 'function')) throw new TypeError('stateSequenceStore requires read and write functions');
  let highestStateSequence = policy.protocolState?.minimumSequence ?? 0;
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
        try { receipt = finalizeSimulation(receipt, await simulator(policy, exactIntent, simulationOptions)); }
        catch (error) { receipt = failedSimulation(receipt, error); }
      }
      await onDecision(receipt);
      if (receipt.decision !== 'allow') throw new WalletGuardError('Wallet guard denied the transaction.', receipt);
      return provider.request(safeRequest);
    },
  });
}

export { READ_ONLY_METHODS };
