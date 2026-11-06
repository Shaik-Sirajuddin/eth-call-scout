import fs from 'node:fs';
import crypto from 'node:crypto';
import { verifyAuthorization } from 'ethers';
import { canonicalJson, sha256 } from './canonical.js';
import { assertAttackerList, ATTACKER_LIST, attackerListIdentity, attackerLookup, describeAttacker, findAttackersInHex } from './attacker-list.js';
import { assertGasRules, GAS_RULES, gasRulesIdentity } from './gas-limits.js';
import { evaluateProtocolState } from './protocol-state.js';

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const SELECTOR = /^0x[a-fA-F0-9]{8}$/;
const HEX_DATA = /^0x(?:[a-fA-F0-9]{2})*$/;
const STORAGE_KEY = /^0x[a-fA-F0-9]{64}$/;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]*)$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const SWAP_QUOTE_KINDS = new Set(['uniswap-v3-exact-input-single']);
const MAX_SLIPPAGE_BPS = 5000n;
const HIGH_SLIPPAGE_BPS = 500n;
// Common swap functions, flagged by audit when a policy allows them with no fresh-quote check.
const UNQUOTED_SWAP_SELECTORS = new Set(['0x04e45aaf', '0x414bf389', '0xb858183f', '0xc04b8d59', '0x38ed1739', '0x7ff36ab5', '0x18cbafe5', '0x8803dbee', '0xfb3bdb41', '0x4a25d94a', '0x3593564c', '0x24856bc3']);
const MAX_UINT64 = (1n << 64n) - 1n;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const MIN_TRANSACTION_GAS = 21000n;
const PER_AUTHORIZATION_GAS = 25000n;

function issue(code, path, message, severity = 'error') {
  return { code, path, message, severity };
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function rejectUnknown(object, allowed, path, errors) {
  if (!isPlainObject(object)) return;
  for (const key of Object.keys(object)) if (!allowed.has(key)) errors.push(issue('unknown-field', `${path}.${key}`, 'Unknown fields are rejected because they may look enforced while being ignored.'));
}

function validateProtocolStateConfig(config, errors) {
  const path = '$.protocolState';
  if (!isPlainObject(config)) { errors.push(issue('invalid-state-policy', path, 'protocolState must be an object.')); return; }
  rejectUnknown(config, new Set(['required', 'maxAgeSeconds', 'maxClockSkewSeconds', 'minimumSequence', 'threshold', 'trustedKeys']), path, errors);
  if (config.required !== true) errors.push(issue('state-not-required', `${path}.required`, 'Configured protocol state must be required.'));
  if (!Number.isSafeInteger(config.maxAgeSeconds) || config.maxAgeSeconds < 1 || config.maxAgeSeconds > 86400) errors.push(issue('invalid-state-age', `${path}.maxAgeSeconds`, 'maxAgeSeconds must be an integer from 1 to 86400.'));
  if (config.maxClockSkewSeconds != null && (!Number.isSafeInteger(config.maxClockSkewSeconds) || config.maxClockSkewSeconds < 0 || config.maxClockSkewSeconds > 300)) errors.push(issue('invalid-clock-skew', `${path}.maxClockSkewSeconds`, 'maxClockSkewSeconds must be an integer from 0 to 300.'));
  if (config.minimumSequence != null && (!Number.isSafeInteger(config.minimumSequence) || config.minimumSequence < 0)) errors.push(issue('invalid-minimum-sequence', `${path}.minimumSequence`, 'minimumSequence must be a non-negative safe integer.'));
  if (!Array.isArray(config.trustedKeys) || !config.trustedKeys.length) errors.push(issue('missing-state-keys', `${path}.trustedKeys`, 'At least one pinned state-signing key is required.'));
  else {
    const ids = new Set();
    config.trustedKeys.forEach((key, index) => {
      const keyPath = `${path}.trustedKeys[${index}]`;
      if (!isPlainObject(key)) { errors.push(issue('invalid-state-key', keyPath, 'Trusted key must be an object.')); return; }
      rejectUnknown(key, new Set(['id', 'algorithm', 'publicKey']), keyPath, errors);
      if (typeof key.id !== 'string' || !key.id.trim()) errors.push(issue('invalid-state-key-id', `${keyPath}.id`, 'Trusted key requires an ID.'));
      if (ids.has(key.id)) errors.push(issue('duplicate-state-key', keyPath, 'Trusted key IDs must be unique.'));
      ids.add(key.id);
      if (key.algorithm !== 'ed25519') errors.push(issue('invalid-state-algorithm', `${keyPath}.algorithm`, 'Only Ed25519 state keys are supported.'));
      if (typeof key.publicKey !== 'string' || key.publicKey.length < 40 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(key.publicKey)) errors.push(issue('invalid-state-public-key', `${keyPath}.publicKey`, 'publicKey must be base64 SPKI DER.'));
      else {
        try {
          const publicKey = crypto.createPublicKey({ key: Buffer.from(key.publicKey, 'base64'), format: 'der', type: 'spki' });
          if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
        } catch { errors.push(issue('invalid-state-public-key', `${keyPath}.publicKey`, 'publicKey must decode to an Ed25519 SPKI key.')); }
      }
    });
  }
  if (!Number.isSafeInteger(config.threshold) || config.threshold < 1 || (Array.isArray(config.trustedKeys) && config.threshold > config.trustedKeys.length)) errors.push(issue('invalid-state-threshold', `${path}.threshold`, 'threshold must be between 1 and the number of trusted keys.'));
}

function validateSimulationConfig(config, errors) {
  const path = '$.simulation';
  if (!isPlainObject(config)) { errors.push(issue('invalid-simulation-policy', path, 'simulation must be an object.')); return; }
  rejectUnknown(config, new Set(['required', 'blockTag', 'timeoutMs', 'quorum', 'maxBlockSkew', 'maxGasEstimate', 'maxCallDepth', 'maxInternalCalls', 'maxStateAccounts', 'maxStorageWrites', 'denyCodeChanges', 'allowedCallTypes', 'internalTargets', 'assetLimits', 'eip7702', 'sources']), path, errors);
  if (config.required !== true) errors.push(issue('simulation-not-required', `${path}.required`, 'Full transaction simulation must be required.'));
  if (!['latest', 'pending'].includes(config.blockTag)) errors.push(issue('invalid-simulation-block', `${path}.blockTag`, 'blockTag must be latest or pending.'));
  if (config.timeoutMs != null && (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1000 || config.timeoutMs > 30000)) errors.push(issue('invalid-simulation-timeout', `${path}.timeoutMs`, 'timeoutMs must be between 1000 and 30000.'));
  if (!Number.isSafeInteger(config.maxBlockSkew) || config.maxBlockSkew < 0 || config.maxBlockSkew > 100) errors.push(issue('invalid-simulation-block-skew', `${path}.maxBlockSkew`, 'maxBlockSkew must be an integer from 0 to 100.'));
  parseUint(config.maxGasEstimate, `${path}.maxGasEstimate`, errors, { optional: false });
  for (const [field, maximum] of [['maxCallDepth', 64], ['maxInternalCalls', 2000], ['maxStateAccounts', 5000], ['maxStorageWrites', 10000]]) {
    if (!Number.isSafeInteger(config[field]) || config[field] < 1 || config[field] > maximum) errors.push(issue('invalid-simulation-limit', `${path}.${field}`, `${field} must be an integer from 1 to ${maximum}.`));
  }
  if (config.denyCodeChanges !== true) errors.push(issue('unsafe-code-change-setting', `${path}.denyCodeChanges`, 'The secure simulation profile must deny code changes.'));
  const supportedTypes = new Set(['CALL', 'STATICCALL', 'DELEGATECALL', 'CALLCODE']);
  if (!Array.isArray(config.allowedCallTypes) || !config.allowedCallTypes.length) errors.push(issue('missing-call-types', `${path}.allowedCallTypes`, 'At least one allowed call type is required.'));
  else config.allowedCallTypes.forEach((type, index) => { if (!supportedTypes.has(type)) errors.push(issue('invalid-call-type', `${path}.allowedCallTypes[${index}]`, `Unsupported call type ${type}.`)); });
  if (!Array.isArray(config.internalTargets)) errors.push(issue('invalid-internal-targets', `${path}.internalTargets`, 'internalTargets must be an array.'));
  else config.internalTargets.forEach((target, index) => {
    const at = `${path}.internalTargets[${index}]`;
    if (!isPlainObject(target)) { errors.push(issue('invalid-internal-target', at, 'Internal target must be an object.')); return; }
    rejectUnknown(target, new Set(['chainId', 'address']), at, errors);
    if (!Number.isSafeInteger(target.chainId) || target.chainId < 1) errors.push(issue('invalid-chain', `${at}.chainId`, 'chainId must be a positive safe integer.'));
    if (!ADDRESS.test(String(target.address ?? ''))) errors.push(issue('invalid-address', `${at}.address`, 'Expected a 20-byte address.'));
  });
  if (!Array.isArray(config.assetLimits)) errors.push(issue('invalid-asset-limits', `${path}.assetLimits`, 'assetLimits must be an array.'));
  else {
    const tokens = new Set();
    config.assetLimits.forEach((limit, index) => {
      const at = `${path}.assetLimits[${index}]`;
      if (!isPlainObject(limit)) { errors.push(issue('invalid-asset-limit', at, 'Asset limit must be an object.')); return; }
      rejectUnknown(limit, new Set(['chainId', 'token', 'maxOutflow', 'maxOutflowPerBlock', 'maxApproval', 'allowedRecipients', 'allowedSpenders']), at, errors);
      if (!Number.isSafeInteger(limit.chainId) || limit.chainId < 1) errors.push(issue('invalid-chain', `${at}.chainId`, 'chainId must be a positive safe integer.'));
      if (!ADDRESS.test(String(limit.token ?? ''))) errors.push(issue('invalid-address', `${at}.token`, 'Asset limit requires an exact token address.'));
      const token = `${limit.chainId}:${String(limit.token).toLowerCase()}`;
      if (tokens.has(token)) errors.push(issue('duplicate-asset-limit', at, 'Each token may have only one asset limit.'));
      tokens.add(token);
      parseUint(limit.maxOutflow, `${at}.maxOutflow`, errors, { optional: false });
      parseUint(limit.maxOutflowPerBlock, `${at}.maxOutflowPerBlock`, errors);
      parseUint(limit.maxApproval, `${at}.maxApproval`, errors, { optional: false });
      for (const field of ['allowedRecipients', 'allowedSpenders']) {
        if (!Array.isArray(limit[field])) errors.push(issue('invalid-address-list', `${at}.${field}`, `${field} must be an array.`));
        else limit[field].forEach((address, addressIndex) => { if (!ADDRESS.test(String(address))) errors.push(issue('invalid-address', `${at}.${field}[${addressIndex}]`, 'Expected a 20-byte address.')); });
      }
    });
  }
  const eip7702 = config.eip7702;
  const eipPath = `${path}.eip7702`;
  if (!isPlainObject(eip7702)) errors.push(issue('missing-eip7702-policy', eipPath, 'simulation.eip7702 must explicitly define the delegated-EOA boundary.'));
  else {
    rejectUnknown(eip7702, new Set(['allowAuthorizationList', 'allowDelegatedWallet', 'maxAuthorizations', 'delegates']), eipPath, errors);
    if (typeof eip7702.allowAuthorizationList !== 'boolean') errors.push(issue('invalid-eip7702-setting', `${eipPath}.allowAuthorizationList`, 'allowAuthorizationList must be boolean.'));
    if (typeof eip7702.allowDelegatedWallet !== 'boolean') errors.push(issue('invalid-eip7702-setting', `${eipPath}.allowDelegatedWallet`, 'allowDelegatedWallet must be boolean.'));
    if (eip7702.maxAuthorizations !== 1) errors.push(issue('invalid-eip7702-count', `${eipPath}.maxAuthorizations`, 'The secure EIP-7702 profile supports exactly one authorization per transaction.'));
    if (!Array.isArray(eip7702.delegates)) errors.push(issue('invalid-eip7702-delegates', `${eipPath}.delegates`, 'delegates must be an array.'));
    else {
      const delegates = new Set();
      eip7702.delegates.forEach((delegate, index) => {
        const at = `${eipPath}.delegates[${index}]`;
        if (!isPlainObject(delegate)) { errors.push(issue('invalid-eip7702-delegate', at, 'Delegate must be an object.')); return; }
        rejectUnknown(delegate, new Set(['chainId', 'address', 'codeHash']), at, errors);
        if (!Number.isSafeInteger(delegate.chainId) || delegate.chainId < 1) errors.push(issue('invalid-chain', `${at}.chainId`, 'chainId must be a positive safe integer.'));
        if (!ADDRESS.test(String(delegate.address ?? '')) || String(delegate.address).toLowerCase() === ZERO_ADDRESS) errors.push(issue('invalid-eip7702-delegate', `${at}.address`, 'Delegate requires an exact non-zero address.'));
        const address = `${delegate.chainId}:${String(delegate.address ?? '').toLowerCase()}`;
        if (delegates.has(address)) errors.push(issue('duplicate-eip7702-delegate', at, 'Delegate addresses must be unique.'));
        delegates.add(address);
        if (!/^0x[a-fA-F0-9]{64}$/.test(String(delegate.codeHash ?? ''))) errors.push(issue('invalid-eip7702-code-hash', `${at}.codeHash`, 'Delegate requires an exact 32-byte runtime code hash.'));
      });
      if ((eip7702.allowAuthorizationList || eip7702.allowDelegatedWallet) && eip7702.delegates.length === 0) errors.push(issue('missing-eip7702-delegates', `${eipPath}.delegates`, 'Opting into EIP-7702 requires at least one code-hash-pinned delegate.'));
    }
  }
  if (!Array.isArray(config.sources) || !config.sources.length) errors.push(issue('missing-simulation-sources', `${path}.sources`, 'At least one trace-capable simulation source is required.'));
  else {
    const ids = new Set();
    config.sources.forEach((source, index) => {
      const at = `${path}.sources[${index}]`;
      if (!isPlainObject(source)) { errors.push(issue('invalid-simulation-source', at, 'Simulation source must be an object.')); return; }
      rejectUnknown(source, new Set(['id', 'env']), at, errors);
      if (typeof source.id !== 'string' || !source.id.trim()) errors.push(issue('invalid-simulation-source-id', `${at}.id`, 'Simulation source requires an ID.'));
      if (ids.has(source.id)) errors.push(issue('duplicate-simulation-source', at, 'Simulation source IDs must be unique.'));
      ids.add(source.id);
      if (typeof source.env !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(source.env)) errors.push(issue('invalid-simulation-source-env', `${at}.env`, 'env must name an uppercase environment variable.'));
    });
  }
  if (!Number.isSafeInteger(config.quorum) || config.quorum < 1 || (Array.isArray(config.sources) && config.quorum > config.sources.length)) errors.push(issue('invalid-simulation-quorum', `${path}.quorum`, 'quorum must be between 1 and the number of simulation sources.'));
}

function parseUint(value, path, errors, { optional = true } = {}) {
  if (value == null && optional) return null;
  if (typeof value !== 'string' || !DECIMAL_UINT.test(value)) {
    errors.push(issue('invalid-uint', path, 'Use an unsigned base-10 integer string.'));
    return null;
  }
  try {
    const parsed = BigInt(value);
    if (parsed > MAX_UINT256) { errors.push(issue('uint-overflow', path, 'Value exceeds uint256.')); return null; }
    return parsed;
  }
  catch { errors.push(issue('invalid-uint', path, 'Value is outside the supported integer range.')); return null; }
}

function validateGasCeiling(value, path, errors) {
  if (value == null) return;
  const parsed = parseUint(value, path, errors);
  if (parsed != null && parsed < MIN_TRANSACTION_GAS) errors.push(issue('invalid-gas-limit', path, `Gas limit must be at least ${MIN_TRANSACTION_GAS}.`));
}

/** Bind a swap to a fresh quote. Only Uniswap V3 single-pool swaps are supported so far. */
function validateSwapQuote(rule, path, errors) {
  if (!isPlainObject(rule)) { errors.push(issue('invalid-swap-quote', path, 'swapQuote must be an object.')); return; }
  rejectUnknown(rule, new Set(['kind', 'quoter', 'wrappedNative', 'arguments', 'pools']), path, errors);
  if (!SWAP_QUOTE_KINDS.has(rule.kind)) errors.push(issue('invalid-swap-quote', `${path}.kind`, `Unsupported swap quote kind ${rule.kind}.`));
  for (const field of ['quoter', 'wrappedNative']) if (!ADDRESS.test(String(rule[field] ?? ''))) errors.push(issue('invalid-address', `${path}.${field}`, 'Expected a 20-byte 0x address.'));
  if (!isPlainObject(rule.arguments)) errors.push(issue('invalid-swap-quote', `${path}.arguments`, 'arguments must map each swap field to a calldata word.'));
  else for (const field of ['tokenIn', 'tokenOut', 'fee', 'amountIn', 'minimumOut']) if (!Number.isInteger(rule.arguments[field]) || rule.arguments[field] < 0 || rule.arguments[field] > 63) errors.push(issue('invalid-swap-quote', `${path}.arguments.${field}`, 'Expected a calldata word index.'));
  if (!Array.isArray(rule.pools) || !rule.pools.length) errors.push(issue('invalid-swap-quote', `${path}.pools`, 'List at least one measured pool.'));
  else rule.pools.forEach((pool, index) => {
    const at = `${path}.pools[${index}]`;
    if (!isPlainObject(pool) || !ADDRESS.test(String(pool.tokenA ?? '')) || !ADDRESS.test(String(pool.tokenB ?? '')) || !Number.isSafeInteger(pool.fee) || pool.fee <= 0) errors.push(issue('invalid-swap-quote', at, 'Each pool needs tokenA, tokenB and a fee tier.'));
  });
}

function validateConstraint(constraint, path, errors) {
  if (!isPlainObject(constraint)) { errors.push(issue('invalid-constraint', path, 'Constraint must be an object.')); return; }
  rejectUnknown(constraint, new Set(['type', 'argument', 'addresses', 'value']), path, errors);
  const supported = new Set(['address-in', 'uint-max', 'uint-min', 'uint-equals', 'bytes32-equals']);
  if (!supported.has(constraint.type)) errors.push(issue('invalid-constraint-type', `${path}.type`, `Unsupported constraint type: ${constraint.type ?? 'missing'}.`));
  if (!Number.isInteger(constraint.argument) || constraint.argument < 0 || constraint.argument > 63) errors.push(issue('invalid-argument-index', `${path}.argument`, 'Argument index must be an integer from 0 to 63.'));
  if (constraint.type === 'address-in') {
    if (!Array.isArray(constraint.addresses) || !constraint.addresses.length) errors.push(issue('empty-address-allowlist', `${path}.addresses`, 'Address constraints require at least one exact address.'));
    else constraint.addresses.forEach((address, index) => { if (!ADDRESS.test(String(address))) errors.push(issue('invalid-address', `${path}.addresses[${index}]`, 'Expected a 20-byte 0x address.')); });
  } else if (constraint.type?.startsWith('uint-')) parseUint(constraint.value, `${path}.value`, errors, { optional: false });
  else if (constraint.type === 'bytes32-equals' && !/^0x[a-fA-F0-9]{64}$/.test(String(constraint.value ?? ''))) errors.push(issue('invalid-bytes32', `${path}.value`, 'Expected a 32-byte hex value.'));
}

/** Validate a wallet policy. Activation checks may be disabled only for draft auditing. */
/** List allowed calls that have no gas ceiling from the policy or the measured rule set. */
function uncappedGasFindings(policy, gasRules) {
  const findings = [];
  if (!Array.isArray(policy.contracts)) return findings;
  policy.contracts.forEach((contract, index) => {
    if (!isPlainObject(contract)) return;
    const path = `$.contracts[${index}]`;
    if (contract.allowEmptyCalldata === true && contract.maxGas == null) findings.push(issue('uncapped-empty-calldata-gas', `${path}.maxGas`, 'Native transfers to this contract need a contract maxGas.', 'high'));
    (Array.isArray(contract.methods) ? contract.methods : []).forEach((method, methodIndex) => {
      if (!isPlainObject(method) || method.maxGas != null || contract.maxGas != null) return;
      if (!gasRules.find(contract.chainId, contract.address, method.selector)) findings.push(issue('uncapped-function-gas', `${path}.methods[${methodIndex}].maxGas`, `Selector ${method.selector} has no measured gas rule, so the policy must set maxGas.`, 'high'));
    });
  });
  return findings;
}

/** Find attacker addresses a policy tries to allow. Listing one must fail loudly, not quietly deny later. */
function attackersInPolicy(policy, attackerList) {
  if (!attackerList) return [];
  const found = [];
  const check = (address, path) => {
    const match = attackerList.find(address);
    if (match) found.push({ address: match.address, label: match.label, path });
  };
  const contracts = Array.isArray(policy.contracts) ? policy.contracts : [];
  contracts.forEach((contract, index) => {
    check(contract?.address, `$.contracts[${index}].address`);
    (Array.isArray(contract?.methods) ? contract.methods : []).forEach((method, methodIndex) => {
      (Array.isArray(method?.constraints) ? method.constraints : []).forEach((constraint, constraintIndex) => {
        if (constraint?.type === 'address-in' && Array.isArray(constraint.addresses)) constraint.addresses.forEach((address, addressIndex) => check(address, `$.contracts[${index}].methods[${methodIndex}].constraints[${constraintIndex}].addresses[${addressIndex}]`));
      });
      if (method?.swapQuote?.quoter) check(method.swapQuote.quoter, `$.contracts[${index}].methods[${methodIndex}].swapQuote.quoter`);
    });
  });
  const simulation = policy.simulation;
  (Array.isArray(simulation?.internalTargets) ? simulation.internalTargets : []).forEach((target, index) => check(target?.address, `$.simulation.internalTargets[${index}].address`));
  (Array.isArray(simulation?.assetLimits) ? simulation.assetLimits : []).forEach((limit, index) => {
    check(limit?.token, `$.simulation.assetLimits[${index}].token`);
    for (const field of ['allowedRecipients', 'allowedSpenders']) (Array.isArray(limit?.[field]) ? limit[field] : []).forEach((address, addressIndex) => check(address, `$.simulation.assetLimits[${index}].${field}[${addressIndex}]`));
  });
  return found;
}

export function validatePolicy(policy, { activation = true, gasRules = GAS_RULES, attackerList = ATTACKER_LIST } = {}) {
  const errors = [];
  if (!isPlainObject(policy)) return { valid: false, errors: [issue('invalid-policy', '$', 'Policy must be a JSON object.')] };
  rejectUnknown(policy, new Set(['version', 'name', 'defaultAction', 'chains', 'wallets', 'validUntil', 'invariants', 'contracts', 'protocolState', 'simulation', 'blockedAddresses']), '$', errors);
  if (policy.version !== 1) errors.push(issue('unsupported-version', '$.version', 'Wallet policy version must be 1.'));
  if (typeof policy.name !== 'string' || !policy.name.trim()) errors.push(issue('missing-name', '$.name', 'Policy requires a non-empty name.'));
  if (policy.defaultAction !== 'deny') errors.push(issue('unsafe-default', '$.defaultAction', 'defaultAction must be "deny". Allow-by-default policies are not supported.'));
  if (!Array.isArray(policy.chains) || !policy.chains.length) errors.push(issue('missing-chains', '$.chains', 'Policy requires at least one allowed chain ID.'));
  else policy.chains.forEach((chain, index) => { if (!Number.isSafeInteger(chain) || chain < 1) errors.push(issue('invalid-chain', `$.chains[${index}]`, 'Chain ID must be a positive safe integer.')); });
  if (policy.wallets != null) {
    if (!Array.isArray(policy.wallets)) errors.push(issue('invalid-wallets', '$.wallets', 'wallets must be an array of exact addresses.'));
    else policy.wallets.forEach((address, index) => { if (!ADDRESS.test(String(address))) errors.push(issue('invalid-address', `$.wallets[${index}]`, 'Expected a 20-byte 0x address.')); });
  }
  if (policy.blockedAddresses != null) {
    if (!Array.isArray(policy.blockedAddresses)) errors.push(issue('invalid-blocked-addresses', '$.blockedAddresses', 'blockedAddresses must be an array of exact addresses.'));
    else policy.blockedAddresses.forEach((address, index) => { if (!ADDRESS.test(String(address))) errors.push(issue('invalid-address', `$.blockedAddresses[${index}]`, 'Expected a 20-byte 0x address.')); });
  }
  if (policy.validUntil != null && (typeof policy.validUntil !== 'string' || !Number.isFinite(Date.parse(policy.validUntil)))) errors.push(issue('invalid-expiry', '$.validUntil', 'validUntil must be an ISO-8601 timestamp.'));
  if (policy.protocolState == null) errors.push(issue('missing-state-policy', '$.protocolState', 'Executable wallet policies must require authenticated live protocol state.'));
  else validateProtocolStateConfig(policy.protocolState, errors);
  if (policy.simulation == null) errors.push(issue('missing-simulation-policy', '$.simulation', 'Executable wallet policies must require full transaction simulation.'));
  else validateSimulationConfig(policy.simulation, errors);

  if (!isPlainObject(policy.invariants)) errors.push(issue('missing-invariants', '$.invariants', 'Policy requires an invariants object.'));
  else {
    rejectUnknown(policy.invariants, new Set(['maxNativeValueWei', 'maxNativeOutflowPerBlockWei', 'maxSlippageBps', 'maxGas', 'maxGasPriceWei', 'maxFeePerGasWei', 'maxPriorityFeePerGasWei', 'requireCalldata', 'denyUnlimitedApproval']), '$.invariants', errors);
    parseUint(policy.invariants.maxNativeValueWei, '$.invariants.maxNativeValueWei', errors, { optional: false });
    parseUint(policy.invariants.maxNativeOutflowPerBlockWei, '$.invariants.maxNativeOutflowPerBlockWei', errors);
    const slippage = parseUint(policy.invariants.maxSlippageBps, '$.invariants.maxSlippageBps', errors);
    if (slippage != null && (slippage < 1n || slippage > MAX_SLIPPAGE_BPS)) errors.push(issue('invalid-slippage-limit', '$.invariants.maxSlippageBps', `maxSlippageBps must be between 1 and ${MAX_SLIPPAGE_BPS}.`));
    parseUint(policy.invariants.maxGas, '$.invariants.maxGas', errors);
    parseUint(policy.invariants.maxGasPriceWei, '$.invariants.maxGasPriceWei', errors);
    parseUint(policy.invariants.maxFeePerGasWei, '$.invariants.maxFeePerGasWei', errors);
    parseUint(policy.invariants.maxPriorityFeePerGasWei, '$.invariants.maxPriorityFeePerGasWei', errors);
    if (policy.invariants.requireCalldata != null && typeof policy.invariants.requireCalldata !== 'boolean') errors.push(issue('invalid-invariant', '$.invariants.requireCalldata', 'requireCalldata must be boolean.'));
    if (policy.invariants.denyUnlimitedApproval === false) errors.push(issue('unsafe-approval-setting', '$.invariants.denyUnlimitedApproval', 'Unlimited ERC-20 approvals cannot be enabled in the secure policy profile.'));
  }

  for (const finding of attackersInPolicy(policy, attackerList)) errors.push(issue('attacker-in-policy', finding.path, `${finding.address} is on the attacker list (${finding.label}), so a policy cannot allow it.`));

  if (!Array.isArray(policy.contracts) || !policy.contracts.length) errors.push(issue('missing-contracts', '$.contracts', 'Policy requires at least one exact contract allowlist entry.'));
  else {
    const contracts = new Set();
    policy.contracts.forEach((contract, index) => {
      const path = `$.contracts[${index}]`;
      if (!isPlainObject(contract)) { errors.push(issue('invalid-contract', path, 'Contract entry must be an object.')); return; }
      rejectUnknown(contract, new Set(['chainId', 'address', 'protocolId', 'maxNativeValueWei', 'maxGas', 'allowEmptyCalldata', 'methods']), path, errors);
      validateGasCeiling(contract.maxGas, `${path}.maxGas`, errors);
      if (!Number.isSafeInteger(contract.chainId) || contract.chainId < 1) errors.push(issue('invalid-chain', `${path}.chainId`, 'Contract chainId must be a positive safe integer.'));
      if (!ADDRESS.test(String(contract.address ?? ''))) errors.push(issue('invalid-address', `${path}.address`, 'Contract requires an exact 20-byte address.'));
      if (policy.protocolState?.required === true && (typeof contract.protocolId !== 'string' || !contract.protocolId.trim())) errors.push(issue('missing-protocol-binding', `${path}.protocolId`, 'Live-state policies require every contract to name its protocolId.'));
      const key = `${contract.chainId}:${String(contract.address).toLowerCase()}`;
      if (contracts.has(key)) errors.push(issue('duplicate-contract', path, 'Each chain/address pair may appear only once.'));
      contracts.add(key);
      if (contract.maxNativeValueWei != null) parseUint(contract.maxNativeValueWei, `${path}.maxNativeValueWei`, errors);
      if (contract.allowEmptyCalldata != null && typeof contract.allowEmptyCalldata !== 'boolean') errors.push(issue('invalid-empty-calldata-setting', `${path}.allowEmptyCalldata`, 'allowEmptyCalldata must be boolean.'));
      if (!Array.isArray(contract.methods) || !contract.methods.length) {
        if (contract.allowEmptyCalldata !== true) errors.push(issue('missing-methods', `${path}.methods`, 'Contract requires at least one exact selector unless it only accepts an explicitly allowed native transfer.'));
      } else {
        const selectors = new Set();
        contract.methods.forEach((method, methodIndex) => {
          const methodPath = `${path}.methods[${methodIndex}]`;
          if (!isPlainObject(method)) { errors.push(issue('invalid-method', methodPath, 'Method entry must be an object.')); return; }
          rejectUnknown(method, new Set(['selector', 'name', 'maxGas', 'constraints', 'swapQuote']), methodPath, errors);
          if (method.swapQuote != null) {
            validateSwapQuote(method.swapQuote, `${methodPath}.swapQuote`, errors);
            if (policy.invariants?.maxSlippageBps == null) errors.push(issue('missing-slippage-limit', '$.invariants.maxSlippageBps', 'A swap with a quote check needs maxSlippageBps, the most slippage the user accepts.'));
          }
          validateGasCeiling(method.maxGas, `${methodPath}.maxGas`, errors);
          if (!SELECTOR.test(String(method.selector ?? ''))) errors.push(issue('invalid-selector', `${methodPath}.selector`, 'Expected a four-byte selector such as 0x095ea7b3.'));
          const selector = String(method.selector ?? '').toLowerCase();
          if (selectors.has(selector)) errors.push(issue('duplicate-selector', methodPath, 'Selector is duplicated for this contract.'));
          selectors.add(selector);
          if (method.constraints != null && !Array.isArray(method.constraints)) errors.push(issue('invalid-constraints', `${methodPath}.constraints`, 'constraints must be an array.'));
          else (method.constraints ?? []).forEach((constraint, constraintIndex) => validateConstraint(constraint, `${methodPath}.constraints[${constraintIndex}]`, errors));
        });
      }
    });
  }
  if (activation) {
    if (!Array.isArray(policy.wallets) || policy.wallets.length === 0) errors.push(issue('activation-wallet-binding', '$.wallets', 'Executable policies must bind at least one exact wallet address.'));
    if (policy.validUntil == null) errors.push(issue('activation-expiry', '$.validUntil', 'Executable policies must have an ISO-8601 expiry.'));
    if ((policy.protocolState?.trustedKeys?.length ?? 0) < 2) errors.push(issue('activation-state-keys', '$.protocolState.trustedKeys', 'The secure activation profile requires at least two independent live-state keys.'));
    if ((policy.protocolState?.threshold ?? 0) < 2) errors.push(issue('activation-state-threshold', '$.protocolState.threshold', 'The secure activation profile requires a live-state signature threshold of at least two.'));
    if ((policy.simulation?.sources?.length ?? 0) < 2) errors.push(issue('activation-simulation-sources', '$.simulation.sources', 'The secure activation profile requires at least two simulation sources.'));
    if ((policy.simulation?.quorum ?? 0) < 2) errors.push(issue('activation-simulation-quorum', '$.simulation.quorum', 'The secure activation profile requires a simulation quorum of at least two.'));
    if (policy.invariants?.maxGas == null) errors.push(issue('activation-gas-cap', '$.invariants.maxGas', 'Executable policies must require and cap the transaction gas limit.'));
    for (const finding of uncappedGasFindings(policy, gasRules)) errors.push(issue(`activation-${finding.code}`, finding.path, finding.message));
  }
  return { valid: errors.length === 0, errors };
}

export { canonicalJson, sha256 };

export function loadPolicy(file) {
  const policy = JSON.parse(fs.readFileSync(file, 'utf8'));
  const validation = validatePolicy(policy);
  if (!validation.valid) {
    const error = new Error(`Invalid wallet policy:\n${validation.errors.map((x) => `${x.path}: ${x.message}`).join('\n')}`);
    error.validation = validation;
    throw error;
  }
  return policy;
}

function normalizeQuantity(value, path, errors, { required = false, fallback = null, hexOnly = false } = {}) {
  if (value == null || value === '') {
    if (required) errors.push(issue('missing-quantity', path, 'Required quantity is missing.'));
    return fallback;
  }
  // Wallets disagree on non-hex quantities, so a checked gas value could mean far more gas once forwarded.
  if (hexOnly && (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value))) {
    errors.push(issue('invalid-gas-quantity', path, 'Gas and fee quantities must be 0x hexadecimal strings.'));
    return null;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) { errors.push(issue('invalid-quantity', path, 'Numeric quantities must be non-negative safe integers. Prefer hex or decimal strings.')); return null; }
    return BigInt(value);
  }
  if (typeof value !== 'string' || (!/^0x[0-9a-fA-F]+$/.test(value) && !DECIMAL_UINT.test(value))) {
    errors.push(issue('invalid-quantity', path, 'Quantity must be a non-negative hexadecimal or decimal string.'));
    return null;
  }
  try { return BigInt(value); }
  catch { errors.push(issue('invalid-quantity', path, 'Quantity could not be parsed.')); return null; }
}

function normalizeAuthorization(raw, index, errors) {
  const path = `$.authorizationList[${index}]`;
  if (!isPlainObject(raw)) { errors.push(issue('invalid-eip7702-authorization', path, 'Authorization must be an object.')); return null; }
  rejectUnknown(raw, new Set(['chainId', 'address', 'nonce', 'yParity', 'r', 's']), path, errors);
  if (!ADDRESS.test(String(raw.address ?? ''))) errors.push(issue('invalid-address', `${path}.address`, 'Authorization requires an exact delegate address.'));
  const chainId = normalizeQuantity(raw.chainId, `${path}.chainId`, errors, { required: true });
  const nonce = normalizeQuantity(raw.nonce, `${path}.nonce`, errors, { required: true });
  const yParity = normalizeQuantity(raw.yParity, `${path}.yParity`, errors, { required: true });
  const r = normalizeQuantity(raw.r, `${path}.r`, errors, { required: true });
  const s = normalizeQuantity(raw.s, `${path}.s`, errors, { required: true });
  if (chainId != null && chainId > MAX_UINT256) errors.push(issue('invalid-eip7702-chain', `${path}.chainId`, 'Authorization chainId must fit uint256.'));
  if (nonce != null && nonce >= MAX_UINT64) errors.push(issue('invalid-eip7702-nonce', `${path}.nonce`, 'Authorization nonce must be less than 2^64 - 1.'));
  if (yParity != null && yParity !== 0n && yParity !== 1n) errors.push(issue('invalid-eip7702-signature', `${path}.yParity`, 'Authorization yParity must be 0 or 1.'));
  if (r != null && (r < 1n || r > MAX_UINT256)) errors.push(issue('invalid-eip7702-signature', `${path}.r`, 'Authorization r must be a non-zero uint256.'));
  if (s != null && (s < 1n || s > MAX_UINT256)) errors.push(issue('invalid-eip7702-signature', `${path}.s`, 'Authorization s must be a non-zero uint256.'));
  if (!ADDRESS.test(String(raw.address ?? '')) || [chainId, nonce, yParity, r, s].some((value) => value == null)) return null;
  return {
    chainId,
    address: raw.address.toLowerCase(),
    nonce,
    yParity,
    r: `0x${r.toString(16).padStart(64, '0')}`,
    s: `0x${s.toString(16).padStart(64, '0')}`,
  };
}

function normalizeAccessList(raw, errors) {
  if (!Array.isArray(raw)) {
    errors.push(issue('invalid-access-list', '$.accessList', 'accessList must be an array.'));
    return null;
  }
  if (raw.length > 256) errors.push(issue('access-list-too-large', '$.accessList', 'accessList may contain at most 256 addresses.'));
  const addresses = new Set();
  let totalStorageKeys = 0;
  const normalizedEntries = raw.map((entry, index) => {
    const path = `$.accessList[${index}]`;
    if (!isPlainObject(entry)) {
      errors.push(issue('invalid-access-list-entry', path, 'Access-list entries must be objects.'));
      return null;
    }
    rejectUnknown(entry, new Set(['address', 'storageKeys']), path, errors);
    const address = String(entry.address ?? '').toLowerCase();
    if (!ADDRESS.test(address)) errors.push(issue('invalid-address', `${path}.address`, 'Access-list entry requires an exact address.'));
    if (addresses.has(address)) errors.push(issue('duplicate-access-list-address', `${path}.address`, 'Access-list addresses must be unique.'));
    addresses.add(address);
    if (!Array.isArray(entry.storageKeys)) {
      errors.push(issue('invalid-access-list-storage', `${path}.storageKeys`, 'storageKeys must be an array.'));
      return null;
    }
    totalStorageKeys += entry.storageKeys.length;
    const keys = new Set();
    const storageKeys = entry.storageKeys.map((key, keyIndex) => {
      const normalized = String(key).toLowerCase();
      if (!STORAGE_KEY.test(normalized)) errors.push(issue('invalid-storage-key', `${path}.storageKeys[${keyIndex}]`, 'Access-list storage keys must be 32-byte hex values.'));
      if (keys.has(normalized)) errors.push(issue('duplicate-storage-key', `${path}.storageKeys[${keyIndex}]`, 'Access-list storage keys must be unique per address.'));
      keys.add(normalized);
      return normalized;
    });
    return { address, storageKeys };
  }).filter(Boolean);
  if (totalStorageKeys > 4096) errors.push(issue('access-list-too-large', '$.accessList', 'accessList may contain at most 4096 storage keys.'));
  return normalizedEntries;
}

export function normalizeIntent(intent) {
  const errors = [];
  if (!isPlainObject(intent)) return { valid: false, errors: [issue('invalid-intent', '$', 'Transaction intent must be an object.')], intent: null };
  rejectUnknown(intent, new Set(['chainId', 'from', 'to', 'data', 'value', 'gas', 'gasLimit', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce', 'type', 'accessList', 'authorizationList']), '$', errors);
  let chainId = intent.chainId;
  if (typeof chainId === 'string' && (/^0x[0-9a-fA-F]+$/.test(chainId) || DECIMAL_UINT.test(chainId))) chainId = Number(BigInt(chainId));
  if (!Number.isSafeInteger(chainId) || chainId < 1) errors.push(issue('invalid-chain', '$.chainId', 'Intent requires a positive chain ID.'));
  if (!ADDRESS.test(String(intent.from ?? ''))) errors.push(issue('invalid-address', '$.from', 'Intent requires an exact from address.'));
  if (!ADDRESS.test(String(intent.to ?? ''))) errors.push(issue('invalid-address', '$.to', 'Intent requires an exact to address. Contract creation is not supported.'));
  const data = intent.data ?? '0x';
  if (!HEX_DATA.test(String(data))) errors.push(issue('invalid-calldata', '$.data', 'Calldata must be even-length hexadecimal bytes.'));
  const value = normalizeQuantity(intent.value, '$.value', errors, { fallback: 0n });
  if (intent.gas != null && intent.gasLimit != null && String(intent.gas) !== String(intent.gasLimit)) errors.push(issue('conflicting-gas', '$.gasLimit', 'gas and gasLimit must not disagree.'));
  if (intent.gasLimit != null && intent.gas == null) errors.push(issue('gas-field-required', '$.gas', 'Send the gas limit as gas. A wallet can ignore gasLimit and pick its own limit.'));
  const gas = normalizeQuantity(intent.gas ?? intent.gasLimit, '$.gas', errors, { hexOnly: true });
  const gasPrice = normalizeQuantity(intent.gasPrice, '$.gasPrice', errors, { hexOnly: true });
  const maxFeePerGas = normalizeQuantity(intent.maxFeePerGas, '$.maxFeePerGas', errors, { hexOnly: true });
  const maxPriorityFeePerGas = normalizeQuantity(intent.maxPriorityFeePerGas, '$.maxPriorityFeePerGas', errors, { hexOnly: true });
  const nonce = normalizeQuantity(intent.nonce, '$.nonce', errors, { required: true });
  if (nonce != null && nonce >= MAX_UINT64) errors.push(issue('invalid-nonce', '$.nonce', 'Transaction nonce must be less than 2^64 - 1.'));
  if (gasPrice != null && (maxFeePerGas != null || maxPriorityFeePerGas != null)) errors.push(issue('conflicting-fee-model', '$.gasPrice', 'Legacy gasPrice cannot be combined with EIP-1559 fee fields.'));
  const type = normalizeQuantity(intent.type, '$.type', errors);
  const accessList = intent.accessList == null ? null : normalizeAccessList(intent.accessList, errors);
  let authorizationList = null;
  if (intent.authorizationList != null) {
    if (!Array.isArray(intent.authorizationList)) errors.push(issue('invalid-eip7702-authorization-list', '$.authorizationList', 'authorizationList must be an array.'));
    else authorizationList = intent.authorizationList.map((authorization, index) => normalizeAuthorization(authorization, index, errors));
  }
  const normalized = errors.length ? null : {
    chainId,
    from: intent.from.toLowerCase(),
    to: intent.to.toLowerCase(),
    data: data.toLowerCase(),
    value,
    gas,
    gasPrice,
    maxFeePerGas,
    maxPriorityFeePerGas,
    nonce,
    type,
    accessList,
    authorizationList,
  };
  return { valid: errors.length === 0, errors, intent: normalized };
}

function calldataWord(data, argument) {
  const start = 10 + argument * 64;
  if (data.length < start + 64) return null;
  return data.slice(start, start + 64).toLowerCase();
}

/** The swap rule for a call, if the policy binds that function to a fresh quote. */
export function findSwapRule(policy, chainId, to, data) {
  if (!/^0x[0-9a-fA-F]{8}/.test(String(data))) return null;
  const selector = String(data).slice(0, 10).toLowerCase();
  const contract = policy.contracts?.find((entry) => entry.chainId === chainId && entry.address.toLowerCase() === String(to).toLowerCase());
  return contract?.methods?.find((entry) => entry.selector.toLowerCase() === selector)?.swapQuote ?? null;
}

/** Read a swap's arguments from fixed calldata words. Returns null unless every word is well formed. */
export function decodeSwapCall(rule, data) {
  const lower = String(data).toLowerCase();
  const uint = (name) => { const word = calldataWord(lower, rule.arguments[name]); return word ? BigInt(`0x${word}`) : null; };
  const address = (name) => { const word = calldataWord(lower, rule.arguments[name]); return word && /^0{24}[0-9a-f]{40}$/.test(word) ? `0x${word.slice(24)}` : null; };
  const swap = { tokenIn: address('tokenIn'), tokenOut: address('tokenOut'), fee: uint('fee'), amountIn: uint('amountIn'), minimumOut: uint('minimumOut') };
  return Object.values(swap).some((value) => value == null) ? null : swap;
}

/** The fee tiers of the measured pools for a pair. Only these count as a fair price. */
export function listedSwapFees(rule, tokenIn, tokenOut) {
  const a = String(tokenIn).toLowerCase();
  const b = String(tokenOut).toLowerCase();
  return rule.pools
    .filter((pool) => { const x = pool.tokenA.toLowerCase(); const y = pool.tokenB.toLowerCase(); return (x === a && y === b) || (x === b && y === a); })
    .map((pool) => BigInt(pool.fee));
}

/** What can be checked without the chain. The fresh quote itself is checked during simulation. */
function evaluateSwapCall(rule, data, value, add) {
  const swap = decodeSwapCall(rule, data);
  if (!add('swap:decoded', Boolean(swap), 'Swap arguments must decode to exact tokens and amounts.')) return;
  add('swap:pool-listed', listedSwapFees(rule, swap.tokenIn, swap.tokenOut).includes(swap.fee), `The pool for ${swap.tokenIn} to ${swap.tokenOut} at fee ${swap.fee} must be one of the measured pools.`);
  add('swap:amount-set', swap.amountIn > 0n, 'Swap amount must be greater than zero.');
  add('swap:minimum-set', swap.minimumOut > 0n, 'Swap minimum output must be greater than zero.');
  // Extra ETH stays in the router, where anyone can take it.
  add('swap:native-input', value === 0n || (swap.tokenIn === rule.wrappedNative.toLowerCase() && value === swap.amountIn), `Native value ${value} must be 0, or exactly the amount in when swapping from the wrapped native token.`);
}

function evaluateConstraint(constraint, data) {
  const word = calldataWord(data, constraint.argument);
  if (!word) return { ok: false, detail: `Calldata does not contain ABI word ${constraint.argument}.` };
  if (constraint.type === 'address-in') {
    if (!/^0{24}[0-9a-f]{40}$/.test(word)) return { ok: false, detail: `ABI word ${constraint.argument} is not a canonical address.` };
    const address = `0x${word.slice(24)}`;
    const allowed = new Set(constraint.addresses.map((x) => x.toLowerCase()));
    return { ok: allowed.has(address), detail: `Argument ${constraint.argument} address ${address} must be allowlisted.` };
  }
  if (constraint.type === 'bytes32-equals') return { ok: `0x${word}` === constraint.value.toLowerCase(), detail: `Argument ${constraint.argument} must equal ${constraint.value}.` };
  const actual = BigInt(`0x${word}`);
  const expected = BigInt(constraint.value);
  const ok = constraint.type === 'uint-max' ? actual <= expected : constraint.type === 'uint-min' ? actual >= expected : actual === expected;
  return { ok, detail: `Argument ${constraint.argument} is ${actual}; ${constraint.type} requires ${expected}.` };
}

function serializableIntent(intent) {
  return {
    chainId: intent.chainId, from: intent.from, to: intent.to, data: intent.data,
    value: intent.value.toString(), gas: intent.gas?.toString() ?? null,
    gasPrice: intent.gasPrice?.toString() ?? null,
    maxFeePerGas: intent.maxFeePerGas?.toString() ?? null,
    maxPriorityFeePerGas: intent.maxPriorityFeePerGas?.toString() ?? null,
    nonce: intent.nonce.toString(),
    type: intent.type?.toString() ?? null,
    accessList: intent.accessList,
    authorizationList: intent.authorizationList?.map((authorization) => ({
      chainId: authorization.chainId.toString(),
      address: authorization.address,
      nonce: authorization.nonce.toString(),
      yParity: authorization.yParity.toString(),
      r: authorization.r,
      s: authorization.s,
    })) ?? null,
  };
}

/** Apply one target's exact address, value, selector, approval, and ABI-word rules. */
function evaluateTargetCall(policy, { chainId, to, data, value }, add, valueToTarget = value) {
  const contract = policy.contracts.find((entry) => entry.chainId === chainId && entry.address.toLowerCase() === to);
  add('target:allowlisted', Boolean(contract), `Target ${to} must match an exact contract entry on chain ${chainId}.`);
  if (!contract) return null;
  if (contract.maxNativeValueWei != null) add('value:contract-limit', valueToTarget <= BigInt(contract.maxNativeValueWei), `Native value to this target must not exceed ${contract.maxNativeValueWei} wei.`);
  if (data === '0x') {
    add('calldata:required', policy.invariants.requireCalldata !== true, 'Global policy requires calldata.');
    add('target:empty-calldata', contract.allowEmptyCalldata === true, 'Target must explicitly allow empty calldata.');
  } else if (data.length < 10) add('calldata:selector', false, 'Calldata must include a complete four-byte selector.');
  else {
    const selector = data.slice(0, 10);
    const method = contract.methods?.find((entry) => entry.selector.toLowerCase() === selector);
    add('method:allowlisted', Boolean(method), `Selector ${selector} must be allowlisted for this target.`);
    if (selector === '0x095ea7b3') {
      const amountWord = calldataWord(data, 1);
      add('erc20:no-unlimited-approval', Boolean(amountWord) && BigInt(`0x${amountWord}`) !== MAX_UINT256, 'ERC-20 approval amount must not be uint256 max.');
    }
    for (const [index, constraint] of (method?.constraints ?? []).entries()) {
      const result = evaluateConstraint(constraint, data);
      add(`constraint:${index}:${constraint.type}`, result.ok, result.detail);
    }
    if (method?.swapQuote) evaluateSwapCall(method.swapQuote, data, value, add);
  }
  return contract;
}

/**
 * Find the gas ceiling for one call. A valid call can still waste gas, so passing simulation is not enough.
 * Order: the policy's method limit, then a measured rule whose code version is still current, then the policy's
 * contract limit, then the overall cap. Without version statuses, as before simulation, a rule cannot be trusted
 * yet, so the overall cap applies. An outdated rule never denies, because an upgrade can change honest gas costs.
 */
export function resolveGasLimit(policy, { chainId, to, data, authorizationList = null }, { rules = GAS_RULES, statuses = null } = {}) {
  const contract = policy.contracts.find((entry) => entry.chainId === chainId && entry.address.toLowerCase() === to);
  if (!contract) return null;
  const selector = data.length >= 10 ? data.slice(0, 10) : null;
  const method = selector ? contract.methods?.find((entry) => entry.selector.toLowerCase() === selector) : null;
  const rule = selector ? rules.find(chainId, to, selector) : null;
  const status = rule ? statuses?.get(rule) ?? null : null;
  let ceiling = null;
  let source = null;
  if (method?.maxGas != null) { ceiling = method.maxGas; source = 'policy method limit'; }
  else if (status?.current) { ceiling = rule.maxGas; source = `gas rule ${rule.versionTag}, measured ${rules.version}`; }
  else if (rule) {
    const useContract = status != null && contract.maxGas != null;
    ceiling = useContract ? contract.maxGas : policy.invariants?.maxGas;
    source = `${useContract ? 'policy contract limit' : 'overall gas cap'}; gas rule ${rule.versionTag} ${status ? `not used because ${status.reason}` : 'not version-checked yet'}`;
  } else if (contract.maxGas != null) { ceiling = contract.maxGas; source = 'policy contract limit'; }
  if (ceiling == null) return null;
  return { limit: BigInt(ceiling) + BigInt(authorizationList?.length ?? 0) * PER_AUTHORIZATION_GAS, source, rule: rule ?? null, outdated: status?.current === false };
}

/** Reapply policy and signed live-state checks to every trace call originating from the wallet. */
export function evaluateWalletCalls(policy, chainId, calls, { protocolState = null, now = new Date(), minimumStateSequence = 0, gasRules = GAS_RULES, gasRuleStatuses = null } = {}) {
  const failures = [];
  const valueByTarget = new Map();
  for (const [index, call] of calls.entries()) {
    const label = `Wallet call ${index} to ${call.to ?? '(none)'}`;
    if (!['CALL', 'STATICCALL'].includes(call.type) || !call.to) {
      failures.push(`${label}: only CALL and STATICCALL may originate from the wallet, saw ${call.type}.`);
      continue;
    }
    const value = BigInt(call.value);
    if (call.type === 'STATICCALL' && value !== 0n) {
      failures.push(`${label}: STATICCALL cannot carry native value.`);
      continue;
    }
    const valueToTarget = (valueByTarget.get(call.to) ?? 0n) + value;
    valueByTarget.set(call.to, valueToTarget);
    const add = (id, ok, detail) => { if (!ok) failures.push(`${label} failed ${id}: ${detail}`); return ok; };
    const contract = evaluateTargetCall(policy, { chainId, to: call.to, data: call.input, value }, add, valueToTarget);
    if (contract) {
      const gasLimit = resolveGasLimit(policy, { chainId, to: call.to, data: call.input }, { rules: gasRules, statuses: gasRuleStatuses });
      const used = call.gasUsed == null ? null : BigInt(call.gasUsed);
      const limitText = gasLimit ? `this function allows ${gasLimit.limit} (${gasLimit.source})` : 'this function has no gas limit';
      add('gas:function-limit', gasLimit != null && used != null && used <= gasLimit.limit, used == null ? `The trace reports no gas for this call; ${limitText}.` : `Used ${used} gas; ${limitText}.`);
    }
    if (!contract || policy.protocolState?.required !== true) continue;
    const state = evaluateProtocolState(protocolState, policy.protocolState, {
      protocolId: contract.protocolId,
      chainId,
      address: call.to,
      now,
      minimumSequence: minimumStateSequence,
    });
    for (const check of state.checks) add(check.id, check.status === 'pass', check.detail);
  }
  return failures;
}

/** Deterministically authorize the exact transaction that will be forwarded to the wallet. */
export function authorizeIntent(policy, rawIntent, { now = new Date(), protocolState = null, minimumStateSequence = 0, gasRules = GAS_RULES, attackerList = ATTACKER_LIST } = {}) {
  assertGasRules(gasRules);
  assertAttackerList(attackerList);
  const attackerRecord = attackerListIdentity(attackerList);
  const evaluatedAt = new Date(now).toISOString();
  const policyValidation = validatePolicy(policy, { gasRules, attackerList });
  const gasRulesRecord = gasRulesIdentity(gasRules);
  const policyHash = policyValidation.valid ? sha256(policy) : null;
  const checks = [];
  const add = (id, ok, detail) => { checks.push({ id, status: ok ? 'pass' : 'deny', detail }); return ok; };
  if (!policyValidation.valid) {
    policyValidation.errors.forEach((error) => add(`policy:${error.code}`, false, `${error.path}: ${error.message}`));
    return { version: 1, decision: 'deny', evaluatedAt, policy: { name: policy?.name ?? null, hash: policyHash }, intent: null, gasRules: gasRulesRecord, attackerList: attackerRecord, protocolState: null, checks };
  }
  const normalized = normalizeIntent(rawIntent);
  if (!normalized.valid) {
    normalized.errors.forEach((error) => add(`intent:${error.code}`, false, `${error.path}: ${error.message}`));
    return { version: 1, decision: 'deny', evaluatedAt, policy: { name: policy.name, hash: policyHash }, intent: null, gasRules: gasRulesRecord, attackerList: attackerRecord, protocolState: null, checks };
  }
  const intent = normalized.intent;
  const summary = { ...serializableIntent(intent), selector: intent.data.length >= 10 ? intent.data.slice(0, 10) : null };
  const receiptIntent = { ...summary, hash: sha256(serializableIntent(intent)) };

  if (policy.validUntil) add('policy:not-expired', Date.parse(policy.validUntil) > new Date(now).getTime(), `Policy expires at ${policy.validUntil}.`);
  add('chain:allowed', policy.chains.includes(intent.chainId), `Chain ${intent.chainId} must be allowlisted.`);
  if (policy.wallets?.length) add('wallet:allowed', policy.wallets.some((x) => x.toLowerCase() === intent.from), `Wallet ${intent.from} must be allowlisted.`);
  const usesEip7702 = intent.type === 4n || intent.authorizationList != null;
  add('transaction:type', intent.type == null || intent.type === 0n || intent.type === 2n || intent.type === 4n, 'Only omitted, legacy type 0, EIP-1559 type 2, and guarded EIP-7702 type 4 envelopes are supported.');
  const legacyFees = intent.gasPrice != null;
  const eip1559Fees = intent.maxFeePerGas != null && intent.maxPriorityFeePerGas != null;
  add('transaction:fee-model', legacyFees !== eip1559Fees && (intent.type !== 0n || legacyFees) && (intent.type !== 2n && intent.type !== 4n || eip1559Fees), 'Transaction must contain exactly one fee model matching its explicit envelope type.');
  add('transaction:access-list', intent.accessList == null || (!legacyFees && intent.type !== 0n), 'Access lists are supported only by EIP-1559 type-2 and EIP-7702 type-4 envelopes.');
  if (!usesEip7702) add('eip7702:request', true, 'Transaction does not request an EIP-7702 delegation change.');
  else {
    const eip7702 = policy.simulation.eip7702;
    add('eip7702:envelope', intent.type === 4n && Array.isArray(intent.authorizationList) && intent.authorizationList.length > 0, 'EIP-7702 requires an explicit type-4 envelope and a non-empty authorization list.');
    add('eip7702:policy-enabled', eip7702.allowAuthorizationList === true, 'Policy must explicitly allow EIP-7702 authorization lists.');
    add('eip7702:authorization-count', Array.isArray(intent.authorizationList) && intent.authorizationList.length <= eip7702.maxAuthorizations, `Authorization list must contain at most ${eip7702.maxAuthorizations} entry.`);
    for (const [index, authorization] of (intent.authorizationList ?? []).entries()) {
      const delegate = eip7702.delegates.find((entry) => entry.chainId === intent.chainId && entry.address.toLowerCase() === authorization.address);
      add(`eip7702:${index}:chain`, authorization.chainId === BigInt(intent.chainId), `Authorization chain ${authorization.chainId} must exactly equal transaction chain ${intent.chainId}; chain 0 is not accepted.`);
      add(`eip7702:${index}:delegate`, Boolean(delegate), `Delegate ${authorization.address} must be address- and code-hash-pinned by policy.`);
      let authority = null;
      try {
        authority = verifyAuthorization(
          { address: authorization.address, chainId: authorization.chainId, nonce: authorization.nonce },
          { yParity: authorization.yParity, r: authorization.r, s: authorization.s },
        ).toLowerCase();
      } catch { /* Invalid signatures fail the next check. */ }
      add(`eip7702:${index}:authority`, authority === intent.from, `Authorization signer ${authority ?? '(invalid)'} must be the guarded wallet ${intent.from}.`);
    }
  }

  const invariants = policy.invariants;
  const maxValue = BigInt(invariants.maxNativeValueWei);
  add('value:global-limit', intent.value <= maxValue, `Native value ${intent.value} must not exceed ${maxValue} wei.`);
  if (invariants.maxGas != null) add('gas:limit', intent.gas != null && intent.gas <= BigInt(invariants.maxGas), `Gas must be present and at most ${invariants.maxGas}.`);
  if (legacyFees) add('fee:legacy-max', invariants.maxGasPriceWei != null && intent.gasPrice <= BigInt(invariants.maxGasPriceWei), `Legacy gasPrice requires maxGasPriceWei and must not exceed ${invariants.maxGasPriceWei ?? '(missing)'}.`);
  else {
    add('fee:max', invariants.maxFeePerGasWei != null && intent.maxFeePerGas != null && intent.maxFeePerGas <= BigInt(invariants.maxFeePerGasWei), `EIP-1559 requires maxFeePerGasWei and the transaction field must not exceed ${invariants.maxFeePerGasWei ?? '(missing)'}.`);
    add('fee:priority', invariants.maxPriorityFeePerGasWei != null && intent.maxPriorityFeePerGas != null && intent.maxPriorityFeePerGas <= BigInt(invariants.maxPriorityFeePerGasWei), `EIP-1559 requires maxPriorityFeePerGasWei and the transaction field must not exceed ${invariants.maxPriorityFeePerGasWei ?? '(missing)'}.`);
  }

  // These apply before anything else about the call is trusted, whatever the policy allows.
  const lookup = attackerLookup(attackerList, policy);
  const targetAttacker = lookup(intent.to);
  add('attacker:target', !targetAttacker, targetAttacker ? `Target is a listed attacker: ${describeAttacker(targetAttacker)}.` : `Target is not on the attacker list (${attackerList.count} addresses, version ${attackerList.version}).`);
  const calldataAttackers = findAttackersInHex(intent.data, lookup);
  add('attacker:calldata', calldataAttackers.length === 0, calldataAttackers.length ? `Calldata names a listed attacker: ${calldataAttackers.map(describeAttacker).join(', ')}.` : 'Calldata names no listed attacker.');
  const delegateAttackers = (intent.authorizationList ?? []).map((authorization) => lookup(authorization.address)).filter(Boolean);
  if (intent.authorizationList != null) add('attacker:delegate', delegateAttackers.length === 0, delegateAttackers.length ? `EIP-7702 delegate is a listed attacker: ${delegateAttackers.map(describeAttacker).join(', ')}.` : 'EIP-7702 delegates are not on the attacker list.');

  const contract = evaluateTargetCall(policy, intent, add);
  const gasLimit = contract ? resolveGasLimit(policy, intent, { rules: gasRules }) : null;
  if (contract) add('gas:function-limit', gasLimit != null && intent.gas != null && intent.gas <= gasLimit.limit, gasLimit ? `Gas must be present and at most ${gasLimit.limit} for this function (${gasLimit.source}).` : 'This function has no gas limit. Set maxGas in the policy.');
  let stateSummary = null;
  if (policy.protocolState?.required === true) {
    const stateResult = evaluateProtocolState(protocolState, policy.protocolState, {
      protocolId: contract?.protocolId ?? null,
      chainId: intent.chainId,
      address: intent.to,
      now,
      minimumSequence: minimumStateSequence,
    });
    checks.push(...stateResult.checks);
    stateSummary = stateResult.summary;
  }
  const decision = checks.some((check) => check.status === 'deny') ? 'deny' : 'simulate';
  return { version: 1, decision, evaluatedAt, policy: { name: policy.name, hash: policyHash }, intent: receiptIntent, gasRules: gasRulesRecord, attackerList: attackerRecord, protocolState: stateSummary, simulation: null, checks };
}

/** Find structurally valid but broad rules that deserve human review before activation. */
export function auditPolicy(policy, { gasRules = GAS_RULES } = {}) {
  const validation = validatePolicy(policy, { activation: false, gasRules });
  const findings = [...validation.errors];
  if (!validation.valid) return { valid: false, policyHash: null, findings };
  if (!policy.wallets?.length) findings.push(issue('unbound-wallet', '$.wallets', 'Policy is not bound to a specific wallet.', 'high'));
  if (!policy.validUntil) findings.push(issue('no-expiry', '$.validUntil', 'Policy does not expire automatically.', 'medium'));
  if ((policy.protocolState?.trustedKeys?.length ?? 0) < 2) findings.push(issue('single-state-key', '$.protocolState.trustedKeys', 'Secure activation requires at least two independent live-state keys.', 'high'));
  if ((policy.protocolState?.threshold ?? 0) < 2) findings.push(issue('single-state-signer', '$.protocolState.threshold', 'Secure activation requires at least two live-state signatures.', 'high'));
  if ((policy.simulation?.sources?.length ?? 0) < 2) findings.push(issue('single-simulation-source', '$.simulation.sources', 'Secure activation requires at least two simulation sources.', 'high'));
  if ((policy.simulation?.quorum ?? 0) < 2) findings.push(issue('single-simulation-quorum', '$.simulation.quorum', 'Secure activation requires a simulation quorum of at least two.', 'high'));
  if (policy.invariants?.maxGas == null) findings.push(issue('uncapped-transaction-gas', '$.invariants.maxGas', 'Secure activation requires an explicit transaction gas cap.', 'high'));
  const eip7702 = policy.simulation.eip7702;
  if (eip7702.allowAuthorizationList && !eip7702.allowDelegatedWallet) findings.push(issue('eip7702-wallet-lockout', '$.simulation.eip7702.allowDelegatedWallet', 'A permitted delegation will make later transactions deny until delegated-wallet use is separately enabled.', 'medium'));
  findings.push(...uncappedGasFindings(policy, gasRules));
  if (policy.invariants?.maxSlippageBps != null && BigInt(policy.invariants.maxSlippageBps) > HIGH_SLIPPAGE_BPS) findings.push(issue('high-slippage-limit', '$.invariants.maxSlippageBps', `Allowing more than ${HIGH_SLIPPAGE_BPS} basis points of slippage leaves swaps open to heavy price manipulation.`, 'high'));
  if (Date.parse(gasRules.validUntil) <= Date.now()) findings.push(issue('gas-rules-expired', '$.contracts', `The gas rule set expired on ${gasRules.validUntil}, so only the overall gas cap applies. Run npm run gas:sync.`, 'medium'));
  policy.contracts.forEach((contract, index) => {
    contract.methods?.forEach((method, methodIndex) => {
      const rule = gasRules.find(contract.chainId, contract.address, method.selector);
      if (rule && method.maxGas != null && BigInt(method.maxGas) > BigInt(rule.maxGas)) findings.push(issue('function-gas-above-rule', `$.contracts[${index}].methods[${methodIndex}].maxGas`, `maxGas ${method.maxGas} is above the measured ${rule.versionTag} limit of ${rule.maxGas}.`, 'medium'));
    });
    if (!contract.protocolId) findings.push(issue('missing-protocol-binding', `$.contracts[${index}].protocolId`, 'Contract is not bound to a protocol identity for live-state enforcement.', 'high'));
    if (contract.allowEmptyCalldata) findings.push(issue('native-transfer-enabled', `$.contracts[${index}].allowEmptyCalldata`, 'Contract accepts empty-calldata native transfers.', 'medium'));
    contract.methods?.forEach((method, methodIndex) => {
      if (UNQUOTED_SWAP_SELECTORS.has(method.selector.toLowerCase()) && !method.swapQuote) findings.push(issue('swap-without-fresh-quote', `$.contracts[${index}].methods[${methodIndex}]`, `Selector ${method.selector} is a swap with no swapQuote, so nothing stops a very low minimum output.`, 'high'));
      if (!(method.constraints?.length)) findings.push(issue('unconstrained-method', `$.contracts[${index}].methods[${methodIndex}]`, `Selector ${method.selector} has no argument constraints.`, 'medium'));
      if (method.selector.toLowerCase() === '0x095ea7b3') {
        const constraints = method.constraints ?? [];
        if (!constraints.some((x) => x.type === 'address-in' && x.argument === 0)) findings.push(issue('unbounded-approval-spender', `$.contracts[${index}].methods[${methodIndex}]`, 'ERC-20 approve must constrain argument 0 to exact spenders.', 'high'));
        if (!constraints.some((x) => x.type === 'uint-max' && x.argument === 1)) findings.push(issue('unbounded-approval-amount', `$.contracts[${index}].methods[${methodIndex}]`, 'ERC-20 approve should cap argument 1.', 'high'));
      }
    });
  });
  return { valid: true, policyHash: sha256(policy), findings };
}
