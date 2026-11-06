import fs from 'node:fs';
import crypto from 'node:crypto';

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const SELECTOR = /^0x[a-fA-F0-9]{8}$/;
const HEX_DATA = /^0x(?:[a-fA-F0-9]{2})*$/;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]*)$/;
const MAX_UINT256 = (1n << 256n) - 1n;

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

/** Validate the executable wallet policy. Invalid policies must never be evaluated as permissive. */
export function validatePolicy(policy) {
  const errors = [];
  if (!isPlainObject(policy)) return { valid: false, errors: [issue('invalid-policy', '$', 'Policy must be a JSON object.')] };
  rejectUnknown(policy, new Set(['version', 'name', 'defaultAction', 'chains', 'wallets', 'validUntil', 'invariants', 'contracts']), '$', errors);
  if (policy.version !== 1) errors.push(issue('unsupported-version', '$.version', 'Wallet policy version must be 1.'));
  if (typeof policy.name !== 'string' || !policy.name.trim()) errors.push(issue('missing-name', '$.name', 'Policy requires a non-empty name.'));
  if (policy.defaultAction !== 'deny') errors.push(issue('unsafe-default', '$.defaultAction', 'defaultAction must be "deny". Allow-by-default policies are not supported.'));
  if (!Array.isArray(policy.chains) || !policy.chains.length) errors.push(issue('missing-chains', '$.chains', 'Policy requires at least one allowed chain ID.'));
  else policy.chains.forEach((chain, index) => { if (!Number.isSafeInteger(chain) || chain < 1) errors.push(issue('invalid-chain', `$.chains[${index}]`, 'Chain ID must be a positive safe integer.')); });
  if (policy.wallets != null) {
    if (!Array.isArray(policy.wallets)) errors.push(issue('invalid-wallets', '$.wallets', 'wallets must be an array of exact addresses.'));
    else policy.wallets.forEach((address, index) => { if (!ADDRESS.test(String(address))) errors.push(issue('invalid-address', `$.wallets[${index}]`, 'Expected a 20-byte 0x address.')); });
  }
  if (policy.validUntil != null && (typeof policy.validUntil !== 'string' || !Number.isFinite(Date.parse(policy.validUntil)))) errors.push(issue('invalid-expiry', '$.validUntil', 'validUntil must be an ISO-8601 timestamp.'));

  if (!isPlainObject(policy.invariants)) errors.push(issue('missing-invariants', '$.invariants', 'Policy requires an invariants object.'));
  else {
    rejectUnknown(policy.invariants, new Set(['maxNativeValueWei', 'maxGas', 'maxFeePerGasWei', 'maxPriorityFeePerGasWei', 'requireCalldata', 'denyUnlimitedApproval']), '$.invariants', errors);
    parseUint(policy.invariants.maxNativeValueWei, '$.invariants.maxNativeValueWei', errors, { optional: false });
    parseUint(policy.invariants.maxGas, '$.invariants.maxGas', errors);
    parseUint(policy.invariants.maxFeePerGasWei, '$.invariants.maxFeePerGasWei', errors);
    parseUint(policy.invariants.maxPriorityFeePerGasWei, '$.invariants.maxPriorityFeePerGasWei', errors);
    if (policy.invariants.requireCalldata != null && typeof policy.invariants.requireCalldata !== 'boolean') errors.push(issue('invalid-invariant', '$.invariants.requireCalldata', 'requireCalldata must be boolean.'));
    if (policy.invariants.denyUnlimitedApproval === false) errors.push(issue('unsafe-approval-setting', '$.invariants.denyUnlimitedApproval', 'Unlimited ERC-20 approvals cannot be enabled in the secure policy profile.'));
  }

  if (!Array.isArray(policy.contracts) || !policy.contracts.length) errors.push(issue('missing-contracts', '$.contracts', 'Policy requires at least one exact contract allowlist entry.'));
  else {
    const contracts = new Set();
    policy.contracts.forEach((contract, index) => {
      const path = `$.contracts[${index}]`;
      if (!isPlainObject(contract)) { errors.push(issue('invalid-contract', path, 'Contract entry must be an object.')); return; }
      rejectUnknown(contract, new Set(['chainId', 'address', 'protocolId', 'maxNativeValueWei', 'allowEmptyCalldata', 'methods']), path, errors);
      if (!Number.isSafeInteger(contract.chainId) || contract.chainId < 1) errors.push(issue('invalid-chain', `${path}.chainId`, 'Contract chainId must be a positive safe integer.'));
      if (!ADDRESS.test(String(contract.address ?? ''))) errors.push(issue('invalid-address', `${path}.address`, 'Contract requires an exact 20-byte address.'));
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
          rejectUnknown(method, new Set(['selector', 'name', 'constraints']), methodPath, errors);
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
  return { valid: errors.length === 0, errors };
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isPlainObject(value)) return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  return value;
}

export function canonicalJson(value) { return JSON.stringify(canonicalize(value)); }
export function sha256(value) { return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex'); }

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

function normalizeQuantity(value, path, errors, { required = false, fallback = null } = {}) {
  if (value == null || value === '') {
    if (required) errors.push(issue('missing-quantity', path, 'Required quantity is missing.'));
    return fallback;
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

export function normalizeIntent(intent) {
  const errors = [];
  if (!isPlainObject(intent)) return { valid: false, errors: [issue('invalid-intent', '$', 'Transaction intent must be an object.')], intent: null };
  rejectUnknown(intent, new Set(['chainId', 'from', 'to', 'data', 'value', 'gas', 'gasLimit', 'maxFeePerGas', 'maxPriorityFeePerGas']), '$', errors);
  let chainId = intent.chainId;
  if (typeof chainId === 'string' && (/^0x[0-9a-fA-F]+$/.test(chainId) || DECIMAL_UINT.test(chainId))) chainId = Number(BigInt(chainId));
  if (!Number.isSafeInteger(chainId) || chainId < 1) errors.push(issue('invalid-chain', '$.chainId', 'Intent requires a positive chain ID.'));
  if (!ADDRESS.test(String(intent.from ?? ''))) errors.push(issue('invalid-address', '$.from', 'Intent requires an exact from address.'));
  if (!ADDRESS.test(String(intent.to ?? ''))) errors.push(issue('invalid-address', '$.to', 'Intent requires an exact to address. Contract creation is not supported.'));
  const data = intent.data ?? '0x';
  if (!HEX_DATA.test(String(data))) errors.push(issue('invalid-calldata', '$.data', 'Calldata must be even-length hexadecimal bytes.'));
  const value = normalizeQuantity(intent.value, '$.value', errors, { fallback: 0n });
  if (intent.gas != null && intent.gasLimit != null && String(intent.gas) !== String(intent.gasLimit)) errors.push(issue('conflicting-gas', '$.gasLimit', 'gas and gasLimit must not disagree.'));
  const gas = normalizeQuantity(intent.gas ?? intent.gasLimit, '$.gas', errors);
  const maxFeePerGas = normalizeQuantity(intent.maxFeePerGas, '$.maxFeePerGas', errors);
  const maxPriorityFeePerGas = normalizeQuantity(intent.maxPriorityFeePerGas, '$.maxPriorityFeePerGas', errors);
  const normalized = errors.length ? null : {
    chainId,
    from: intent.from.toLowerCase(),
    to: intent.to.toLowerCase(),
    data: data.toLowerCase(),
    value,
    gas,
    maxFeePerGas,
    maxPriorityFeePerGas,
  };
  return { valid: errors.length === 0, errors, intent: normalized };
}

function calldataWord(data, argument) {
  const start = 10 + argument * 64;
  if (data.length < start + 64) return null;
  return data.slice(start, start + 64).toLowerCase();
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
    maxFeePerGas: intent.maxFeePerGas?.toString() ?? null,
    maxPriorityFeePerGas: intent.maxPriorityFeePerGas?.toString() ?? null,
  };
}

/** Deterministically authorize the exact transaction that will be forwarded to the wallet. */
export function authorizeIntent(policy, rawIntent, { now = new Date() } = {}) {
  const evaluatedAt = new Date(now).toISOString();
  const policyValidation = validatePolicy(policy);
  const policyHash = policyValidation.valid ? sha256(policy) : null;
  const checks = [];
  const add = (id, ok, detail) => { checks.push({ id, status: ok ? 'pass' : 'deny', detail }); return ok; };
  if (!policyValidation.valid) {
    policyValidation.errors.forEach((error) => add(`policy:${error.code}`, false, `${error.path}: ${error.message}`));
    return { version: 1, decision: 'deny', evaluatedAt, policy: { name: policy?.name ?? null, hash: policyHash }, intent: null, checks };
  }
  const normalized = normalizeIntent(rawIntent);
  if (!normalized.valid) {
    normalized.errors.forEach((error) => add(`intent:${error.code}`, false, `${error.path}: ${error.message}`));
    return { version: 1, decision: 'deny', evaluatedAt, policy: { name: policy.name, hash: policyHash }, intent: null, checks };
  }
  const intent = normalized.intent;
  const summary = { ...serializableIntent(intent), selector: intent.data.length >= 10 ? intent.data.slice(0, 10) : null };
  const receiptIntent = { ...summary, hash: sha256(serializableIntent(intent)) };

  if (policy.validUntil) add('policy:not-expired', Date.parse(policy.validUntil) > new Date(now).getTime(), `Policy expires at ${policy.validUntil}.`);
  add('chain:allowed', policy.chains.includes(intent.chainId), `Chain ${intent.chainId} must be allowlisted.`);
  if (policy.wallets?.length) add('wallet:allowed', policy.wallets.some((x) => x.toLowerCase() === intent.from), `Wallet ${intent.from} must be allowlisted.`);

  const invariants = policy.invariants;
  const maxValue = BigInt(invariants.maxNativeValueWei);
  add('value:global-limit', intent.value <= maxValue, `Native value ${intent.value} must not exceed ${maxValue} wei.`);
  if (invariants.maxGas != null) add('gas:limit', intent.gas != null && intent.gas <= BigInt(invariants.maxGas), `Gas must be present and at most ${invariants.maxGas}.`);
  if (invariants.maxFeePerGasWei != null) add('fee:max', intent.maxFeePerGas != null && intent.maxFeePerGas <= BigInt(invariants.maxFeePerGasWei), `maxFeePerGas must be present and at most ${invariants.maxFeePerGasWei}.`);
  if (invariants.maxPriorityFeePerGasWei != null) add('fee:priority', intent.maxPriorityFeePerGas != null && intent.maxPriorityFeePerGas <= BigInt(invariants.maxPriorityFeePerGasWei), `maxPriorityFeePerGas must be present and at most ${invariants.maxPriorityFeePerGasWei}.`);

  const contract = policy.contracts.find((entry) => entry.chainId === intent.chainId && entry.address.toLowerCase() === intent.to);
  add('target:allowlisted', Boolean(contract), `Target ${intent.to} must match an exact contract entry on chain ${intent.chainId}.`);
  if (contract) {
    if (contract.maxNativeValueWei != null) add('value:contract-limit', intent.value <= BigInt(contract.maxNativeValueWei), `Native value must not exceed this contract's ${contract.maxNativeValueWei} wei limit.`);
    if (intent.data === '0x') {
      add('calldata:required', invariants.requireCalldata !== true, 'Global policy requires calldata.');
      add('target:empty-calldata', contract.allowEmptyCalldata === true, 'Target must explicitly allow empty calldata.');
    } else if (intent.data.length < 10) add('calldata:selector', false, 'Calldata must include a complete four-byte selector.');
    else {
      const selector = intent.data.slice(0, 10);
      const method = contract.methods?.find((entry) => entry.selector.toLowerCase() === selector);
      add('method:allowlisted', Boolean(method), `Selector ${selector} must be allowlisted for this target.`);
      if (selector === '0x095ea7b3') {
        const amountWord = calldataWord(intent.data, 1);
        add('erc20:no-unlimited-approval', Boolean(amountWord) && BigInt(`0x${amountWord}`) !== MAX_UINT256, 'ERC-20 approval amount must not be uint256 max.');
      }
      for (const [index, constraint] of (method?.constraints ?? []).entries()) {
        const result = evaluateConstraint(constraint, intent.data);
        add(`constraint:${index}:${constraint.type}`, result.ok, result.detail);
      }
    }
  }
  const decision = checks.some((check) => check.status === 'deny') ? 'deny' : 'allow';
  return { version: 1, decision, evaluatedAt, policy: { name: policy.name, hash: policyHash }, intent: receiptIntent, checks };
}

/** Find structurally valid but broad rules that deserve human review before activation. */
export function auditPolicy(policy) {
  const validation = validatePolicy(policy);
  const findings = [...validation.errors];
  if (!validation.valid) return { valid: false, policyHash: null, findings };
  if (!policy.wallets?.length) findings.push(issue('unbound-wallet', '$.wallets', 'Policy is not bound to a specific wallet.', 'high'));
  if (!policy.validUntil) findings.push(issue('no-expiry', '$.validUntil', 'Policy does not expire automatically.', 'medium'));
  policy.contracts.forEach((contract, index) => {
    if (!contract.protocolId) findings.push(issue('missing-protocol-binding', `$.contracts[${index}].protocolId`, 'Contract is not bound to a protocol identity for live-state enforcement.', 'high'));
    if (contract.allowEmptyCalldata) findings.push(issue('native-transfer-enabled', `$.contracts[${index}].allowEmptyCalldata`, 'Contract accepts empty-calldata native transfers.', 'medium'));
    contract.methods?.forEach((method, methodIndex) => {
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
