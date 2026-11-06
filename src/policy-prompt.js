import { validatePolicy } from './policy.js';

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const HASH = /^0x[a-fA-F0-9]{64}$/;
const SELECTOR = /^0x[a-fA-F0-9]{8}$/;
const CHAIN_ALIASES = new Map([
  ['ethereum', 1],
  ['ethereum mainnet', 1],
  ['mainnet', 1],
  ['optimism', 10],
  ['polygon', 137],
  ['arbitrum', 42161],
  ['arbitrum one', 42161],
  ['base', 8453],
  ['sepolia', 11155111],
]);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function issue(code, message, clause = null, path = null) {
  return { code, message, ...(clause ? { clause } : {}), ...(path ? { path } : {}) };
}

function normalizeName(value) {
  return String(value ?? '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

function parseDecimalUnits(value, decimals) {
  const normalized = String(value).replace(/,/g, '');
  const match = /^(\d+)(?:\.(\d+))?$/.exec(normalized);
  if (!match) throw new Error('Use a positive decimal amount.');
  const fraction = match[2] ?? '';
  if (fraction.length > decimals) throw new Error(`Amount has more than ${decimals} decimal places.`);
  const whole = BigInt(match[1]);
  const fractional = fraction ? BigInt(fraction.padEnd(decimals, '0')) : 0n;
  return (whole * (10n ** BigInt(decimals)) + fractional).toString();
}

function parseChain(value) {
  const normalized = normalizeName(value);
  if (CHAIN_ALIASES.has(normalized)) return CHAIN_ALIASES.get(normalized);
  if (/^[1-9][0-9]*$/.test(normalized)) {
    const parsed = Number(normalized);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
}

function splitClauses(prompt) {
  return String(prompt)
    .split(/\r?\n|(?<=[.!?])\s+/)
    .map((value) => value.trim().replace(/[.;]+$/, '').trim())
    .filter(Boolean);
}

function chainBindingFromClause(clause) {
  const numeric = /\bchain(?:\s+id)?\s+([1-9][0-9]*)\b/i.exec(clause);
  const named = /\bon\s+(ethereum\s+mainnet|arbitrum\s+one|ethereum|mainnet|optimism|polygon|arbitrum|base|sepolia)\b/i.exec(clause);
  const raw = numeric?.[1] ?? named?.[1];
  return raw ? { raw, chainId: parseChain(raw) } : null;
}

function lookupByName(items, requested, fields) {
  const target = normalizeName(requested);
  const exact = (items ?? []).filter((item) => fields.some((field) => normalizeName(item[field]) === target));
  return exact.length === 1 ? exact[0] : null;
}

function addRecognized(recognized, code, detail, clause) {
  recognized.push({ code, detail, clause });
}

function addContract(policy, contract, errors, clause) {
  const duplicate = policy.contracts.some((entry) => entry.chainId === contract.chainId && entry.address.toLowerCase() === contract.address.toLowerCase());
  if (duplicate) {
    errors.push(issue('duplicate-contract-rule', 'Describe each contract only once; duplicate rules are not merged because merging can broaden authority.', clause));
    return false;
  }
  policy.contracts.push(contract);
  return true;
}

function compileApproval({ amount, protocolName, tokenName, clause, policy, registry, recognized, errors }) {
  const chainId = policy.chains.length === 1 ? policy.chains[0] : null;
  if (!chainId) {
    errors.push(issue('ambiguous-chain', 'Approval rules require exactly one chain in the policy.', clause));
    return;
  }
  const token = lookupByName((registry.tokens ?? []).filter((entry) => entry.chainId === chainId), tokenName, ['symbol', 'name']);
  if (!token) {
    errors.push(issue('unknown-token', `No unique ${tokenName} token is registered on chain ${chainId}.`, clause));
    return;
  }
  const protocol = lookupByName(registry.protocols ?? [], protocolName, ['id', 'name']);
  if (!protocol) {
    errors.push(issue('unknown-protocol', `No unique protocol named ${protocolName} exists in the trusted registry.`, clause));
    return;
  }
  const spenders = (registry.contracts ?? []).filter((entry) => entry.chainId === chainId && entry.protocolId === protocol.id);
  const spender = spenders.find((entry) => entry.role === 'swap-router') ?? (spenders.length === 1 ? spenders[0] : null);
  if (!spender) {
    errors.push(issue('missing-protocol-contract', `${protocol.name} has no unique trusted spender contract on chain ${chainId}.`, clause));
    return;
  }
  let baseUnits;
  try {
    baseUnits = parseDecimalUnits(amount, token.decimals);
  } catch (error) {
    errors.push(issue('invalid-token-amount', error.message, clause));
    return;
  }
  if (BigInt(baseUnits) === 0n) {
    errors.push(issue('zero-token-amount', 'Approval limits must be greater than zero.', clause));
    return;
  }
  const added = addContract(policy, {
    chainId,
    address: token.address,
    protocolId: String(token.symbol).toLowerCase(),
    maxNativeValueWei: '0',
    methods: [{
      selector: '0x095ea7b3',
      name: 'approve(address,uint256)',
      constraints: [
        { type: 'address-in', argument: 0, addresses: [spender.address] },
        { type: 'uint-max', argument: 1, value: baseUnits },
      ],
    }],
  }, errors, clause);
  if (!added) return;
  policy.simulation.assetLimits.push({
    chainId,
    token: token.address,
    maxOutflow: '0',
    maxApproval: baseUnits,
    allowedRecipients: [],
    allowedSpenders: [spender.address],
  });
  addRecognized(recognized, 'approval-rule', `${token.symbol} approval capped at ${baseUnits} base units for ${spender.name} (${spender.address}).`, clause);
}

function parseThreshold(match, available, field, errors, clause) {
  const threshold = Number(match[1]);
  const total = Number(match[2]);
  if (!Number.isSafeInteger(threshold) || !Number.isSafeInteger(total) || threshold < 2 || total !== available || threshold > total) {
    errors.push(issue('invalid-quorum', `${field} must use at least two approvals and match the ${available} configured independent sources.`, clause));
    return null;
  }
  return threshold;
}

/**
 * Compile a deliberately small natural-language policy grammar into an untrusted
 * policy draft. The authoritative deterministic validator still decides whether
 * the result is structurally capable of activation.
 */
export function compilePolicyPrompt(prompt, { registry = {}, seedPolicy } = {}) {
  const source = typeof prompt === 'string' ? prompt.trim() : '';
  const recognized = [];
  const warnings = [];
  const errors = [];
  if (!source) return { version: 1, engine: 'deterministic-policy-prompt-v1', valid: false, policy: null, recognized, warnings, errors: [issue('empty-prompt', 'Describe at least one exact wallet rule.')] };
  if (source.length > 4_000) return { version: 1, engine: 'deterministic-policy-prompt-v1', valid: false, policy: null, recognized, warnings, errors: [issue('prompt-too-long', 'Policy descriptions are limited to 4,000 characters.')] };
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(source)) return { version: 1, engine: 'deterministic-policy-prompt-v1', valid: false, policy: null, recognized, warnings, errors: [issue('invalid-prompt-characters', 'Policy descriptions cannot contain control characters.')] };
  if (!seedPolicy || typeof seedPolicy !== 'object') return { version: 1, engine: 'deterministic-policy-prompt-v1', valid: false, policy: null, recognized, warnings, errors: [issue('missing-secure-template', 'A secure policy template is required.')] };

  const policy = clone(seedPolicy);
  policy.name = 'Prompt-authored wallet policy';
  policy.wallets = [];
  policy.contracts = [];
  policy.simulation.assetLimits = [];
  policy.simulation.eip7702 = { allowAuthorizationList: false, allowDelegatedWallet: false, maxAuthorizations: 1, delegates: [] };
  const clauses = splitClauses(source);
  let sawExpiry = false;
  let sawWallet = false;
  const mentionedChains = [...new Set(clauses.map((clause) => chainBindingFromClause(clause)?.chainId).filter(Boolean))];
  if (mentionedChains.length === 1) policy.chains = [mentionedChains[0]];
  else if (mentionedChains.length > 1) errors.push(issue('conflicting-chain-bindings', 'A version 1 prompt-authored policy must bind to exactly one chain.'));

  for (const clause of clauses) {
    const lower = clause.toLowerCase();
    let matched = false;

    if (/\b(?:allow|permit)\b.{0,80}\b(?:unlimited|no\s+limit)\b/i.test(clause)
      || /\ballow\s+(?:any|all)\b/i.test(clause)
      || /\bany\s+(?:contract|protocol|token|wallet|address|method|selector)\b/i.test(clause)) {
      errors.push(issue('unsafe-broad-rule', 'Broad or unlimited permissions are not supported; use exact targets and numeric ceilings.', clause));
      matched = true;
    }
    if (/\b(?:disable|skip|bypass|ignore|without)\b.{0,40}\b(?:simulation|live state|validation|quorum)\b/i.test(clause)) {
      errors.push(issue('security-bypass-request', 'Simulation, live state, validation, and quorum checks cannot be disabled by a prompt.', clause));
      matched = true;
    }
    if (/\b(?:private key|seed phrase|mnemonic|raw sign|eth_sign|sendrawtransaction)\b/i.test(clause)) {
      errors.push(issue('signer-access-request', 'Policy authoring cannot expose signing material or raw signing methods.', clause));
      matched = true;
    }

    const nameMatch = /(?:create|name)(?:\s+(?:a|the))?(?:\s+policy)?(?:\s+named)?\s+["“]([^"”]{1,80})["”]/i.exec(clause);
    if (nameMatch) {
      policy.name = nameMatch[1].trim();
      addRecognized(recognized, 'policy-name', `Policy name set to “${policy.name}”.`, clause);
      matched = true;
    }

    const walletMatch = /\bwallet\s+(0x[a-fA-F0-9]{40})\b/i.exec(clause);
    if (walletMatch) {
      policy.wallets = [walletMatch[1]];
      sawWallet = true;
      addRecognized(recognized, 'wallet-binding', `Policy bound to ${walletMatch[1]}.`, clause);
      matched = true;
    } else if (/\bwallet\s+0x/i.test(clause)) {
      errors.push(issue('invalid-wallet', 'Wallet binding must be one exact 20-byte address.', clause));
      matched = true;
    }

    const chainBinding = chainBindingFromClause(clause);
    if (chainBinding) {
      const { chainId } = chainBinding;
      if (chainId) {
        addRecognized(recognized, 'chain-binding', `Policy bound to chain ${chainId}.`, clause);
      } else errors.push(issue('invalid-chain', 'Chain must be a supported name or positive safe integer.', clause));
      matched = true;
    }

    const expiryMatch = /\bexpire(?:s|d)?\s+(?:on|at)\s+(\d{4}-\d{2}-\d{2})(?:[tT ](\d{2}:\d{2}(?::\d{2})?(?:\.\d{1,3})?)(?:[zZ])?)?\b/i.exec(clause);
    if (expiryMatch) {
      const iso = expiryMatch[2] ? `${expiryMatch[1]}T${expiryMatch[2]}${/[zZ]$/.test(expiryMatch[0]) ? '' : 'Z'}` : `${expiryMatch[1]}T00:00:00.000Z`;
      const parsed = Date.parse(iso);
      if (Number.isFinite(parsed)) {
        policy.validUntil = new Date(parsed).toISOString();
        sawExpiry = true;
        addRecognized(recognized, 'policy-expiry', `Policy expires at ${policy.validUntil}.`, clause);
        if (parsed <= Date.now()) errors.push(issue('expired-policy', 'Policy expiry must be in the future.', clause));
      } else errors.push(issue('invalid-expiry', 'Expiry must be a real ISO date such as 2030-01-01.', clause));
      matched = true;
    }

    const priorityFeeMatch = /\bmax(?:imum)?\s+priority\s+fee(?:\s+per\s+gas)?(?:\s+(?:is|of|to))?\s+([\d,]+(?:\.\d+)?)\s*(gwei|wei)\b/i.exec(clause);
    if (priorityFeeMatch) {
      try {
        policy.invariants.maxPriorityFeePerGasWei = parseDecimalUnits(priorityFeeMatch[1], priorityFeeMatch[2].toLowerCase() === 'gwei' ? 9 : 0);
        addRecognized(recognized, 'priority-fee-cap', `Priority fee capped at ${policy.invariants.maxPriorityFeePerGasWei} wei.`, clause);
      } catch (error) { errors.push(issue('invalid-priority-fee-cap', error.message, clause)); }
      matched = true;
    }

    const feeMatch = /\bmax(?:imum)?\s+fee(?:\s+per\s+gas)?(?:\s+(?:is|of|to))?\s+([\d,]+(?:\.\d+)?)\s*(gwei|wei)\b/i.exec(clause);
    if (feeMatch && !priorityFeeMatch) {
      try {
        const value = parseDecimalUnits(feeMatch[1], feeMatch[2].toLowerCase() === 'gwei' ? 9 : 0);
        policy.invariants.maxFeePerGasWei = value;
        policy.invariants.maxGasPriceWei = value;
        addRecognized(recognized, 'fee-cap', `Fee and legacy gas-price caps set to ${value} wei.`, clause);
      } catch (error) { errors.push(issue('invalid-fee-cap', error.message, clause)); }
      matched = true;
    }

    const nativeMatch = /\bmax(?:imum)?\s+native\s+value(?:\s+(?:is|of|to))?\s+([\d,]+(?:\.\d+)?)\s*(eth|wei)\b/i.exec(clause);
    if (nativeMatch) {
      try {
        policy.invariants.maxNativeValueWei = parseDecimalUnits(nativeMatch[1], nativeMatch[2].toLowerCase() === 'eth' ? 18 : 0);
        addRecognized(recognized, 'native-value-cap', `Native value capped at ${policy.invariants.maxNativeValueWei} wei.`, clause);
      } catch (error) { errors.push(issue('invalid-native-value-cap', error.message, clause)); }
      matched = true;
    }

    const gasMatch = /\bmax(?:imum)?\s+(?:transaction\s+)?gas(?:\s+(?:is|of|to))?\s+([\d,]+)\b/i.exec(clause);
    if (gasMatch) {
      const gas = gasMatch[1].replace(/,/g, '');
      if (/^[1-9][0-9]*$/.test(gas)) {
        policy.invariants.maxGas = gas;
        policy.simulation.maxGasEstimate = gas;
        addRecognized(recognized, 'gas-cap', `Transaction and simulation gas capped at ${gas}.`, clause);
      } else errors.push(issue('invalid-gas-cap', 'Gas cap must be a positive integer.', clause));
      matched = true;
    }

    const stateMatch = /\brequire\s+(\d+)\s+of\s+(\d+)\s+(?:live[ -]?state|protocol[ -]?state)\s+(?:signers?|signatures?|keys?)\b/i.exec(clause);
    if (stateMatch) {
      const threshold = parseThreshold(stateMatch, policy.protocolState.trustedKeys.length, 'Live-state threshold', errors, clause);
      if (threshold != null) {
        policy.protocolState.threshold = threshold;
        addRecognized(recognized, 'live-state-quorum', `Live state requires ${threshold} of ${policy.protocolState.trustedKeys.length} signatures.`, clause);
      }
      matched = true;
    }

    const simulationMatch = /\brequire\s+(\d+)\s+of\s+(\d+)\s+(?:simulation|trace)\s+sources?\b/i.exec(clause);
    if (simulationMatch) {
      const quorum = parseThreshold(simulationMatch, policy.simulation.sources.length, 'Simulation quorum', errors, clause);
      if (quorum != null) {
        policy.simulation.quorum = quorum;
        addRecognized(recognized, 'simulation-quorum', `Full simulation requires ${quorum} of ${policy.simulation.sources.length} sources.`, clause);
      }
      matched = true;
    }

    if (/\b(?:deny|disable|disallow)\s+(?:eip[- ]?)?7702\b/i.test(clause)) {
      policy.simulation.eip7702 = { allowAuthorizationList: false, allowDelegatedWallet: false, maxAuthorizations: 1, delegates: [] };
      addRecognized(recognized, 'eip7702-deny', 'EIP-7702 authorization lists and already-delegated EOAs are denied.', clause);
      matched = true;
    }

    const auth7702 = /\ballow\s+(?:eip[- ]?)?7702\s+authorization\s+lists?\s+for\s+delegate\s+(0x[a-fA-F0-9]{40})\s+on\s+([a-zA-Z0-9 ]+?)\s+with\s+(?:runtime\s+)?code\s+hash\s+(0x[a-fA-F0-9]{64})\b/i.exec(clause);
    const delegated7702 = /\ballow\s+(?:an?\s+)?already[- ]delegated\s+(?:eoa|wallet)\s+for\s+delegate\s+(0x[a-fA-F0-9]{40})\s+on\s+([a-zA-Z0-9 ]+?)\s+with\s+(?:runtime\s+)?code\s+hash\s+(0x[a-fA-F0-9]{64})\b/i.exec(clause);
    const eipMatch = auth7702 ?? delegated7702;
    if (eipMatch) {
      const chainId = parseChain(eipMatch[2]);
      if (!ADDRESS.test(eipMatch[1]) || !HASH.test(eipMatch[3]) || !chainId || !policy.chains.includes(chainId)) {
        errors.push(issue('invalid-eip7702-opt-in', 'EIP-7702 opt-in requires an exact non-zero delegate, 32-byte runtime code hash, and the policy chain.', clause));
      } else {
        const existing = policy.simulation.eip7702.delegates.find((entry) => entry.chainId === chainId && entry.address.toLowerCase() === eipMatch[1].toLowerCase());
        if (existing && existing.codeHash.toLowerCase() !== eipMatch[3].toLowerCase()) errors.push(issue('conflicting-eip7702-delegate', 'The same delegate cannot use two runtime code hashes.', clause));
        else if (!existing) policy.simulation.eip7702.delegates.push({ chainId, address: eipMatch[1], codeHash: eipMatch[3] });
        if (auth7702) policy.simulation.eip7702.allowAuthorizationList = true;
        if (delegated7702) policy.simulation.eip7702.allowDelegatedWallet = true;
        addRecognized(recognized, 'eip7702-pinned-opt-in', `EIP-7702 permission pinned to ${eipMatch[1]} and runtime code hash ${eipMatch[3]}.`, clause);
      }
      matched = true;
    } else if (/\ballow\b.{0,30}\b(?:eip[- ]?)?7702\b|\ballow\b.{0,30}\balready[- ]delegated\b/i.test(clause)) {
      errors.push(issue('unpinned-eip7702-opt-in', 'EIP-7702 opt-in must name the permission type, exact delegate, chain, and runtime code hash.', clause));
      matched = true;
    }

    const approvalMatch = /\ballow\s+([a-zA-Z0-9-]+)\s+approvals?\s+to\s+([a-zA-Z0-9 /_-]+?)\s+up\s+to\s+([\d,]+(?:\.\d+)?)\s+([a-zA-Z0-9-]+)\b/i.exec(clause);
    const spendMatch = /\ballow\s+([a-zA-Z0-9 /_-]+?)\s+to\s+spend\s+up\s+to\s+([\d,]+(?:\.\d+)?)\s+([a-zA-Z0-9-]+)\b/i.exec(clause);
    if (approvalMatch) {
      if (normalizeName(approvalMatch[1]) !== normalizeName(approvalMatch[4])) errors.push(issue('approval-token-mismatch', 'The approval token before and after the amount must match.', clause));
      else compileApproval({ tokenName: approvalMatch[1], protocolName: approvalMatch[2], amount: approvalMatch[3], clause, policy, registry, recognized, errors });
      matched = true;
    } else if (spendMatch) {
      compileApproval({ tokenName: spendMatch[3], protocolName: spendMatch[1], amount: spendMatch[2], clause, policy, registry, recognized, errors });
      matched = true;
    }

    const contractMatch = /\ballow\s+contract\s+(0x[a-fA-F0-9]{40})\s+on\s+([a-zA-Z0-9 ]+?)\s+for\s+protocol\s+([a-zA-Z0-9/_-]+)\s+(?:with\s+)?selector\s+(0x[a-fA-F0-9]{8})\b/i.exec(clause);
    if (contractMatch) {
      const chainId = parseChain(contractMatch[2]);
      const protocol = lookupByName(registry.protocols ?? [], contractMatch[3], ['id', 'name']);
      if (!chainId || !policy.chains.includes(chainId)) errors.push(issue('contract-chain-mismatch', 'The contract rule chain must exactly match the policy chain.', clause));
      else if (!protocol) errors.push(issue('unknown-protocol', `No unique protocol named ${contractMatch[3]} exists in the trusted registry.`, clause));
      else if (!SELECTOR.test(contractMatch[4])) errors.push(issue('invalid-selector', 'Contract rules require one exact four-byte selector.', clause));
      else if (addContract(policy, { chainId, address: contractMatch[1], protocolId: protocol.id, maxNativeValueWei: '0', methods: [{ selector: contractMatch[4], name: `selector ${contractMatch[4]}`, constraints: [] }] }, errors, clause)) addRecognized(recognized, 'contract-method-rule', `Allowed ${contractMatch[1]} selector ${contractMatch[4]} on chain ${chainId}.`, clause);
      matched = true;
    }

    if (!matched) errors.push(issue('unsupported-clause', 'This clause is not in the deterministic policy grammar. Rewrite it using an exact wallet, cap, quorum, approval, contract selector, expiry, or EIP-7702 rule.', clause));
  }

  if (!sawWallet) errors.push(issue('missing-wallet-clause', 'The prompt must bind the policy to one exact wallet address.'));
  if (!sawExpiry) errors.push(issue('missing-expiry-clause', 'The prompt must include an explicit expiry date.'));
  if (policy.contracts.length === 0) errors.push(issue('missing-allow-rule', 'The prompt must include at least one exact approval or contract-selector rule.'));

  const validation = validatePolicy(policy, { activation: true });
  for (const error of validation.errors) {
    if (!errors.some((entry) => entry.code === error.code && entry.path === error.path)) errors.push(issue(error.code, error.message, null, error.path));
  }
  if (!recognized.some((entry) => entry.code === 'eip7702-deny' || entry.code === 'eip7702-pinned-opt-in')) warnings.push(issue('implicit-eip7702-deny', 'EIP-7702 remains denied because the prompt did not explicitly opt in with a pinned delegate.'));
  return {
    version: 1,
    engine: 'deterministic-policy-prompt-v1',
    valid: errors.length === 0,
    policy,
    recognized,
    warnings,
    errors,
  };
}

export { parseDecimalUnits };
