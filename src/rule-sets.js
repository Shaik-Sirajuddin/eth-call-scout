import fs from 'node:fs';

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const TRANSFER_SIGNATURE = 'transfer(address,uint256)';
const TRANSFER_SELECTOR = '0xa9059cbb';

/** Ready-made rules measured on real contracts, so a normal user does not have to write any. */
export const GENERAL_RULE_SET = Object.freeze(JSON.parse(fs.readFileSync(new URL('../data/rule-sets/general.json', import.meta.url), 'utf8')));

/** What each type of user is allowed to do. Everything outside the chosen groups stays denied. */
export function ruleSetProfiles(ruleSet = GENERAL_RULE_SET) {
  return { ...ruleSet.profiles, payments: [] };
}

function resolveLimit(asset, overrides) {
  const custom = overrides?.[asset.symbol] ?? {};
  return {
    maxOutflow: custom.maxOutflow ?? asset.maxOutflow,
    maxOutflowPerBlock: custom.maxOutflowPerBlock ?? asset.maxOutflowPerBlock,
    maxApproval: custom.maxApproval ?? asset.maxApproval,
  };
}

/**
 * Build a complete policy from a rule set. Users set low limits, or add payees and blocked addresses,
 * without writing selectors or call rules by hand.
 */
export function createPolicyFromRuleSet({
  ruleSet = GENERAL_RULE_SET,
  profile = 'general',
  wallet,
  trustedKeys,
  sources = [{ id: 'sim-primary', env: 'CALLSCOUT_SIM_PRIMARY' }, { id: 'sim-secondary', env: 'CALLSCOUT_SIM_SECONDARY' }],
  validUntil = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
  name = null,
  limits = {},
  native = {},
  payees = [],
  blockedAddresses = [],
  timeoutMs = 25_000,
}) {
  if (!ADDRESS.test(String(wallet))) throw new Error('A rule set needs one exact wallet address.');
  const profiles = ruleSetProfiles(ruleSet);
  const groups = profiles[profile];
  if (!groups) throw new Error(`Unknown profile ${profile}. Choose one of: ${Object.keys(profiles).join(', ')}.`);
  for (const payee of payees) if (!ADDRESS.test(String(payee))) throw new Error(`Invalid payee address ${payee}.`);
  const selected = new Set(['tokens', ...groups]);
  const nativeValue = native.maxValueWei ?? ruleSet.native.maxValueWei;
  const nativePerBlock = native.maxPerBlockWei ?? ruleSet.native.maxPerBlockWei;

  const contractsInUse = ruleSet.contracts.filter((contract) => selected.has(contract.group));
  const addressesInUse = new Set(contractsInUse.map((contract) => contract.address.toLowerCase()));
  const internalTargets = [...new Set(groups.flatMap((group) => ruleSet.internalTargets[group] ?? []))];
  const assetsInUse = ruleSet.assetLimits.filter((asset) => selected.has(asset.group));
  const recipientsInUse = new Set([...internalTargets, ...assetsInUse.map((asset) => asset.token.toLowerCase()), ZERO_ADDRESS, ...payees.map((payee) => payee.toLowerCase())]);

  const assetLimits = assetsInUse.map((asset) => {
    const limit = resolveLimit(asset, limits);
    const isPlainToken = asset.group === 'tokens';
    return {
      chainId: ruleSet.chainId,
      token: asset.token,
      maxOutflow: limit.maxOutflow,
      maxOutflowPerBlock: limit.maxOutflowPerBlock,
      maxApproval: limit.maxApproval,
      allowedRecipients: [...asset.allowedRecipients.filter((address) => recipientsInUse.has(address.toLowerCase())), ...(isPlainToken ? payees : [])],
      allowedSpenders: asset.allowedSpenders.filter((address) => addressesInUse.has(address.toLowerCase())),
    };
  });

  const tokenLimit = (address) => resolveLimit(ruleSet.assetLimits.find((asset) => asset.token.toLowerCase() === address.toLowerCase()), limits).maxApproval;
  const fill = (value, contract) => (value === '$wallet' ? wallet : value === '$nativeLimit' ? nativeValue : value === '$tokenLimit' ? tokenLimit(contract.address) : value);
  const contracts = contractsInUse.map((contract) => {
    const methods = contract.methods
      .filter((method) => selected.has(method.group ?? contract.group))
      // Approvals are only useful when something is there to spend them.
      .filter((method) => method.signature !== 'approve(address,uint256)' || groups.length > 0)
      .map((method) => ({
        selector: method.selector,
        name: method.signature,
        constraints: method.constraints.map((constraint) => {
          if (constraint.addresses) {
            const addresses = constraint.addresses.map((address) => fill(address, contract));
            const narrowed = method.signature === 'approve(address,uint256)' ? addresses.filter((address) => addressesInUse.has(address.toLowerCase())) : addresses;
            return { ...constraint, addresses: narrowed };
          }
          return { ...constraint, value: fill(constraint.value, contract) };
        }),
      }));
    if (payees.length && contract.group === 'tokens') {
      methods.push({
        selector: TRANSFER_SELECTOR,
        name: TRANSFER_SIGNATURE,
        constraints: [{ type: 'address-in', argument: 0, addresses: payees }, { type: 'uint-max', argument: 1, value: tokenLimit(contract.address) }],
      });
    }
    return {
      chainId: ruleSet.chainId,
      address: contract.address,
      protocolId: contract.protocolId,
      maxNativeValueWei: fill(contract.maxNativeValueWei, contract),
      methods,
    };
  }).filter((contract) => contract.methods.length);
  if (!contracts.length) throw new Error(`Profile ${profile} allows nothing yet. Add a payee, or choose another profile.`);

  return {
    version: 1,
    name: name ?? `${ruleSet.name}: ${profile}`,
    defaultAction: 'deny',
    chains: [ruleSet.chainId],
    wallets: [wallet],
    validUntil,
    blockedAddresses,
    protocolState: { required: true, maxAgeSeconds: 300, maxClockSkewSeconds: 15, minimumSequence: 1, threshold: 2, trustedKeys },
    simulation: {
      required: true,
      blockTag: 'pending',
      timeoutMs,
      quorum: 2,
      maxBlockSkew: 5,
      maxGasEstimate: ruleSet.invariants.maxGas,
      ...ruleSet.simulation,
      denyCodeChanges: true,
      eip7702: { allowAuthorizationList: false, allowDelegatedWallet: false, maxAuthorizations: 1, delegates: [] },
      internalTargets: internalTargets.map((address) => ({ chainId: ruleSet.chainId, address })),
      assetLimits,
      sources,
    },
    invariants: {
      maxNativeValueWei: nativeValue,
      maxNativeOutflowPerBlockWei: nativePerBlock,
      ...ruleSet.invariants,
      requireCalldata: true,
      denyUnlimitedApproval: true,
    },
    contracts,
  };
}

/** Build the monitor that signs protocol health for a policy, with each contract pinned to its measured code. */
export function createMonitorFromPolicy(policy, { ruleSet = GENERAL_RULE_SET, sources, stateTtlSeconds = 300, maxBlockSkew = 5, rpcTimeoutMs = 15_000 }) {
  const byProtocol = new Map();
  for (const contract of policy.contracts) {
    const measured = ruleSet.contracts.find((entry) => entry.address.toLowerCase() === contract.address.toLowerCase());
    if (!measured) throw new Error(`No measured code hash for ${contract.address}.`);
    const list = byProtocol.get(contract.protocolId) ?? [];
    list.push({ address: contract.address, codeHash: measured.codeHash });
    byProtocol.set(contract.protocolId, list);
  }
  return {
    version: 1,
    chainId: ruleSet.chainId,
    stateTtlSeconds,
    rpcTimeoutMs,
    rpcQuorum: 2,
    maxBlockSkew,
    sources,
    protocols: [...byProtocol].map(([id, contracts]) => ({ id, contracts })),
  };
}

/** Turn "12.5" into base units without rounding, so a limit never ends up larger than what was typed. */
export function toBaseUnits(amount, decimals) {
  const match = /^([0-9]+)(?:\.([0-9]+))?$/.exec(String(amount).trim());
  if (!match) throw new Error(`Invalid amount ${amount}.`);
  const fraction = match[2] ?? '';
  if (fraction.length > decimals && /[1-9]/.test(fraction.slice(decimals))) throw new Error(`Amount ${amount} has more than ${decimals} decimal places.`);
  return (BigInt(match[1]) * 10n ** BigInt(decimals) + BigInt((fraction.slice(0, decimals)).padEnd(decimals, '0') || '0')).toString();
}
