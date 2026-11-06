const NATIVE = 'native';
const BLOCKS_KEPT = 64n;

/** Read the per-block limits a policy sets. Assets without a limit are left to the per-transaction checks. */
export function blockSpendLimits(policy, chainId) {
  const limits = new Map();
  if (policy?.invariants?.maxNativeOutflowPerBlockWei != null) limits.set(NATIVE, BigInt(policy.invariants.maxNativeOutflowPerBlockWei));
  for (const limit of policy?.simulation?.assetLimits ?? []) {
    if (limit.chainId === chainId && limit.maxOutflowPerBlock != null) limits.set(limit.token.toLowerCase(), BigInt(limit.maxOutflowPerBlock));
  }
  return limits;
}

/** What one transaction spends, by asset, from simulated or on-chain results. */
export function spendByAsset({ nativeOutflow = '0', outflows = {} }) {
  const spend = new Map();
  if (BigInt(nativeOutflow) > 0n) spend.set(NATIVE, BigInt(nativeOutflow));
  for (const [token, amount] of Object.entries(outflows ?? {})) if (BigInt(amount) > 0n) spend.set(token.toLowerCase(), BigInt(amount));
  return spend;
}

function assetName(asset) { return asset === NATIVE ? 'native ETH (wei)' : `token ${asset}`; }

/**
 * Running totals per block, per wallet. Checking and reserving happen in one synchronous step,
 * so two requests running at the same time cannot both use the same room under a limit.
 */
export function createBlockSpendTracker() {
  const totals = new Map();
  const keyOf = (chainId, wallet, block) => `${chainId}:${String(wallet).toLowerCase()}:${block}`;

  function prune(chainId, block) {
    const oldest = block - BLOCKS_KEPT;
    for (const key of totals.keys()) {
      const [keyChain, , keyBlock] = key.split(':');
      if (Number(keyChain) === chainId && BigInt(keyBlock) < oldest) totals.delete(key);
    }
  }

  return Object.freeze({
    /** Add spend if every asset stays within its limit. Otherwise add nothing and report what broke. */
    reserve({ chainId, wallet, block, spend, limits }) {
      const key = keyOf(chainId, wallet, block);
      const current = totals.get(key) ?? new Map();
      const breaches = [];
      for (const [asset, amount] of spend) {
        const limit = limits.get(asset);
        if (limit == null) continue;
        const already = current.get(asset) ?? 0n;
        if (already + amount > limit) breaches.push({ asset, assetName: assetName(asset), limit: limit.toString(), alreadySpent: already.toString(), amount: amount.toString(), total: (already + amount).toString() });
      }
      if (breaches.length) return { ok: false, breaches, reservation: null };
      for (const [asset, amount] of spend) current.set(asset, (current.get(asset) ?? 0n) + amount);
      totals.set(key, current);
      prune(chainId, BigInt(block));
      return { ok: true, breaches: [], reservation: { key, spend } };
    },
    /** Give the room back when the wallet never accepted the transaction. */
    release(reservation) {
      if (!reservation) return;
      const current = totals.get(reservation.key);
      if (!current) return;
      for (const [asset, amount] of reservation.spend) {
        const next = (current.get(asset) ?? 0n) - amount;
        if (next > 0n) current.set(asset, next); else current.delete(asset);
      }
    },
    /** Record what really landed, and report any limit the block has now gone over. */
    recordOnChain({ chainId, wallet, block, spend, limits }) {
      const key = `onchain:${keyOf(chainId, wallet, block)}`;
      const current = totals.get(key) ?? new Map();
      const breaches = [];
      for (const [asset, amount] of spend) {
        const total = (current.get(asset) ?? 0n) + amount;
        current.set(asset, total);
        const limit = limits.get(asset);
        if (limit != null && total > limit) breaches.push({ asset, assetName: assetName(asset), limit: limit.toString(), total: total.toString() });
      }
      totals.set(key, current);
      return breaches;
    },
    clear() { totals.clear(); },
  });
}

/** Apply per-block limits to an allowed receipt, reserving the spend when it fits. */
export function applyBlockSpendLimits(policy, receipt, tracker) {
  const limits = blockSpendLimits(policy, receipt.intent?.chainId);
  if (!limits.size) return { receipt, reservation: null, breaches: [] };
  const metrics = receipt.simulation?.metrics;
  const block = receipt.simulation?.blockNumber;
  const deny = (detail, breaches = []) => ({
    receipt: { ...receipt, decision: 'deny', checks: [...receipt.checks, { id: 'spend:block-limit', status: 'deny', detail }] },
    reservation: null,
    breaches,
  });
  if (!metrics || block == null) return deny('The policy sets a per-block spend limit, but simulation reported no block or spend to check it against.');
  const spend = spendByAsset(metrics);
  const result = tracker.reserve({ chainId: receipt.intent.chainId, wallet: receipt.intent.from, block, spend, limits });
  if (!result.ok) {
    const first = result.breaches[0];
    return deny(`Block ${block} spend limit reached for ${first.assetName}: ${first.alreadySpent} already spent plus ${first.amount} exceeds ${first.limit}.`, result.breaches);
  }
  return {
    receipt: { ...receipt, checks: [...receipt.checks, { id: 'spend:block-limit', status: 'pass', detail: `Spend fits every per-block limit for block ${block}.` }] },
    reservation: result.reservation,
    breaches: [],
  };
}
