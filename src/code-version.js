import { keccak256 } from 'ethers';

export const IMPLEMENTATION_SLOTS = [
  '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc', // EIP-1967
  '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3', // ZeppelinOS, used by USDC
];
const IMPLEMENTATION_CALL = '0x5c60da1b'; // implementation()

function wordToAddress(word) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(word))) return null;
  const address = `0x${word.slice(-40).toLowerCase()}`;
  return /^0x0{40}$/.test(address) ? null : address;
}

/** Read the code identity of a contract. Gas costs belong to one version of the code. */
export async function readCodeVersion(rpc, address, blockTag = 'latest') {
  const codeHash = keccak256(await rpc('eth_getCode', [address, blockTag])).toLowerCase();
  for (const slot of IMPLEMENTATION_SLOTS) {
    const implementation = wordToAddress(await rpc('eth_getStorageAt', [address, slot, blockTag]));
    if (implementation) return { codeHash, implementation: { kind: 'slot', slot, address: implementation } };
  }
  let word = null;
  try { word = await rpc('eth_call', [{ to: address, data: IMPLEMENTATION_CALL }, blockTag]); }
  catch { /* A contract without implementation() is not this kind of proxy. */ }
  const implementation = wordToAddress(word);
  return { codeHash, implementation: implementation ? { kind: 'call', address: implementation } : null };
}

/** Compare a contract with the version pinned when its gas was measured. Returns why it differs, or null. */
export async function codeVersionChange(rpc, address, pin, blockTag = 'latest') {
  const codeHash = keccak256(await rpc('eth_getCode', [address, blockTag])).toLowerCase();
  if (codeHash !== pin.codeHash) return 'the contract code changed after it was measured';
  if (!pin.implementation) return null;
  const word = pin.implementation.kind === 'slot'
    ? await rpc('eth_getStorageAt', [address, pin.implementation.slot, blockTag])
    : await rpc('eth_call', [{ to: address, data: IMPLEMENTATION_CALL }, blockTag]);
  return wordToAddress(word) === pin.implementation.address ? null : 'the contract was upgraded after it was measured';
}

/**
 * Find the first block whose code is the current version, so samples from before an upgrade are not attributed
 * to it. It checks evenly spaced blocks from newest to oldest, then narrows down to the exact block. This needs
 * a node that keeps historical state. If the node cannot answer, this throws, so the caller leaves the rules out.
 * Contracts that are not proxies cannot change their code, so they need no search.
 */
export async function firstBlockOfCurrentVersion(rpc, address, pin, firstBlock, lastBlock, { probes = 32 } = {}) {
  if (!pin.implementation) return firstBlock;
  const isCurrent = async (block) => (await codeVersionChange(rpc, address, pin, `0x${block.toString(16)}`)) == null;
  const step = Math.max(1, Math.ceil((lastBlock - firstBlock) / probes));
  let matching = null;
  let differing = null;
  for (let block = lastBlock; ; block = Math.max(firstBlock, block - step)) {
    if (await isCurrent(block)) matching = block;
    else { differing = block; break; }
    if (block === firstBlock) return firstBlock;
  }
  if (matching == null) throw new Error('the newest block does not match the pinned code version');
  while (matching - differing > 1) {
    const middle = Math.floor((matching + differing) / 2);
    if (await isCurrent(middle)) matching = middle;
    else differing = middle;
  }
  return matching;
}

/** Keep only the gas samples measured on the current code. */
export function samplesFromBlock(samples, startBlock) {
  return samples.filter((sample) => sample.block >= startBlock);
}
