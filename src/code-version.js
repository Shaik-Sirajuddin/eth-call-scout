import { keccak256 } from 'ethers';

const IMPLEMENTATION_SLOTS = [
  '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc', // EIP-1967
  '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036a5a723fd8ee048ed3f8c3', // ZeppelinOS, used by USDC
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
