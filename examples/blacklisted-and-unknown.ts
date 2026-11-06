import { JsonRpcProvider } from 'ethers';

const provider = new JsonRpcProvider(process.env.ETHEREUM_RPC_URL);
const BLACKLISTED_TARGET = '0xBADDCAFE00000000000000000000000000000001';
const UNKNOWN_TARGET = '0x1111111111111111111111111111111111111111';

// These examples are parsed as call sites; this function is not run by the review workflow.
export async function inspectBlacklistedAndUnknownTargets() {
  const blacklisted = await provider.call({ to: BLACKLISTED_TARGET, data: '0x' });
  const unknown = await provider.call({ to: UNKNOWN_TARGET, data: '0x' });
  return { blacklisted, unknown };
}
