import type { JsonRpcProvider } from 'ethers';

// Synthetic address listed in .secu as a blacklist fixture for the review workflow.
const BLACKLISTED_DEMO_TARGET = '0xBADDCAFE00000000000000000000000000000001';

// This is an illustrative read-only call; the function is not invoked by this example.
export async function inspectBlacklistedTarget(provider: JsonRpcProvider) {
  return provider.call({ to: BLACKLISTED_DEMO_TARGET, data: '0x' });
}
