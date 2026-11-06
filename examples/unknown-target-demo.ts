import type { JsonRpcProvider } from 'ethers';

// Deliberately absent from the registry and .secu known-address terms.
const UNMAPPED_DEMO_TARGET = '0x1234567890abcdef1234567890abcdef12345678';

// This is an illustrative read-only call; the function is not invoked by this example.
export async function inspectUnknownTarget(provider: JsonRpcProvider) {
  return provider.call({ to: UNMAPPED_DEMO_TARGET, data: '0x' });
}
