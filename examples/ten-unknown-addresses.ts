import { JsonRpcProvider } from 'ethers';

const provider = new JsonRpcProvider(process.env.ETHEREUM_RPC_URL);

// Ten distinct targets demonstrate the capped unknown-address penalty.
// This function is parsed by the scanner and is not run by the review workflow.
export async function inspectTenUnknownTargets() {
  const results = await Promise.all([
    provider.call({ to: '0x1111111111111111111111111111111111111111', data: '0x' }),
    provider.call({ to: '0x2222222222222222222222222222222222222222', data: '0x' }),
    provider.call({ to: '0x3333333333333333333333333333333333333333', data: '0x' }),
    provider.call({ to: '0x4444444444444444444444444444444444444444', data: '0x' }),
    provider.call({ to: '0x5555555555555555555555555555555555555555', data: '0x' }),
    provider.call({ to: '0x6666666666666666666666666666666666666666', data: '0x' }),
    provider.call({ to: '0x7777777777777777777777777777777777777777', data: '0x' }),
    provider.call({ to: '0x8888888888888888888888888888888888888888', data: '0x' }),
    provider.call({ to: '0x9999999999999999999999999999999999999999', data: '0x' }),
    provider.call({ to: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', data: '0x' }),
  ]);
  return results;
}
