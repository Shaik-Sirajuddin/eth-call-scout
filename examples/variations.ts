import { Contract, JsonRpcProvider } from 'ethers';
import { createPublicClient, http } from 'viem';

const TOKEN = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const BALANCE_OF_DATA = '0x70a082310000000000000000000000001111111111111111111111111111111111111111';
const UNISWAP_SWAP_ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const AAVE_V3_POOL = '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2';
const ABI = [{ type: 'function', name: 'balanceOf', inputs: [{ name: 'owner', type: 'address' }] }];

// ethers v6 and v5-shaped Contract interaction
const ethersProvider = new JsonRpcProvider('https://rpc.example');
const token = new Contract(TOKEN, ABI, ethersProvider);
export async function ethersReads(owner: string) {
  const balance = await token.balanceOf(owner);
  const supply = await token.totalSupply.staticCall();
  return { balance, supply };
}

// Representative call sites exercise the report's protocol and action labels.
const swapRouter = new Contract(UNISWAP_SWAP_ROUTER, ABI, ethersProvider);
const aavePool = new Contract(AAVE_V3_POOL, ABI, ethersProvider);
export async function swapExample(params: unknown) {
  return swapRouter.exactInputSingle(params);
}
export async function flashLoanExample(receiver: string, asset: string, amount: bigint, params: string) {
  return aavePool.flashLoanSimple(receiver, asset, amount, params, 0);
}

// viem's typed action/config style
const publicClient = createPublicClient({ transport: http() });
export async function viemRead(owner: `0x${string}`) {
  return publicClient.readContract({ address: TOKEN, abi: ABI, functionName: 'balanceOf', args: [owner] });
}

// Direct EIP-1193 request; address and calldata are values in eth_call's first param.
export async function walletRpc(provider: { request: (args: unknown) => Promise<unknown> }) {
  return provider.request({ method: 'eth_call', params: [{ to: TOKEN, data: BALANCE_OF_DATA }, 'latest'] });
}

// Native JSON-RPC send form
export async function rawRpc(provider: { send: (method: string, params: unknown[]) => Promise<unknown> }) {
  return provider.send('eth_call', [{ to: TOKEN, data: BALANCE_OF_DATA }, 'latest']);
}

// Direct HTTP JSON-RPC payload (often used to bypass an Ethereum client library)
export async function httpRpc() {
  return fetch('https://rpc.example', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: TOKEN, data: BALANCE_OF_DATA }, 'latest'] }) });
}

// Non-contract Ethereum JSON-RPC calls are included too.
export async function chainInfo(provider: { request: (args: unknown) => Promise<unknown> }) {
  return provider.request({ method: 'eth_chainId' });
}
