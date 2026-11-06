import { Contract, JsonRpcProvider, Wallet } from 'ethers';

const provider = new JsonRpcProvider(process.env.ETHEREUM_RPC_URL);
const signer = new Wallet(process.env.PRIVATE_KEY ?? '', provider);

const UNISWAP_V3_SWAP_ROUTER = '0xE592427A0AEce92De3Edee1F18E0157C05861564';
const UNISWAP_V3_ROUTER_ABI = [
  'function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 deadline,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params) payable returns (uint256 amountOut)',
];

const swapRouter = new Contract(UNISWAP_V3_SWAP_ROUTER, UNISWAP_V3_ROUTER_ABI, signer);

export async function swapOnUniswapV3(input: {
  tokenIn: string;
  tokenOut: string;
  recipient: string;
  amountIn: bigint;
  minimumOutput: bigint;
}) {
  return swapRouter.exactInputSingle({
    tokenIn: input.tokenIn,
    tokenOut: input.tokenOut,
    fee: 3000,
    recipient: input.recipient,
    deadline: Math.floor(Date.now() / 1000) + 300,
    amountIn: input.amountIn,
    amountOutMinimum: input.minimumOutput,
    sqrtPriceLimitX96: 0,
  });
}

// Native RPC variation: a JSON-RPC eth_call with a dynamic target/data payload.
export async function simulateRawRouterCall(calldata: string) {
  return provider.send('eth_call', [
    { to: UNISWAP_V3_SWAP_ROUTER, data: calldata },
    'latest',
  ]);
}
