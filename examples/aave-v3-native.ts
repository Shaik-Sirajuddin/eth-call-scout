import { Contract, JsonRpcProvider, Wallet } from 'ethers';

const provider = new JsonRpcProvider(process.env.ETHEREUM_RPC_URL);
const wallet = new Wallet(process.env.PRIVATE_KEY ?? '', provider);

const AAVE_V3_POOL_ADDRESS = '0x87870Bca3F3fD6335C3F4ce8392D69350B4fa4E2';
const AAVE_V3_POOL_ABI = [
  'function getReserveData(address asset) view returns (tuple(uint256 configuration,uint128 liquidityIndex,uint128 currentLiquidityRate,uint128 variableBorrowIndex,uint128 currentVariableBorrowRate,uint128 currentStableBorrowRate,uint40 lastUpdateTimestamp,uint16 id,address aTokenAddress,address stableDebtTokenAddress,address variableDebtTokenAddress,address interestRateStrategyAddress,uint128 accruedToTreasury,uint128 unbacked,uint128 isolationModeTotalDebt))',
  'function supply(address asset,uint256 amount,address onBehalfOf,uint16 referralCode)',
];

const pool = new Contract(AAVE_V3_POOL_ADDRESS, AAVE_V3_POOL_ABI, wallet);

export async function inspectAaveReserve(asset: string) {
  return pool.getReserveData(asset);
}

export async function supplyToAave(asset: string, amount: bigint, beneficiary: string) {
  return pool.supply(asset, amount, beneficiary, 0);
}

// Native JSON-RPC variation: raw eth_call to the same Aave Pool address.
export async function readPoolCode() {
  return provider.send('eth_getCode', [AAVE_V3_POOL_ADDRESS, 'latest']);
}
