#!/usr/bin/env node
// Rebuilds data/gas-limits.json by sampling recent Ethereum mainnet blocks. Run with: npm run gas:sync
// Options: --blocks <count to sample> (default 3000), --window <blocks back> (default 50400, about 7 days), --out <file>.
// Set ETHEREUM_RPC_URL to use your own node.
import fs from 'node:fs';
import { FunctionFragment, id } from 'ethers';
import { readCodeVersion } from '../src/code-version.js';

const argument = (name) => { const index = process.argv.indexOf(name); return index < 0 ? null : process.argv[index + 1]; };
const OUTPUT = argument('--out') ?? new URL('../data/gas-limits.json', import.meta.url);
const BLOCKS = Number(argument('--blocks') ?? 3000);
const WINDOW = Number(argument('--window') ?? 50400);
const RPC_URL = process.env.ETHEREUM_RPC_URL ?? 'https://ethereum-rpc.publicnode.com';
const CONCURRENCY = 8;
const MAX_SAMPLES_PER_FUNCTION = 300;
const MIN_SAMPLES = 20;
const MAX_SPREAD = 4;
const SAFETY_MARGIN_PERCENT = 125n;
const ROUND_TO = 5000n;
const MIN_GAS = 21000n;
const RULES_VALID_DAYS = 180;

const TARGETS = [
  { protocolId: 'uniswap', contract: 'Uniswap V2 Router02', versionTag: 'uniswap-v2', address: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D' },
  { protocolId: 'uniswap', contract: 'Uniswap V3 SwapRouter', versionTag: 'uniswap-v3', address: '0xE592427A0AEce92De3Edee1F18E0157C05861564' },
  { protocolId: 'uniswap', contract: 'Uniswap V3 SwapRouter02', versionTag: 'uniswap-v2-v3', address: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45' },
  { protocolId: 'uniswap', contract: 'Uniswap Universal Router', versionTag: 'uniswap-universal-v1.2', address: '0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD' },
  { protocolId: 'uniswap', contract: 'Uniswap Universal Router V4', versionTag: 'uniswap-universal-v4', address: '0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af' },
  { protocolId: 'uniswap', contract: 'Uniswap V3 Positions NFT', versionTag: 'uniswap-v3', address: '0xC36442b4a4522E871399CD717aBDD847Ab11FE88' },
  { protocolId: 'uniswap', contract: 'Permit2', versionTag: 'uniswap-permit2', address: '0x000000000022D473030F116dDEE9F6B43aC78BA3' },
  { protocolId: 'aave', contract: 'Aave V3 Ethereum Pool', versionTag: 'aave-v3', address: '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2' },
  { protocolId: 'sushi', contract: 'SushiSwap V2 Router02', versionTag: 'sushi-v2', address: '0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F' },
  { protocolId: '1inch', contract: '1inch Aggregation Router V6', versionTag: '1inch-v6', address: '0x111111125421cA6dc452d289314280a0f8842A65' },
  { protocolId: 'curve', contract: 'Curve 3pool', versionTag: 'curve-stableswap', address: '0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7' },
  { protocolId: 'balancer', contract: 'Balancer V2 Vault', versionTag: 'balancer-v2', address: '0xBA12222222228d8Ba445958a75a0704d566BF2C8' },
  { protocolId: 'compound', contract: 'Compound V3 cUSDCv3', versionTag: 'compound-v3', address: '0xc3d688B66703497DAA19211EEdff47f25384cdc3' },
  { protocolId: 'lido', contract: 'Lido stETH', versionTag: 'lido-v2', address: '0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84' },
  { protocolId: 'weth', contract: 'WETH', versionTag: 'weth9', address: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2' },
  { protocolId: 'usdc', contract: 'USDC', versionTag: 'usdc-erc20', address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' },
  { protocolId: 'usdt', contract: 'USDT', versionTag: 'usdt-erc20', address: '0xdAC17F958D2ee523a2206206994597C13D831ec7' },
  { protocolId: 'dai', contract: 'DAI', versionTag: 'dai-erc20', address: '0x6B175474E89094C44Da98b954EedeAC495271d0F' },
  { protocolId: 'wbtc', contract: 'WBTC', versionTag: 'wbtc-erc20', address: '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599' },
  { protocolId: 'uni', contract: 'UNI', versionTag: 'uni-erc20', address: '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984' },
  { protocolId: 'link', contract: 'LINK', versionTag: 'link-erc20', address: '0x514910771AF9Ca656af840dff83E8264EcF986CA' },
  { protocolId: 'aave-token', contract: 'AAVE', versionTag: 'aave-erc20', address: '0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9' },
  { protocolId: 'mkr', contract: 'MKR', versionTag: 'mkr-erc20', address: '0x9f8F72aa9304c8B593d555F12eF6589cC3A579A2' },
];

// Names are for people reading the rules. Each one is matched to a selector by its hash, so a wrong name cannot attach.
const KNOWN_SIGNATURES = [
  'approve(address,uint256)', 'transfer(address,uint256)', 'transferFrom(address,address,uint256)', 'deposit()', 'withdraw(uint256)',
  'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)', 'multicall(bytes[])', 'multicall(uint256,bytes[])', 'multicall(bytes32,bytes[])',
  'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)', 'swapTokensForExactTokens(uint256,uint256,address[],address,uint256)',
  'swapExactETHForTokens(uint256,address[],address,uint256)', 'swapETHForExactTokens(uint256,address[],address,uint256)',
  'swapExactTokensForETH(uint256,uint256,address[],address,uint256)', 'swapTokensForExactETH(uint256,uint256,address[],address,uint256)',
  'swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)',
  'swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)',
  'swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)',
  'addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)', 'addLiquidityETH(address,uint256,uint256,uint256,address,uint256)',
  'removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)', 'removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)',
  'swapExactTokensForTokens(uint256,uint256,address[],address)', 'swapTokensForExactTokens(uint256,uint256,address[],address)',
  'exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))', 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))',
  'exactInput((bytes,address,uint256,uint256,uint256))', 'exactInput((bytes,address,uint256,uint256))',
  'exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))', 'exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))',
  'exactOutput((bytes,address,uint256,uint256,uint256))', 'exactOutput((bytes,address,uint256,uint256))',
  'execute(bytes,bytes[],uint256)', 'execute(bytes,bytes[])',
  'mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))', 'increaseLiquidity((uint256,uint256,uint256,uint256,uint256,uint256))',
  'decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))', 'collect((uint256,address,uint128,uint128))',
  'supply(address,uint256,address,uint16)', 'supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)',
  'withdraw(address,uint256,address)', 'borrow(address,uint256,uint256,uint16,address)', 'repay(address,uint256,uint256,address)',
  'repayWithPermit(address,uint256,uint256,address,uint256,uint8,bytes32,bytes32)', 'repayWithATokens(address,uint256,uint256)',
  'setUserUseReserveAsCollateral(address,bool)', 'liquidationCall(address,address,address,uint256,bool)', 'setUserEMode(uint8)',
  'flashLoanSimple(address,address,uint256,bytes,uint16)', 'flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)',
  'swap(address,(address,address,address,address,uint256,uint256,uint256),bytes)', 'unoswap(uint256,uint256,uint256,uint256)', 'unoswap2(uint256,uint256,uint256,uint256,uint256)',
  'ethUnoswap(uint256,uint256)', 'unoswapTo(uint256,uint256,uint256,uint256,uint256)',
  'swap((bytes32,uint8,address,address,uint256,bytes),(address,bool,address,bool),uint256,uint256)',
  'batchSwap(uint8,(bytes32,uint256,uint256,uint256,bytes)[],address[],(address,bool,address,bool),int256[],uint256)',
  'exchange(int128,int128,uint256,uint256)', 'add_liquidity(uint256[3],uint256)', 'remove_liquidity(uint256,uint256[3])', 'remove_liquidity_one_coin(uint256,int128,uint256)',
  'supply(address,uint256)', 'withdraw(address,uint256)', 'submit(address)',
  'increaseAllowance(address,uint256)',
  'mint(address,uint256)',
  'burn(uint256)',
  'transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)',
  'transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)',
  'permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)',
  'approve(address,address,uint160,uint48)',
  'lockdown((address,address)[])',
  'invalidateNonces(address,address,uint48)',
  'safeTransferFrom(address,address,uint256,bytes)',
];
const SIGNATURE_BY_SELECTOR = new Map(KNOWN_SIGNATURES.map((signature) => [id(FunctionFragment.from(`function ${signature}`).format('sighash')).slice(0, 10), signature]));
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

async function rpc(method, params) {
  for (let attempt = 0; ; attempt++) {
    try {
      const response = await fetch(RPC_URL, { method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'callscout-gas-rules/0.1' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(30_000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = await response.json();
      if (body.error) throw new Error(body.error.message);
      return body.result;
    } catch (error) {
      if (attempt >= 5) throw error;
      await sleep(1000 * (attempt + 1));
    }
  }
}

const percentile = (sorted, ratio) => sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * ratio) - 1)];

function ruleFor(target, selector, samples, codeVersion) {
  const gas = [...samples].sort((a, b) => a - b);
  const p99 = percentile(gas, 0.99);
  const raw = (BigInt(p99) * SAFETY_MARGIN_PERCENT) / 100n;
  const rounded = ((raw + ROUND_TO - 1n) / ROUND_TO) * ROUND_TO;
  return {
    chainId: 1,
    address: target.address,
    protocolId: target.protocolId,
    versionTag: target.versionTag,
    contract: target.contract,
    selector,
    signature: SIGNATURE_BY_SELECTOR.get(selector) ?? null,
    maxGas: (rounded < MIN_GAS ? MIN_GAS : rounded).toString(),
    codeVersion,
    observed: { samples: gas.length, p50: percentile(gas, 0.5), p95: percentile(gas, 0.95), p99, max: gas[gas.length - 1] },
  };
}

const byAddress = new Map(TARGETS.map((target) => [target.address.toLowerCase(), target]));
const samples = new Map();
const latest = Number(BigInt(await rpc('eth_blockNumber', [])));
const firstBlock = latest - WINDOW + 1;
const stride = Math.max(1, Math.floor(WINDOW / BLOCKS));
let nextBlock = firstBlock;
let done = 0;
let transactions = 0;
let failedBlocks = 0;

async function scanBlock(number) {
  const block = await rpc('eth_getBlockByNumber', [`0x${number.toString(16)}`, true]);
  const wanted = (block?.transactions ?? []).filter((tx) => byAddress.has(String(tx.to).toLowerCase()) && String(tx.input).length >= 10);
  for (const tx of wanted) {
    const key = `${String(tx.to).toLowerCase()}:${tx.input.slice(0, 10).toLowerCase()}`;
    if ((samples.get(key)?.length ?? 0) >= MAX_SAMPLES_PER_FUNCTION) continue;
    const receipt = await rpc('eth_getTransactionReceipt', [tx.hash]);
    if (receipt?.status !== '0x1') continue;
    samples.set(key, [...(samples.get(key) ?? []), Number(BigInt(receipt.gasUsed))]);
    transactions++;
  }
}

await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
  while (nextBlock <= latest) {
    const number = nextBlock;
    nextBlock += stride;
    try { await scanBlock(number); }
    catch { failedBlocks++; }
    if (++done % 500 === 0) process.stdout.write(`${done}/${BLOCKS} blocks, ${transactions} transactions\n`);
  }
}));

const rules = [];
for (const target of TARGETS) {
  const prefix = `${target.address.toLowerCase()}:`;
  // A function whose cost varies this much bundles variable work, so one number would mean little.
  const steady = (gas) => { const sorted = [...gas].sort((a, b) => a - b); return percentile(sorted, 0.99) <= percentile(sorted, 0.5) * MAX_SPREAD; };
  const eligible = [...samples].filter(([key, gas]) => key.startsWith(prefix) && gas.length >= MIN_SAMPLES && steady(gas));
  const codeVersion = await readCodeVersion(rpc, target.address);
  for (const [key, gas] of eligible) rules.push(ruleFor(target, key.slice(prefix.length), gas, codeVersion));
  process.stdout.write(`${target.contract}: ${eligible.length} functions, implementation ${codeVersion.implementation?.address ?? 'none'}\n`);
}
rules.sort((a, b) => a.protocolId.localeCompare(b.protocolId) || a.contract.localeCompare(b.contract) || a.selector.localeCompare(b.selector));

const now = new Date();
const document = {
  version: 1,
  rulesVersion: now.toISOString().slice(0, 10),
  validUntil: new Date(now.getTime() + RULES_VALID_DAYS * 86_400_000).toISOString(),
  generatedAt: now.toISOString(),
  source: `Successful Ethereum mainnet transactions sent directly to each contract, sampled every ${stride} blocks from ${firstBlock} to ${latest}`,
  transactionsMeasured: transactions,
  blocksFailed: failedBlocks,
  method: `maxGas is the 99th percentile of observed gas used, plus ${SAFETY_MARGIN_PERCENT - 100n}%, rounded up to the next ${ROUND_TO}. Functions with fewer than ${MIN_SAMPLES} samples are left out, and so are functions whose 99th percentile is more than ${MAX_SPREAD} times their median, because they bundle variable work and one number would mean little. A policy must set its own limit for those. Each rule pins the code it was measured on. Once that code changes or the set passes validUntil, the rule stops denying and the policy's overall gas cap applies.`,
  rules,
};
fs.writeFileSync(OUTPUT, `${JSON.stringify(document, null, 2)}\n`);
process.stdout.write(`Wrote ${rules.length} rules from ${transactions} transactions (${failedBlocks} blocks failed).\n`);
