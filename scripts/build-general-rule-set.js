#!/usr/bin/env node
// Builds data/rule-sets/general.json by running each allowed call on a local mainnet fork and recording
// every contract it really touches. A hand-written list goes stale and blocks honest calls.
//
// Run with: npm run rules:general
// Needs Foundry's anvil, and a mainnet RPC in ETHEREUM_RPC_URL (default: a public node).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AbiCoder, Contract, Interface, JsonRpcProvider, keccak256, Wallet, id, parseEther, parseUnits } from 'ethers';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const OUTPUT = path.join(ROOT, 'data', 'rule-sets', 'general.json');
const UPSTREAM = process.env.ETHEREUM_RPC_URL ?? 'https://eth.drpc.org';
const PORT = 8611;
const LOCAL = `http://127.0.0.1:${PORT}`;
const MAX = (1n << 256n) - 1n;

const FACTORY = '0x1F98431c8aD98523631AE4a59f267346ea31F984';
const ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const AAVE_POOL = '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2';
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const TOKENS = [
  { symbol: 'USDC', address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', decimals: 6, protocolId: 'usdc', balanceSlot: 9, limit: '1000' },
  { symbol: 'USDT', address: '0xdAC17F958D2ee523a2206206994597C13D831ec7', decimals: 6, protocolId: 'usdt', balanceSlot: 2, limit: '1000' },
  { symbol: 'DAI', address: '0x6B175474E89094C44Da98b954EedeAC495271d0F', decimals: 18, protocolId: 'dai', balanceSlot: 2, limit: '1000' },
  { symbol: 'WETH', address: WETH, decimals: 18, protocolId: 'weth', balanceSlot: null, limit: '0.5' },
];

const erc20 = new Interface(['function approve(address,uint256)', 'function balanceOf(address) view returns (uint256)']);
const weth = new Interface(['function deposit() payable', 'function withdraw(uint256)']);
const factory = new Interface(['function getPool(address,address,uint24) view returns (address)']);
const router = new Interface(['function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96)) payable returns (uint256)']);
const aave = new Interface([
  'function supply(address,uint256,address,uint16)',
  'function withdraw(address,uint256,address) returns (uint256)',
  'function repay(address,uint256,uint256,address) returns (uint256)',
  'function borrow(address,uint256,uint256,uint16,address)',
  'function getReserveData(address) view returns (tuple(uint256 data) configuration, uint128, uint128, uint128, uint128, uint128, uint40, uint16, address aTokenAddress, address stableDebtTokenAddress, address variableDebtTokenAddress, address, uint128, uint128, uint128)',
]);

const lower = (address) => address.toLowerCase();

async function waitForNode(provider) {
  for (let attempt = 0; attempt < 60; attempt++) {
    try { await provider.getBlockNumber(); return; } catch { await new Promise((resolve) => { setTimeout(resolve, 500); }); }
  }
  throw new Error('anvil did not start.');
}

async function main() {
  const anvil = spawn(process.env.ANVIL_BIN || 'anvil', ['--fork-url', UPSTREAM, '--port', String(PORT), '--silent', '--hardfork', 'prague'], { stdio: 'ignore' });
  const provider = new JsonRpcProvider(LOCAL, undefined, { cacheTimeout: -1 });
  provider.pollingInterval = 100;
  try {
    await waitForNode(provider);
    const wallet = Wallet.createRandom().connect(provider);
    await provider.send('anvil_setBalance', [wallet.address, `0x${parseEther('1000').toString(16)}`]);
    for (const token of TOKENS) {
      if (token.balanceSlot == null) continue;
      const slot = keccak256(AbiCoder.defaultAbiCoder().encode(['address', 'uint256'], [wallet.address, token.balanceSlot]));
      await provider.send('anvil_setStorageAt', [token.address, slot, `0x${parseUnits('1000000', token.decimals).toString(16).padStart(64, '0')}`]);
    }

    const pools = new Map();
    const factoryContract = new Contract(FACTORY, factory, provider);
    const pairs = [[WETH, TOKENS[0].address], [WETH, TOKENS[1].address], [WETH, TOKENS[2].address], [TOKENS[0].address, TOKENS[1].address], [TOKENS[0].address, TOKENS[2].address]];
    for (const [a, b] of pairs) {
      for (const fee of [100, 500, 3000]) {
        const pool = await factoryContract.getPool(a, b, fee);
        if (pool !== '0x0000000000000000000000000000000000000000') pools.set(`${a}:${b}:${fee}`, { pool, a, b, fee });
      }
    }

    const reserves = {};
    const poolContract = new Contract(AAVE_POOL, aave, provider);
    for (const token of TOKENS) {
      const data = await poolContract.getReserveData(token.address);
      reserves[token.address] = { aToken: data.aTokenAddress, debtToken: data.variableDebtTokenAddress };
    }

    const touched = { wrap: new Set(), swap: new Set(), lending: new Set() };
    const callTypes = new Set();
    const gasSeen = [];
    const visit = (node, into) => {
      if (node.to) into.add(lower(node.to));
      if (node.type) callTypes.add(String(node.type).toUpperCase());
      for (const child of node.calls ?? []) visit(child, into);
    };
    let nonce = await provider.getTransactionCount(wallet.address);
    const send = async (group, label, to, data, value = 0n) => {
      const tx = await wallet.sendTransaction({ to, data, value, nonce: nonce++, gasLimit: 2_000_000n });
      const receipt = await tx.wait();
      if (receipt.status !== 1) throw new Error(`${label} reverted.`);
      if (group) {
        visit(await provider.send('debug_traceTransaction', [tx.hash, { tracer: 'callTracer' }]), touched[group]);
        gasSeen.push({ label, gasUsed: receipt.gasUsed.toString() });
        console.log(`${label.padEnd(36)} ${receipt.gasUsed} gas`);
      }
    };

    await send('wrap', 'wrap ETH', WETH, weth.encodeFunctionData('deposit'), parseEther('100'));
    await send('wrap', 'unwrap WETH', WETH, weth.encodeFunctionData('withdraw', [parseEther('1')]));
    for (const token of TOKENS) {
      await send(null, '', token.address, erc20.encodeFunctionData('approve', [ROUTER, 0n]));
      await send('swap', `approve ${token.symbol} for swaps`, token.address, erc20.encodeFunctionData('approve', [ROUTER, parseUnits('100000', token.decimals)]));
      await send(null, '', token.address, erc20.encodeFunctionData('approve', [AAVE_POOL, 0n]));
      await send('lending', `approve ${token.symbol} for lending`, token.address, erc20.encodeFunctionData('approve', [AAVE_POOL, parseUnits('100000', token.decimals)]));
    }

    const swapPools = [];
    for (const { pool, a, b, fee } of pools.values()) {
      const liquidity = await provider.call({ to: a, data: erc20.encodeFunctionData('balanceOf', [pool]) });
      const tokenA = TOKENS.find((token) => token.address === a);
      const tokenB = TOKENS.find((token) => token.address === b);
      if (BigInt(liquidity) < parseUnits(tokenA.symbol === 'WETH' ? '10' : '1000', tokenA.decimals)) { console.log(`skipped thin pool ${tokenA.symbol}/${tokenB.symbol} ${fee}`); continue; }
      const swap = (from, to, amount, value = 0n) => router.encodeFunctionData('exactInputSingle', [{ tokenIn: from.address, tokenOut: to.address, fee, recipient: wallet.address, amountIn: amount, amountOutMinimum: 1n, sqrtPriceLimitX96: 0n }]);
      const small = (token) => parseUnits(token.symbol === 'WETH' ? '0.01' : '10', token.decimals);
      try {
        if (a === WETH) await send('swap', `ETH to ${tokenB.symbol} (fee ${fee})`, ROUTER, swap(tokenA, tokenB, small(tokenA)), small(tokenA));
        await send('swap', `${tokenA.symbol} to ${tokenB.symbol} (fee ${fee})`, ROUTER, swap(tokenA, tokenB, small(tokenA)));
        await send('swap', `${tokenB.symbol} to ${tokenA.symbol} (fee ${fee})`, ROUTER, swap(tokenB, tokenA, small(tokenB)));
        swapPools.push({ pool, token0: a, token1: b, fee });
      } catch (error) { console.log(`skipped pool ${tokenA.symbol}/${tokenB.symbol} ${fee}: ${error.message.slice(0, 60)}`); }
    }

    for (const token of TOKENS) {
      const amount = parseUnits(token.symbol === 'WETH' ? '1' : '100', token.decimals);
      await send('lending', `supply ${token.symbol}`, AAVE_POOL, aave.encodeFunctionData('supply', [token.address, amount, wallet.address, 0]));
      await send('lending', `withdraw part of ${token.symbol}`, AAVE_POOL, aave.encodeFunctionData('withdraw', [token.address, amount / 2n, wallet.address]));
    }
    // Borrow here only to prove repay works. The rule set itself does not allow borrowing.
    const debtToken = TOKENS[0];
    await send(null, '', AAVE_POOL, aave.encodeFunctionData('borrow', [debtToken.address, parseUnits('10', debtToken.decimals), 2, 0, wallet.address]));
    await send('lending', 'repay USDC', AAVE_POOL, aave.encodeFunctionData('repay', [debtToken.address, MAX, 2, wallet.address]));

    const codeHash = async (address) => keccak256(await provider.getCode(address));
    const selector = (signature) => id(signature).slice(0, 10);
    const assetLimits = [];
    for (const token of TOKENS) {
      const units = parseUnits(token.limit, token.decimals).toString();
      assetLimits.push({
        token: token.address,
        symbol: token.symbol,
        group: 'tokens',
        decimals: token.decimals,
        maxOutflow: units,
        maxOutflowPerBlock: units,
        maxApproval: units,
        allowedRecipients: [...new Set([...swapPools.filter((entry) => entry.token0 === token.address || entry.token1 === token.address).map((entry) => entry.pool), reserves[token.address].aToken])],
        allowedSpenders: [ROUTER, AAVE_POOL],
      });
      const zero = '0x0000000000000000000000000000000000000000';
      // Withdrawing burns the deposit token and repaying burns the debt token, so each sends to the zero address.
      assetLimits.push({ token: reserves[token.address].aToken, symbol: `a${token.symbol}`, group: 'lending', decimals: token.decimals, maxOutflow: units, maxOutflowPerBlock: units, maxApproval: '0', allowedRecipients: [zero], allowedSpenders: [] });
      assetLimits.push({ token: reserves[token.address].debtToken, symbol: `variableDebt${token.symbol}`, group: 'lending', decimals: token.decimals, maxOutflow: units, maxOutflowPerBlock: units, maxApproval: '0', allowedRecipients: [zero], allowedSpenders: [] });
    }

    const approveRule = {
      signature: 'approve(address,uint256)',
      selector: selector('approve(address,uint256)'),
      constraints: [{ type: 'address-in', argument: 0, addresses: [ROUTER, AAVE_POOL] }, { type: 'uint-max', argument: 1, value: '$tokenLimit' }],
    };
    const tokenAddresses = TOKENS.map((token) => token.address);
    const contracts = [
      ...await Promise.all(TOKENS.map(async (token) => ({
        address: token.address,
        name: token.symbol,
        protocolId: token.protocolId,
        group: 'tokens',
        codeHash: await codeHash(token.address),
        maxNativeValueWei: token.address === WETH ? '$nativeLimit' : '0',
        methods: [
          approveRule,
          ...(token.address === WETH ? [
            { signature: 'deposit()', selector: selector('deposit()'), group: 'wrap', constraints: [] },
            { signature: 'withdraw(uint256)', selector: selector('withdraw(uint256)'), group: 'wrap', constraints: [{ type: 'uint-max', argument: 0, value: '$nativeLimit' }] },
          ] : []),
        ],
      }))),
      {
        address: ROUTER,
        name: 'Uniswap V3 SwapRouter02',
        protocolId: 'uniswap-v3',
        group: 'swap',
        codeHash: await codeHash(ROUTER),
        maxNativeValueWei: '$nativeLimit',
        methods: [{
          signature: 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))',
          selector: selector('exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))'),
          // Swap output must come back to the wallet, and a zero minimum output is refused.
          constraints: [
            { type: 'address-in', argument: 0, addresses: tokenAddresses },
            { type: 'address-in', argument: 1, addresses: tokenAddresses },
            { type: 'address-in', argument: 3, addresses: ['$wallet'] },
            { type: 'uint-min', argument: 5, value: '1' },
          ],
        }],
      },
      {
        address: AAVE_POOL,
        name: 'Aave V3 Ethereum Pool',
        protocolId: 'aave-v3',
        group: 'lending',
        codeHash: await codeHash(AAVE_POOL),
        maxNativeValueWei: '0',
        methods: [
          { signature: 'supply(address,uint256,address,uint16)', selector: selector('supply(address,uint256,address,uint16)'), constraints: [{ type: 'address-in', argument: 0, addresses: tokenAddresses }, { type: 'address-in', argument: 2, addresses: ['$wallet'] }] },
          { signature: 'withdraw(address,uint256,address)', selector: selector('withdraw(address,uint256,address)'), constraints: [{ type: 'address-in', argument: 0, addresses: tokenAddresses }, { type: 'address-in', argument: 2, addresses: ['$wallet'] }] },
          { signature: 'repay(address,uint256,uint256,address)', selector: selector('repay(address,uint256,uint256,address)'), constraints: [{ type: 'address-in', argument: 0, addresses: tokenAddresses }, { type: 'address-in', argument: 3, addresses: ['$wallet'] }] },
        ],
      },
    ];

    const listed = new Set([...contracts.map((contract) => lower(contract.address)), ...assetLimits.map((limit) => lower(limit.token))]);
    const internalTargets = Object.fromEntries(Object.entries(touched).map(([group, targets]) => [group, [...targets].filter((address) => !listed.has(address)).sort()]));

    const document = {
      version: 1,
      id: 'general',
      name: 'General user',
      description: 'Low limits for everyday use: wrap ETH, swap major tokens back to your own wallet, and lend on Aave. Borrowing, flash loans, transfers to other people, and everything else stay denied.',
      chainId: 1,
      measuredAt: new Date().toISOString(),
      forkBlock: await provider.getBlockNumber(),
      profiles: { general: ['wrap', 'swap', 'lending'], swapper: ['wrap', 'swap'], lender: ['wrap', 'lending'] },
      native: { maxValueWei: parseEther('0.5').toString(), maxPerBlockWei: parseEther('0.5').toString() },
      invariants: { maxGas: '700000', maxGasPriceWei: '100000000000', maxFeePerGasWei: '100000000000', maxPriorityFeePerGasWei: '5000000000' },
      simulation: { maxCallDepth: 16, maxInternalCalls: 128, maxStateAccounts: 64, maxStorageWrites: 128, allowedCallTypes: [...callTypes].filter((type) => ['CALL', 'STATICCALL', 'DELEGATECALL'].includes(type)).sort() },
      assetLimits,
      contracts,
      internalTargets,
      observedGas: gasSeen,
    };
    fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
    fs.writeFileSync(OUTPUT, `${JSON.stringify(document, null, 2)}\n`);
    console.log(`\nWrote ${path.relative(ROOT, OUTPUT)}: ${swapPools.length} pools, ${assetLimits.length} asset limits, internal targets ${Object.entries(internalTargets).map(([group, list]) => `${group}=${list.length}`).join(' ')}, fork block ${document.forkBlock}.`);
  } finally {
    anvil.kill();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
