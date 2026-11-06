#!/usr/bin/env node
// The two-transaction demo, on real Ethereum contracts.
//   1. An honest swap: ETH to USDC through Uniswap, paid back to the wallet. Allowed.
//   2. The bot is compromised and sets the Binance bridge exploiter as the recipient. Denied.
//
// Modes:
//   npm run demo:swap                          Dry run on two real mainnet nodes. Nothing is signed or sent.
//   npm run demo:swap -- --fork                Mined on two local mainnet forks. No real money. Needs a recent Foundry.
//   npm run demo:swap -- --mainnet --confirm   Sends a REAL swap. Needs KEYBOUND_DEMO_PRIVATE_KEY and real ETH.
//
// Options:
//   --amount-eth 0.001     Size of the swap
//   --token USDC           Token to buy: USDC, USDT or DAI
//   --block-limit          Also show the per-block limit denying a second swap in the same block
//   --low-minimum          Also show a swap with a one-unit minimum output being denied
//   --max-slippage-bps 100 The most slippage the policy accepts
//   --wallet 0x...         Wallet to simulate in a dry run
//   --sim-a URL --sim-b URL   Trace-capable nodes (or CALLSCOUT_SIM_PRIMARY and CALLSCOUT_SIM_SECONDARY)
//   --fork-urls a,b        Use forks that are already running
//   --out DIR              Where logs go (default .keybound/demo)
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { formatEther, formatUnits, Interface, parseEther, toBeHex, Wallet } from 'ethers';
import { createAlertLog, formatAlert } from '../src/alerts.js';
import { ATTACKER_LIST } from '../src/attacker-list.js';
import { createAuditLog } from '../src/audit-log.js';
import { createBlockSpendTracker } from '../src/block-spend.js';
import { collectProtocolState } from '../src/protocol-monitor.js';
import { addProtocolStateSignature, signProtocolState } from '../src/protocol-state.js';
import { findSwapRule, listedSwapFees } from '../src/policy.js';
import { createMonitorFromPolicy, createPolicyFromRuleSet, GENERAL_RULE_SET } from '../src/rule-sets.js';
import { rpc } from '../src/transaction-simulator.js';
import { createGuardedProvider, WalletGuardError } from '../src/wallet-guard.js';

const EXPLOITER = '0x489A8756C18C0b8B24EC2a2b9FF3D4d447F79BEc';
const ROUTER = '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45';
const QUOTER = '0x61fFE014bA17989E743c5F6cB21bF9697530B21e';
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
// The bot asks for half of what the policy allows, so a small price move does not deny an honest swap.
const BOT_SLIPPAGE_DIVISOR = 2n;
const SWAP_GAS = 180_000n;
const DEFAULT_NODES = ['https://eth.drpc.org', 'https://ethereum.blinklabs.xyz'];
// A large public wallet that rarely moves, used only to simulate a dry run. Nothing is ever sent from it.
const DRY_RUN_WALLET = '0x40B38765696e3d5d8d9d834D8AaD4bB6e418E489';

const routerAbi = new Interface(['function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96)) payable returns (uint256)']);
const quoterAbi = new Interface(['function quoteExactInputSingle((address tokenIn,address tokenOut,uint256 amountIn,uint24 fee,uint160 sqrtPriceLimitX96)) returns (uint256 amountOut,uint160,uint32,uint256)']);
const erc20Abi = new Interface(['function balanceOf(address) view returns (uint256)']);

function parseArgs(argv) {
  const options = { amountEth: '0.001', token: 'USDC', out: path.join('.keybound', 'demo') };
  for (let index = 0; index < argv.length; index++) {
    const flag = argv[index];
    const next = () => { const value = argv[++index]; if (value == null) throw new Error(`${flag} requires a value`); return value; };
    if (flag === '--mainnet') options.mainnet = true;
    else if (flag === '--fork') options.fork = true;
    else if (flag === '--confirm') options.confirm = true;
    else if (flag === '--block-limit') options.blockLimit = true;
    else if (flag === '--low-minimum') options.lowMinimum = true;
    else if (flag === '--max-slippage-bps') options.maxSlippageBps = next();
    else if (flag === '--amount-eth') options.amountEth = next();
    else if (flag === '--token') options.token = next();
    else if (flag === '--wallet') options.wallet = next();
    else if (flag === '--sim-a') options.simA = next();
    else if (flag === '--sim-b') options.simB = next();
    else if (flag === '--fork-urls') { options.forkUrls = next().split(','); options.fork = true; } else if (flag === '--out') options.out = next();
    else throw new Error(`Unknown option ${flag}`);
  }
  if (options.mainnet && options.fork) throw new Error('Choose either --mainnet or --fork.');
  return options;
}

const say = (line = '') => process.stdout.write(`${line}\n`);
const heading = (line) => { say(); say(`=== ${line}`); };
const denied = (receipt) => receipt.checks.filter((check) => check.status === 'deny');

async function startForks() {
  const upstream = process.env.ETHEREUM_RPC_URL ?? DEFAULT_NODES[0];
  const latest = Number(BigInt(await rpc(new URL(upstream), 'eth_blockNumber', [])));
  const forkBlock = latest - 5;
  const children = [];
  const urls = [];
  for (const port of [8631, 8632]) {
    children.push(spawn(process.env.ANVIL_BIN || 'anvil', ['--fork-url', upstream, '--fork-block-number', String(forkBlock), '--port', String(port), '--silent', '--hardfork', 'prague'], { stdio: 'ignore' }));
    urls.push(`http://127.0.0.1:${port}`);
  }
  for (const url of urls) {
    let ready = false;
    for (let attempt = 0; attempt < 120 && !ready; attempt++) {
      try { await rpc(new URL(url), 'eth_chainId', []); ready = true; } catch { await new Promise((resolve) => { setTimeout(resolve, 500); }); }
    }
    if (!ready) throw new Error(`Local fork at ${url} did not start.`);
  }
  return { urls, stop: () => children.forEach((child) => child.kill()) };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const token = GENERAL_RULE_SET.assetLimits.find((asset) => asset.symbol === options.token && asset.group === 'tokens');
  if (!token || token.symbol === 'WETH') throw new Error('--token must be USDC, USDT or DAI.');
  const amount = parseEther(options.amountEth);
  const mode = options.mainnet ? 'mainnet' : options.fork ? 'fork' : 'dry-run';
  if (mode === 'mainnet' && !options.confirm) throw new Error('--mainnet sends a real transaction with real money. Add --confirm if you mean it.');

  let forks = null;
  if (mode === 'fork') forks = options.forkUrls ? { urls: options.forkUrls, stop: () => {} } : await startForks();
  const nodes = forks?.urls ?? [options.simA ?? process.env.CALLSCOUT_SIM_PRIMARY ?? DEFAULT_NODES[0], options.simB ?? process.env.CALLSCOUT_SIM_SECONDARY ?? DEFAULT_NODES[1]];
  const rpcUrls = { 'node-a': nodes[0], 'node-b': nodes[1] };
  const read = (method, params = []) => rpc(new URL(nodes[0]), method, params, { timeoutMs: 25_000 });

  try {
    let signer = null;
    let walletAddress;
    if (mode === 'mainnet') {
      if (!process.env.KEYBOUND_DEMO_PRIVATE_KEY) throw new Error('--mainnet needs KEYBOUND_DEMO_PRIVATE_KEY in your shell. Use a throwaway wallet holding only a small amount.');
      signer = new Wallet(process.env.KEYBOUND_DEMO_PRIVATE_KEY);
      walletAddress = signer.address;
    } else if (mode === 'fork') {
      signer = Wallet.createRandom();
      walletAddress = signer.address;
      for (const url of nodes) await rpc(new URL(url), 'anvil_setBalance', [walletAddress, toBeHex(parseEther('10'))]);
    } else {
      walletAddress = options.wallet ?? DRY_RUN_WALLET;
    }

    const keys = [crypto.generateKeyPairSync('ed25519'), crypto.generateKeyPairSync('ed25519')];
    const trustedKeys = keys.map((pair, index) => ({ id: `demo-signer-${index + 1}`, algorithm: 'ed25519', publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64') }));
    const sources = [{ id: 'node-a', env: 'CALLSCOUT_SIM_PRIMARY' }, { id: 'node-b', env: 'CALLSCOUT_SIM_SECONDARY' }];
    const policy = createPolicyFromRuleSet({
      profile: 'swapper',
      wallet: walletAddress,
      trustedKeys,
      sources,
      name: 'Demo: everyday swaps with low limits',
      maxSlippageBps: options.maxSlippageBps ?? null,
      validUntil: new Date(Date.now() + 86_400_000).toISOString(),
      // Room for one swap per block, so a second swap in the same block hits the limit.
      native: { maxValueWei: (amount * 2n).toString(), maxPerBlockWei: ((amount * 3n) / 2n).toString() },
    });

    fs.mkdirSync(options.out, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const alertFile = path.join(options.out, `alerts-${stamp}.jsonl`);
    const auditFile = path.join(options.out, `receipts-${stamp}.jsonl`);
    const alerts = createAlertLog(alertFile, { echo: false });
    const audit = createAuditLog(auditFile);
    const blockSpend = createBlockSpendTracker();

    say('WalletCordon demo: the agent proposes, deterministic rules decide, and only then may the wallet sign.');
    say(`Mode            ${mode === 'dry-run' ? 'dry run on real mainnet nodes (nothing is signed or sent)' : mode === 'fork' ? 'local mainnet forks (no real money)' : 'REAL MAINNET'}`);
    say(`Simulation      ${nodes.join(' and ')}`);
    say(`Wallet          ${walletAddress}`);
    say(`Rule set        ${GENERAL_RULE_SET.name}, swapper profile`);
    say(`Attacker list   ${ATTACKER_LIST.count} addresses, version ${ATTACKER_LIST.version}`);
    say(`Spend limits    ${formatEther(policy.invariants.maxNativeValueWei)} ETH per transaction, ${formatEther(policy.invariants.maxNativeOutflowPerBlockWei)} ETH per block`);
    say(`Max slippage    ${policy.invariants.maxSlippageBps} basis points, checked against a fresh quote`);

    const monitor = createMonitorFromPolicy(policy, { sources: [{ id: 'node-a', env: 'CALLSCOUT_RPC_PRIMARY' }, { id: 'node-b', env: 'CALLSCOUT_RPC_SECONDARY' }] });
    const now = new Date();
    const payload = await collectProtocolState(monitor, { sequence: 1, now, rpcUrls });
    const broken = payload.protocols.filter((protocol) => protocol.status !== 'operational');
    if (broken.length) say(`Protocol health problem: ${broken.map((protocol) => `${protocol.id} is ${protocol.status}: ${protocol.reason}`).join('; ')}`);
    let protocolState = { version: 1, payload, signatures: [] };
    keys.forEach((pair, index) => { protocolState = addProtocolStateSignature(protocolState, signProtocolState(payload, { keyId: `demo-signer-${index + 1}`, privateKey: pair.privateKey })); });
    say(`Protocol health ${payload.protocols.map((protocol) => `${protocol.id}: ${protocol.status}`).join(', ')}`);

    const forwarded = [];
    const walletProvider = {
      async request({ method, params }) {
        if (method === 'eth_chainId') return toBeHex(GENERAL_RULE_SET.chainId);
        if (method !== 'eth_sendTransaction') throw new Error(`The demo wallet does not expose ${method}.`);
        const tx = params[0];
        forwarded.push(tx);
        if (!signer) return null;
        const raw = await signer.signTransaction({ type: 2, chainId: GENERAL_RULE_SET.chainId, to: tx.to, data: tx.data, value: BigInt(tx.value), nonce: Number(BigInt(tx.nonce)), gasLimit: BigInt(tx.gas), maxFeePerGas: BigInt(tx.maxFeePerGas), maxPriorityFeePerGas: BigInt(tx.maxPriorityFeePerGas) });
        const hashes = await Promise.allSettled(nodes.map((url) => rpc(new URL(url), 'eth_sendRawTransaction', [raw], { timeoutMs: 25_000 })));
        const sent = hashes.find((result) => result.status === 'fulfilled');
        if (!sent) throw new Error(`No node accepted the transaction: ${hashes[0].reason?.message}`);
        return sent.value;
      },
    };
    const guard = createGuardedProvider({
      provider: walletProvider,
      policy,
      protocolState,
      simulationOptions: { rpcUrls },
      alerts,
      blockSpend,
      verification: signer ? { timeoutMs: 180_000, pollMs: 2_000 } : false,
      onDecision: (receipt) => audit.append(receipt),
      onVerification: (result) => audit.append(result),
    });

    // Use the best measured pool, the same way the guard does, so the honest swap gets a fair price.
    const swapRule = findSwapRule(policy, GENERAL_RULE_SET.chainId, ROUTER, routerAbi.getFunction('exactInputSingle').selector);
    let quote = 0n;
    let poolFee = null;
    for (const fee of listedSwapFees(swapRule, WETH, token.token)) {
      try {
        const [amountOut] = quoterAbi.decodeFunctionResult('quoteExactInputSingle', await read('eth_call', [{ to: QUOTER, data: quoterAbi.encodeFunctionData('quoteExactInputSingle', [{ tokenIn: WETH, tokenOut: token.token, amountIn: amount, fee, sqrtPriceLimitX96: 0n }]) }, 'latest']));
        if (amountOut > quote) { quote = amountOut; poolFee = fee; }
      } catch { /* This pool could not be priced. Another one may be. */ }
    }
    if (poolFee == null) throw new Error(`No measured pool could quote ETH to ${token.symbol}.`);
    const minimumOut = quote - (quote * BigInt(policy.invariants.maxSlippageBps)) / (10_000n * BOT_SLIPPAGE_DIVISOR);
    const block = await read('eth_getBlockByNumber', ['latest', false]);
    const baseFee = BigInt(block.baseFeePerGas);
    const tip = 1_000_000_000n;
    const maxFeePerGas = baseFee * 2n + tip;

    const proposal = async (recipient, minimum = minimumOut) => ({
      chainId: GENERAL_RULE_SET.chainId,
      from: walletAddress,
      to: ROUTER,
      data: routerAbi.encodeFunctionData('exactInputSingle', [{ tokenIn: WETH, tokenOut: token.token, fee: poolFee, recipient, amountIn: amount, amountOutMinimum: minimum, sqrtPriceLimitX96: 0n }]),
      value: toBeHex(amount),
      gas: toBeHex(SWAP_GAS),
      maxFeePerGas: toBeHex(maxFeePerGas),
      maxPriorityFeePerGas: toBeHex(tip),
      nonce: toBeHex(BigInt(await read('eth_getTransactionCount', [walletAddress, 'pending']))),
      type: '0x2',
    });
    const tokenBalance = async (owner) => BigInt(await read('eth_call', [{ to: token.token, data: erc20Abi.encodeFunctionData('balanceOf', [owner]) }, 'latest']));
    const showDenied = (error) => {
      if (!(error instanceof WalletGuardError)) throw error;
      say('Decision        DENIED. The wallet was never called.');
      for (const check of denied(error.receipt)) say(`  ${check.id.padEnd(26)} ${check.detail}`);
      for (const failure of new Set((error.receipt.simulation?.sources ?? []).flatMap((source) => source.failures ?? []))) say(`  ${'simulation'.padEnd(26)} ${failure}`);
    };

    heading('Transaction 1: honest swap, proceeds to the wallet');
    say(`Bot proposes    Swap ${options.amountEth} ETH for ${token.symbol}. Best fresh quote ${formatUnits(quote, token.decimals)} (fee tier ${poolFee}), minimum ${formatUnits(minimumOut, token.decimals)}.`);
    say(`Recipient       ${walletAddress} (the wallet)`);
    const before = await tokenBalance(walletAddress);
    let firstAllowed = false;
    try {
      const hash = await guard.request({ method: 'eth_sendTransaction', params: [await proposal(walletAddress)] });
      firstAllowed = true;
      say('Decision        ALLOWED. Two independent nodes agreed on the result.');
      if (hash) {
        say(`Transaction     ${hash}`);
        const verification = await guard.verification(hash);
        say(`On-chain check  ${verification?.status?.toUpperCase() ?? 'NOT RUN'}${verification?.blockNumber ? ` in block ${verification.blockNumber}, ${verification.gasUsed} gas` : ''}`);
        for (const check of verification?.checks ?? []) say(`  ${check.status === 'pass' ? 'ok  ' : check.status === 'unknown' ? '??  ' : 'FAIL'} ${check.id.padEnd(34)} ${check.detail}`);
        const after = await tokenBalance(walletAddress);
        say(`Wallet received ${formatUnits(after - before, token.decimals)} ${token.symbol}`);
      } else say('Not sent        This is a dry run, so the demo wallet did not sign.');
    } catch (error) { showDenied(error); }

    heading('Transaction 2: compromised bot sends the proceeds to the Binance bridge exploiter');
    const entry = ATTACKER_LIST.find(EXPLOITER);
    say(`Bot proposes    The same swap, with one change.`);
    say(`Recipient       ${EXPLOITER}`);
    say(`Attacker list   ${entry ? entry.label : 'NOT LISTED'}`);
    let secondDenied = false;
    try {
      const hash = await guard.request({ method: 'eth_sendTransaction', params: [await proposal(EXPLOITER)] });
      say(`Decision        ALLOWED, which is WRONG. Transaction: ${hash}`);
    } catch (error) { showDenied(error); secondDenied = true; }

    if (options.lowMinimum) {
      heading('Extra: compromised bot sets a one-unit minimum, so anyone can take the difference');
      say('Bot proposes    The same swap to the wallet, with a minimum output of 1 base unit.');
      try {
        const hash = await guard.request({ method: 'eth_sendTransaction', params: [await proposal(walletAddress, 1n)] });
        say(`Decision        ALLOWED, which is WRONG. Transaction: ${hash}`);
        process.exitCode = 1;
      } catch (error) { showDenied(error); }
    }

    if (options.blockLimit) {
      heading('Extra: a second honest swap in the same block');
      if (mode === 'fork') for (const url of nodes) await rpc(new URL(url), 'evm_setAutomine', [false]);
      try {
        const first = await guard.request({ method: 'eth_sendTransaction', params: [await proposal(walletAddress)] });
        say(`First swap      Forwarded${first ? `: ${first}` : ''}. Block limit now partly used.`);
        const second = await guard.request({ method: 'eth_sendTransaction', params: [await proposal(walletAddress)] });
        say(`Second swap     ALLOWED, which is WRONG: ${second}`);
      } catch (error) { showDenied(error); } finally {
        if (mode === 'fork') for (const url of nodes) { await rpc(new URL(url), 'evm_mine', []); await rpc(new URL(url), 'evm_setAutomine', [true]); }
      }
    }

    await guard.settled();
    heading('Alerts written to the log');
    const written = await alerts.read();
    if (!written.length) say('None.');
    for (const alert of written) say(formatAlert(alert));
    const auditStatus = await audit.verify();
    say();
    say(`Alert log       ${alertFile}`);
    say(`Decision log    ${auditFile} (${auditStatus.count} records, chain ${auditStatus.valid ? 'valid' : 'BROKEN'})`);
    say(`Read later with walletcordon alerts show ${alertFile}`);
    say();
    say(firstAllowed && secondDenied ? 'Demo result     PASS: the honest swap was allowed and the exploiter was stopped.' : 'Demo result     FAIL: see the decisions above.');
    if (!firstAllowed || !secondDenied) process.exitCode = 1;
  } finally {
    forks?.stop();
  }
}

main().catch((error) => { console.error(`\n${error.message}`); if (/unsupported tracer/i.test(error.message)) console.error('Your Anvil has no prestateTracer. Update Foundry with: foundryup'); process.exitCode = 1; });
