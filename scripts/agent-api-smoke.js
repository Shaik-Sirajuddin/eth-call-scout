import { Interface, parseUnits } from 'ethers';

const originIndex = process.argv.indexOf('--origin');
const origin = new URL(originIndex >= 0 ? process.argv[originIndex + 1] : process.env.GATEWAY_ORIGIN ?? 'http://127.0.0.1:3000');
const loopback = origin.protocol === 'http:' && ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(origin.hostname);
if (origin.protocol !== 'https:' && !loopback) throw new Error('Gateway origin must use HTTPS; HTTP is allowed only for loopback development.');
if (origin.username || origin.password || origin.search || origin.hash) throw new Error('Gateway origin must not contain credentials, query parameters, or a fragment.');

async function request(path, options = {}) {
  const response = await fetch(new URL(path, origin), {
    ...options,
    headers: { accept: 'application/json', ...(options.headers ?? {}) },
    signal: AbortSignal.timeout(15_000),
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error ?? `Gateway returned HTTP ${response.status}.`);
  return { status: response.status, payload };
}

async function waitForRun(id, timeoutMs = 30_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const { payload } = await request(`/api/v1/agent/runs/${encodeURIComponent(id)}`);
    if (['complete', 'error'].includes(payload.status)) return payload;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`Timed out waiting for agent run ${id}.`);
}

const { payload: capabilities } = await request('/api/v1/agent/capabilities');
const action = capabilities.actions?.find((entry) => entry.name === 'swapExactTokensForTokens');
if (!action) throw new Error('Gateway does not expose the expected bounded swap capability.');
const router = new Interface(['function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address recipient)']);
const proposal = {
  chainId: capabilities.chainId,
  from: capabilities.wallet,
  to: action.target,
  data: router.encodeFunctionData('swapExactTokensForTokens', [parseUnits('100', 18), parseUnits('190', 18), capabilities.wallet]),
  value: '0',
  gas: '350000',
  maxFeePerGas: '10000000000',
  maxPriorityFeePerGas: '1000000000',
  nonce: capabilities.nextNonce,
  type: '2',
};
const requestId = `agent-smoke-${Date.now()}`;
const body = JSON.stringify({
  requestId,
  goal: 'Swap 100 dUSD for at least 190 dETH to my wallet',
  proposal,
});
const accepted = await request('/api/v1/agent/runs', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body,
});
if (accepted.status !== 202) throw new Error(`New agent run returned HTTP ${accepted.status}; expected 202.`);
const completed = await waitForRun(accepted.payload.id);
if (completed.status !== 'complete' || completed.decision !== 'allow') throw new Error(`Agent run failed closed with ${completed.status}/${completed.decision}.`);
if (!completed.transactionHash || completed.receipt?.simulation?.agreeingSources?.length !== 2) throw new Error('Allowed run lacks a transaction hash or two-source simulation consensus.');

const retry = await request('/api/v1/agent/runs', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body,
});
if (retry.status !== 200 || retry.payload.id !== completed.id) throw new Error('Idempotent retry did not return the original run.');

process.stdout.write(`${JSON.stringify({
  origin: origin.origin,
  requestId,
  runId: completed.id,
  decision: completed.decision,
  transactionHash: completed.transactionHash,
  simulationSources: completed.receipt.simulation.agreeingSources,
  idempotentRetry: retry.payload.id === completed.id,
  signerExposedToAgent: false,
}, null, 2)}\n`);
