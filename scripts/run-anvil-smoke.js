import { WalletPolicyGateway } from '../src/wallet-policy-gateway.js';

const runtime = new WalletPolicyGateway();

async function run(prompt, scenario) {
  const created = runtime.createRun(prompt, { scenario });
  return runtime.waitForRun(created.id);
}

try {
  const environment = await runtime.start();
  const runs = [];
  runs.push(await run('Swap 100 dUSD for dETH with at least 190 dETH out.', 'safe'));
  runs.push(await run('Swap 100 dUSD for dETH with at least 190 dETH out.', 'exploiter'));
  runs.push(await run('Swap 100 dUSD for dETH with at least 190 dETH out.', 'block-limit'));
  runs.push(await run('Swap 100 dUSD for dETH with at least 190 dETH out.', 'compromised'));
  runs.push(await run('Swap 100 dUSD for dETH with at least 190 dETH out.', 'hidden-call'));
  runs.push(await run('Swap 100 dUSD for dETH with at least 190 dETH out.', 'slippage'));
  // The block-limit run must keep both attempts: the first mined, the second denied.
  const blockLimit = runs.find((entry) => entry.scenario === 'block-limit');
  const [first, second] = blockLimit.attempts ?? [];
  if (!blockLimit.transactionHash || !blockLimit.chainReceipt || first?.decision !== 'allow' || second?.decision !== 'deny' || second?.transactionHash) {
    throw new Error('The block-limit run did not record a mined first swap and a denied second swap.');
  }
  process.stdout.write(`${JSON.stringify({
    environment,
    runs: runs.map((entry) => ({
      id: entry.id,
      scenario: entry.scenario,
      decision: entry.decision,
      transactionHash: entry.transactionHash,
      attempts: entry.attempts?.map((attempt) => ({ label: attempt.label, decision: attempt.decision, transactionHash: attempt.transactionHash })),
      verification: entry.verification?.status ?? null,
      eventCount: entry.events.length,
      failedChecks: entry.receipt?.checks.filter((check) => check.status === 'deny') ?? [],
      simulation: entry.receipt?.simulation ?? null,
    })),
  }, null, 2)}\n`);
} finally {
  await runtime.stop();
}
