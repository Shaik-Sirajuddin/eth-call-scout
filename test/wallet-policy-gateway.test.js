import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { WalletPolicyGateway } from '../src/wallet-policy-gateway.js';

async function temporaryRuntime(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'wallet-gateway-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

function storedRun(overrides = {}) {
  const now = '2026-11-06T00:00:00.000Z';
  return {
    id: 'run_persisted_001',
    createdAt: now,
    updatedAt: now,
    prompt: 'Swap within policy limits.',
    scenario: 'safe',
    source: 'agent-api',
    requestId: 'request-persisted-001',
    status: 'complete',
    decision: 'deny',
    agent: null,
    transaction: null,
    receipt: null,
    transactionHash: null,
    chainReceipt: null,
    events: [],
    ...overrides,
  };
}

test('persists completed run history and reloads it in a new gateway instance', async (t) => {
  const runtimeDirectory = await temporaryRuntime(t);
  const first = new WalletPolicyGateway({ runtimeDirectory });
  await first.persistRun(storedRun());

  const second = new WalletPolicyGateway({ runtimeDirectory });
  await second.loadRunHistory();

  assert.equal(second.listRuns().length, 1);
  assert.equal(second.getRun('run_persisted_001').requestId, 'request-persisted-001');
  assert.equal(second.getRun('run_persisted_001').status, 'complete');
  const mode = (await fs.stat(path.join(runtimeDirectory, 'runs', 'run_persisted_001.json'))).mode & 0o777;
  assert.equal(mode, 0o600);
});

test('recovers an interrupted queued or running record as a terminal error', async (t) => {
  const runtimeDirectory = await temporaryRuntime(t);
  const first = new WalletPolicyGateway({ runtimeDirectory });
  await first.persistRun(storedRun({ status: 'running', decision: null }));

  const second = new WalletPolicyGateway({ runtimeDirectory });
  await second.loadRunHistory();
  const recovered = second.getRun('run_persisted_001');

  assert.equal(recovered.status, 'error');
  assert.equal(recovered.decision, 'error');
  assert.equal(recovered.events.at(-1).title, 'Run interrupted before completion');
});

test('deduplicates agent retries by requestId before executing wallet work', async (t) => {
  const runtimeDirectory = await temporaryRuntime(t);
  const gateway = new WalletPolicyGateway({ runtimeDirectory });
  gateway.started = true;
  let executions = 0;
  gateway.executeRun = async (run) => {
    executions++;
    run.status = 'complete';
    run.decision = 'deny';
    await gateway.persistRun(run);
  };
  const request = {
    requestId: 'agent-request-0001',
    goal: 'Swap within policy limits.',
    proposal: {
      chainId: 31_337,
      from: '0x1111111111111111111111111111111111111111',
      to: '0x2222222222222222222222222222222222222222',
      data: '0x12345678',
      value: '0',
      gas: '100000',
      maxFeePerGas: '1000000000',
      maxPriorityFeePerGas: '100000000',
      nonce: '0',
      type: '2',
    },
  };

  const first = gateway.createAgentRun(request);
  const retry = gateway.createAgentRun(request);
  assert.equal(retry.id, first.id);
  assert.equal(gateway.listRuns().length, 1);

  const completed = await gateway.waitForRun(first.id);
  assert.equal(completed.status, 'complete');
  assert.equal(executions, 1);
  await gateway.stop();
});
