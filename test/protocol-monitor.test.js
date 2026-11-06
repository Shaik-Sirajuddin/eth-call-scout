import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { collectProtocolState, validateMonitorConfig } from '../src/protocol-monitor.js';

const config = JSON.parse(fs.readFileSync(new URL('../examples/protocol-monitor.demo.json', import.meta.url), 'utf8'));
const GOOD_CODE = '0x60016000';
const BAD_CODE = '0x60026000';
const ZERO_WORD = `0x${'0'.repeat(64)}`;
const ONE_WORD = `0x${'0'.repeat(63)}1`;
const NOW = new Date('2026-12-01T00:00:00.000Z');

function fakeRpc({ badSources = [], errorSources = [], lagSources = [] } = {}) {
  return async (url, options) => {
    const source = new URL(url).hostname.split('.')[0];
    if (errorSources.includes(source)) throw new Error('RPC offline');
    const request = JSON.parse(options.body);
    let result;
    if (request.method === 'eth_blockNumber') result = lagSources.includes(source) ? '0x16b2300' : source === 'primary' ? '0x16b23f0' : '0x16b23ef';
    else if (request.method === 'eth_getCode') result = badSources.includes(source) ? BAD_CODE : GOOD_CODE;
    else if (request.method === 'eth_getStorageAt') result = ZERO_WORD;
    else if (request.method === 'eth_call') result = ONE_WORD;
    else throw new Error(`Unexpected method ${request.method}`);
    const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }));
    return { ok: true, headers: { get: () => String(body.length) }, arrayBuffer: async () => body };
  };
}

const rpcUrls = { primary: 'https://primary.rpc.example', secondary: 'https://secondary.rpc.example' };

test('validates strict multi-source monitor configuration', () => {
  assert.deepEqual(validateMonitorConfig(config), { valid: true, errors: [] });
  const unknown = structuredClone(config);
  unknown.protocols[0].contracts[0].aiOpinion = 'safe';
  assert.equal(validateMonitorConfig(unknown).valid, false);
});

test('collects an operational payload only when RPC quorum satisfies all invariants', async () => {
  const payload = await collectProtocolState(config, { sequence: 42, now: NOW, rpcUrls, fetchImpl: fakeRpc() });
  assert.equal(payload.sequence, 42);
  assert.equal(payload.protocols[0].status, 'operational');
  assert.equal(payload.protocols[0].blockNumber, BigInt('0x16b23ef').toString());
  assert.match(payload.protocols[0].reason, /2\/2 RPC sources/);
});

test('marks quorum code-hash mismatch compromised', async () => {
  const payload = await collectProtocolState(config, { sequence: 43, now: NOW, rpcUrls, fetchImpl: fakeRpc({ badSources: ['primary', 'secondary'] }) });
  assert.equal(payload.protocols[0].status, 'compromised');
  assert.ok(payload.protocols[0].evidence.some((entry) => entry.includes(':code:') && entry.endsWith(':mismatch')));
});

test('marks state degraded when neither pass nor mismatch reaches quorum', async () => {
  const payload = await collectProtocolState(config, { sequence: 44, now: NOW, rpcUrls, fetchImpl: fakeRpc({ errorSources: ['secondary'] }) });
  assert.equal(payload.protocols[0].status, 'degraded');
  assert.match(payload.protocols[0].reason, /quorum unavailable/);
});

test('excludes RPC sources that lag beyond the configured block skew', async () => {
  const payload = await collectProtocolState(config, { sequence: 45, now: NOW, rpcUrls, fetchImpl: fakeRpc({ lagSources: ['secondary'] }) });
  assert.equal(payload.protocols[0].status, 'degraded');
  assert.ok(payload.protocols[0].evidence.some((entry) => entry.includes('block-lag')));
});

test('rejects insecure remote RPC URLs and missing environment bindings', async () => {
  await assert.rejects(collectProtocolState(config, { sequence: 1, now: NOW, rpcUrls: { primary: 'http://evil.example', secondary: rpcUrls.secondary }, fetchImpl: fakeRpc() }), /HTTPS/);
  await assert.rejects(collectProtocolState(config, { sequence: 1, now: NOW, rpcUrls: { primary: rpcUrls.primary, secondary: rpcUrls.primary }, fetchImpl: fakeRpc() }), /distinct/);
  await assert.rejects(collectProtocolState(config, { sequence: 1, now: NOW, rpcUrls: {}, fetchImpl: fakeRpc() }), /Missing RPC URL/);
});
