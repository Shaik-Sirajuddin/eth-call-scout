import { keccak256 } from 'ethers';

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const BYTES32 = /^0x[a-fA-F0-9]{64}$/;
const HEX_DATA = /^0x(?:[a-fA-F0-9]{2})*$/;
const HASH = /^0x[a-fA-F0-9]{64}$/;
const UINT = /^(?:0|[1-9][0-9]*)$/;

function object(value) { return Boolean(value) && typeof value === 'object' && !Array.isArray(value); }
function error(errors, code, path, message) { errors.push({ code, path, message }); }
function unknown(value, allowed, at, errors) {
  if (!object(value)) return;
  for (const key of Object.keys(value)) if (!allowed.has(key)) error(errors, 'unknown-field', `${at}.${key}`, 'Unknown monitor fields are rejected.');
}

export function validateMonitorConfig(config) {
  const errors = [];
  if (!object(config)) return { valid: false, errors: [{ code: 'invalid-config', path: '$', message: 'Monitor config must be an object.' }] };
  unknown(config, new Set(['version', 'chainId', 'stateTtlSeconds', 'rpcTimeoutMs', 'rpcQuorum', 'maxBlockSkew', 'sources', 'protocols']), '$', errors);
  if (config.version !== 1) error(errors, 'unsupported-version', '$.version', 'Monitor config version must be 1.');
  if (!Number.isSafeInteger(config.chainId) || config.chainId < 1) error(errors, 'invalid-chain', '$.chainId', 'chainId must be a positive safe integer.');
  if (!Number.isSafeInteger(config.stateTtlSeconds) || config.stateTtlSeconds < 30 || config.stateTtlSeconds > 3600) error(errors, 'invalid-ttl', '$.stateTtlSeconds', 'stateTtlSeconds must be between 30 and 3600.');
  if (config.rpcTimeoutMs != null && (!Number.isSafeInteger(config.rpcTimeoutMs) || config.rpcTimeoutMs < 500 || config.rpcTimeoutMs > 30000)) error(errors, 'invalid-timeout', '$.rpcTimeoutMs', 'rpcTimeoutMs must be between 500 and 30000.');
  if (!Array.isArray(config.sources) || config.sources.length < 2) error(errors, 'missing-sources', '$.sources', 'The secure monitor profile requires at least two independent RPC sources.');
  else {
    const ids = new Set();
    config.sources.forEach((source, index) => {
      const at = `$.sources[${index}]`;
      if (!object(source)) { error(errors, 'invalid-source', at, 'Source must be an object.'); return; }
      unknown(source, new Set(['id', 'env']), at, errors);
      if (typeof source.id !== 'string' || !source.id.trim()) error(errors, 'invalid-source-id', `${at}.id`, 'Source requires an ID.');
      if (ids.has(source.id)) error(errors, 'duplicate-source', at, 'Source IDs must be unique.');
      ids.add(source.id);
      if (typeof source.env !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(source.env)) error(errors, 'invalid-source-env', `${at}.env`, 'env must name an uppercase environment variable.');
    });
  }
  if (!Number.isSafeInteger(config.rpcQuorum) || config.rpcQuorum < 2 || (Array.isArray(config.sources) && config.rpcQuorum > config.sources.length)) error(errors, 'invalid-quorum', '$.rpcQuorum', 'The secure monitor profile requires rpcQuorum between 2 and the number of sources.');
  if (!Number.isSafeInteger(config.maxBlockSkew) || config.maxBlockSkew < 0 || config.maxBlockSkew > 100) error(errors, 'invalid-block-skew', '$.maxBlockSkew', 'maxBlockSkew must be an integer from 0 to 100.');
  if (!Array.isArray(config.protocols) || !config.protocols.length) error(errors, 'missing-protocols', '$.protocols', 'At least one protocol monitor is required.');
  else {
    const ids = new Set();
    config.protocols.forEach((protocol, protocolIndex) => {
      const at = `$.protocols[${protocolIndex}]`;
      if (!object(protocol)) { error(errors, 'invalid-protocol', at, 'Protocol monitor must be an object.'); return; }
      unknown(protocol, new Set(['id', 'contracts']), at, errors);
      if (typeof protocol.id !== 'string' || !protocol.id.trim()) error(errors, 'invalid-protocol-id', `${at}.id`, 'Protocol requires an ID.');
      if (ids.has(protocol.id)) error(errors, 'duplicate-protocol', at, 'Protocol IDs must be unique per config.');
      ids.add(protocol.id);
      if (!Array.isArray(protocol.contracts) || !protocol.contracts.length) { error(errors, 'missing-contracts', `${at}.contracts`, 'Protocol requires monitored contracts.'); return; }
      protocol.contracts.forEach((contract, contractIndex) => {
        const contractAt = `${at}.contracts[${contractIndex}]`;
        if (!object(contract)) { error(errors, 'invalid-contract', contractAt, 'Contract monitor must be an object.'); return; }
        unknown(contract, new Set(['address', 'codeHash', 'storage', 'calls']), contractAt, errors);
        if (!ADDRESS.test(String(contract.address ?? ''))) error(errors, 'invalid-address', `${contractAt}.address`, 'Expected a 20-byte contract address.');
        if (!HASH.test(String(contract.codeHash ?? ''))) error(errors, 'invalid-code-hash', `${contractAt}.codeHash`, 'codeHash must be a 32-byte Keccak-256 value.');
        if (contract.storage != null && !Array.isArray(contract.storage)) error(errors, 'invalid-storage-checks', `${contractAt}.storage`, 'storage must be an array.');
        else (contract.storage ?? []).forEach((check, checkIndex) => {
          const checkAt = `${contractAt}.storage[${checkIndex}]`;
          if (!object(check)) { error(errors, 'invalid-storage-check', checkAt, 'Storage check must be an object.'); return; }
          unknown(check, new Set(['slot', 'equals']), checkAt, errors);
          if (!BYTES32.test(String(check.slot ?? ''))) error(errors, 'invalid-storage-slot', `${checkAt}.slot`, 'slot must be a 32-byte hex value.');
          if (!BYTES32.test(String(check.equals ?? ''))) error(errors, 'invalid-storage-value', `${checkAt}.equals`, 'equals must be a 32-byte hex value.');
        });
        if (contract.calls != null && !Array.isArray(contract.calls)) error(errors, 'invalid-call-checks', `${contractAt}.calls`, 'calls must be an array.');
        else (contract.calls ?? []).forEach((check, checkIndex) => {
          const checkAt = `${contractAt}.calls[${checkIndex}]`;
          if (!object(check)) { error(errors, 'invalid-call-check', checkAt, 'Call check must be an object.'); return; }
          unknown(check, new Set(['to', 'data', 'operator', 'expected']), checkAt, errors);
          if (check.to != null && !ADDRESS.test(String(check.to))) error(errors, 'invalid-address', `${checkAt}.to`, 'to must be a 20-byte address.');
          if (!HEX_DATA.test(String(check.data ?? '')) || check.data === '0x') error(errors, 'invalid-call-data', `${checkAt}.data`, 'data must be non-empty even-length hex bytes.');
          if (!['equals', 'not-equals', 'uint-lte', 'uint-gte'].includes(check.operator)) error(errors, 'invalid-call-operator', `${checkAt}.operator`, 'Unsupported call operator.');
          if (['equals', 'not-equals'].includes(check.operator) && !HEX_DATA.test(String(check.expected ?? ''))) error(errors, 'invalid-call-expected', `${checkAt}.expected`, 'Hex comparison requires even-length hex expected data.');
          if (['uint-lte', 'uint-gte'].includes(check.operator) && !UINT.test(String(check.expected ?? ''))) error(errors, 'invalid-call-expected', `${checkAt}.expected`, 'Integer comparison requires an unsigned decimal string.');
        });
      });
    });
  }
  return { valid: errors.length === 0, errors };
}

function validateRpcUrl(value) {
  const url = new URL(value);
  const local = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !local) throw new Error('RPC endpoints must use HTTPS; HTTP is allowed only for loopback development.');
  if (url.username || url.password) throw new Error('RPC URLs must not contain credentials. Use environment-specific headers outside this collector.');
  return url;
}

async function rpc(url, method, params, { fetchImpl, timeoutMs }) {
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': 'callscout-monitor/0.1' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    redirect: 'error',
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const contentLength = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(contentLength) && contentLength > 1_000_000) throw new Error('RPC response exceeds 1 MB.');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 1_000_000) throw new Error('RPC response exceeds 1 MB.');
  const payload = JSON.parse(bytes.toString('utf8'));
  if (payload.error) throw new Error(`RPC ${payload.error.code ?? 'error'}: ${payload.error.message ?? 'unknown error'}`);
  if (!Object.hasOwn(payload, 'result')) throw new Error('RPC response has no result.');
  return payload.result;
}

function callMatches(result, check) {
  if (!HEX_DATA.test(String(result))) return false;
  if (check.operator === 'equals') return result.toLowerCase() === check.expected.toLowerCase();
  if (check.operator === 'not-equals') return result.toLowerCase() !== check.expected.toLowerCase();
  const value = BigInt(result);
  const expected = BigInt(check.expected);
  return check.operator === 'uint-lte' ? value <= expected : value >= expected;
}

async function inspectProtocol(protocol, source, url, config, fetchImpl) {
  const failures = [];
  const evidence = [];
  const blockHex = await rpc(url, 'eth_blockNumber', [], { fetchImpl, timeoutMs: config.rpcTimeoutMs ?? 8_000 });
  const blockNumber = BigInt(blockHex);
  for (const contract of protocol.contracts) {
    const code = await rpc(url, 'eth_getCode', [contract.address, 'latest'], { fetchImpl, timeoutMs: config.rpcTimeoutMs ?? 8_000 });
    const actualHash = HEX_DATA.test(String(code)) ? keccak256(code) : null;
    if (actualHash?.toLowerCase() !== contract.codeHash.toLowerCase()) failures.push(`code:${contract.address}`);
    else evidence.push(`code:${contract.address}`);
    for (const check of contract.storage ?? []) {
      const actual = await rpc(url, 'eth_getStorageAt', [contract.address, check.slot, 'latest'], { fetchImpl, timeoutMs: config.rpcTimeoutMs ?? 8_000 });
      if (String(actual).toLowerCase() !== check.equals.toLowerCase()) failures.push(`storage:${contract.address}:${check.slot}`);
      else evidence.push(`storage:${contract.address}:${check.slot}`);
    }
    for (const check of contract.calls ?? []) {
      const target = check.to ?? contract.address;
      const actual = await rpc(url, 'eth_call', [{ to: target, data: check.data }, 'latest'], { fetchImpl, timeoutMs: config.rpcTimeoutMs ?? 8_000 });
      if (!callMatches(actual, check)) failures.push(`call:${target}:${check.data.slice(0, 10)}`);
      else evidence.push(`call:${target}:${check.data.slice(0, 10)}`);
    }
  }
  return { sourceId: source.id, kind: failures.length ? 'mismatch' : 'pass', failures, evidence, blockNumber };
}

/** Collect deterministic on-chain invariant results from independent RPC sources. */
export async function collectProtocolState(config, { sequence, now = new Date(), rpcUrls = {}, fetchImpl = fetch } = {}) {
  const validation = validateMonitorConfig(config);
  if (!validation.valid) throw new Error(`Invalid monitor config:\n${validation.errors.map((entry) => `${entry.path}: ${entry.message}`).join('\n')}`);
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw new Error('sequence must be a non-negative safe integer');
  const sources = config.sources.map((source) => {
    const value = rpcUrls[source.id] ?? process.env[source.env];
    if (!value) throw new Error(`Missing RPC URL for ${source.id}; set ${source.env}.`);
    return { ...source, url: validateRpcUrl(value) };
  });
  if (new Set(sources.map((source) => source.url.href)).size !== sources.length) throw new Error('RPC sources must use distinct endpoint URLs.');
  const observedAt = new Date(now).toISOString();
  const protocols = await Promise.all(config.protocols.map(async (protocol) => {
    const results = await Promise.all(sources.map(async (source) => {
      try { return await inspectProtocol(protocol, source, source.url, config, fetchImpl); }
      catch (cause) { return { sourceId: source.id, kind: 'error', failures: [cause.message], evidence: [], blockNumber: null }; }
    }));
    const observedBlocks = results.map((result) => result.blockNumber).filter((value) => value != null);
    const highestBlock = observedBlocks.length ? observedBlocks.reduce((maximum, value) => value > maximum ? value : maximum) : null;
    for (const result of results) {
      if (result.blockNumber != null && highestBlock - result.blockNumber > BigInt(config.maxBlockSkew)) {
        result.kind = 'error';
        result.failures.push(`block-lag:${highestBlock - result.blockNumber}`);
      }
    }
    const passes = results.filter((result) => result.kind === 'pass');
    const mismatches = results.filter((result) => result.kind === 'mismatch');
    const conflictingQuorums = passes.length >= config.rpcQuorum && mismatches.length >= config.rpcQuorum;
    const status = conflictingQuorums ? 'degraded' : passes.length >= config.rpcQuorum ? 'operational' : mismatches.length >= config.rpcQuorum ? 'compromised' : 'degraded';
    const relevant = status === 'operational' ? passes : status === 'compromised' ? mismatches : results.filter((result) => result.blockNumber != null);
    const blocks = relevant.map((result) => result.blockNumber).filter((value) => value != null);
    const reason = status === 'operational'
      ? `${passes.length}/${sources.length} RPC sources satisfied every invariant.`
      : status === 'compromised'
        ? `${mismatches.length}/${sources.length} RPC sources observed deterministic invariant mismatches.`
        : `${conflictingQuorums ? 'Conflicting RPC quorums' : 'RPC quorum unavailable'}: ${passes.length} pass, ${mismatches.length} mismatch, ${results.length - passes.length - mismatches.length} error.`;
    const evidence = results.flatMap((result) => [
      `rpc:${result.sourceId}:${result.kind}`,
      ...result.evidence.map((entry) => `rpc:${result.sourceId}:${entry}:pass`),
      ...result.failures.map((entry) => `rpc:${result.sourceId}:${entry}:${result.kind}`),
    ]);
    return {
      id: protocol.id,
      chainId: config.chainId,
      status,
      observedAt,
      contracts: protocol.contracts.map((contract) => contract.address),
      ...(blocks.length ? { blockNumber: blocks.reduce((minimum, value) => value < minimum ? value : minimum).toString() } : {}),
      reason,
      evidence,
    };
  }));
  return {
    version: 1,
    sequence,
    issuedAt: observedAt,
    expiresAt: new Date(new Date(now).getTime() + config.stateTtlSeconds * 1000).toISOString(),
    protocols,
  };
}
