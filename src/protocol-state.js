import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { canonicalJson, sha256 } from './canonical.js';

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const STATUSES = new Set(['operational', 'degraded', 'paused', 'compromised', 'unknown']);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function addError(errors, code, path, message) { errors.push({ code, path, message }); }

function unknownFields(value, allowed, at, errors) {
  if (!isObject(value)) return;
  for (const key of Object.keys(value)) if (!allowed.has(key)) addError(errors, 'unknown-field', `${at}.${key}`, 'Unknown signed-state fields are rejected.');
}

function validatePayload(payload, errors) {
  if (!isObject(payload)) { addError(errors, 'invalid-payload', '$.payload', 'payload must be an object.'); return; }
  unknownFields(payload, new Set(['version', 'sequence', 'issuedAt', 'expiresAt', 'protocols']), '$.payload', errors);
  if (payload.version !== 1) addError(errors, 'unsupported-version', '$.payload.version', 'State payload version must be 1.');
  if (!Number.isSafeInteger(payload.sequence) || payload.sequence < 0) addError(errors, 'invalid-sequence', '$.payload.sequence', 'sequence must be a non-negative safe integer.');
  if (typeof payload.issuedAt !== 'string' || !Number.isFinite(Date.parse(payload.issuedAt))) addError(errors, 'invalid-issued-at', '$.payload.issuedAt', 'issuedAt must be an ISO-8601 timestamp.');
  if (typeof payload.expiresAt !== 'string' || !Number.isFinite(Date.parse(payload.expiresAt))) addError(errors, 'invalid-expires-at', '$.payload.expiresAt', 'expiresAt must be an ISO-8601 timestamp.');
  if (Number.isFinite(Date.parse(payload.issuedAt)) && Number.isFinite(Date.parse(payload.expiresAt)) && Date.parse(payload.expiresAt) <= Date.parse(payload.issuedAt)) addError(errors, 'invalid-state-window', '$.payload.expiresAt', 'expiresAt must be later than issuedAt.');
  if (!Array.isArray(payload.protocols) || !payload.protocols.length) { addError(errors, 'missing-protocols', '$.payload.protocols', 'payload requires protocol observations.'); return; }
  const identities = new Set();
  payload.protocols.forEach((protocol, index) => {
    const at = `$.payload.protocols[${index}]`;
    if (!isObject(protocol)) { addError(errors, 'invalid-protocol', at, 'Protocol observation must be an object.'); return; }
    unknownFields(protocol, new Set(['id', 'chainId', 'status', 'observedAt', 'contracts', 'blockNumber', 'reason', 'evidence']), at, errors);
    if (typeof protocol.id !== 'string' || !protocol.id.trim()) addError(errors, 'invalid-protocol-id', `${at}.id`, 'Protocol observation requires an ID.');
    if (!Number.isSafeInteger(protocol.chainId) || protocol.chainId < 1) addError(errors, 'invalid-chain', `${at}.chainId`, 'chainId must be a positive safe integer.');
    if (!STATUSES.has(protocol.status)) addError(errors, 'invalid-status', `${at}.status`, `status must be one of ${[...STATUSES].join(', ')}.`);
    if (typeof protocol.observedAt !== 'string' || !Number.isFinite(Date.parse(protocol.observedAt))) addError(errors, 'invalid-observed-at', `${at}.observedAt`, 'observedAt must be an ISO-8601 timestamp.');
    if (!Array.isArray(protocol.contracts) || !protocol.contracts.length) addError(errors, 'missing-contracts', `${at}.contracts`, 'Protocol observation requires exact contract addresses.');
    else protocol.contracts.forEach((address, addressIndex) => { if (!ADDRESS.test(String(address))) addError(errors, 'invalid-address', `${at}.contracts[${addressIndex}]`, 'Expected a 20-byte 0x address.'); });
    if (protocol.blockNumber != null && (typeof protocol.blockNumber !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(protocol.blockNumber))) addError(errors, 'invalid-block-number', `${at}.blockNumber`, 'blockNumber must be an unsigned decimal string.');
    if (protocol.evidence != null && (!Array.isArray(protocol.evidence) || protocol.evidence.some((item) => typeof item !== 'string'))) addError(errors, 'invalid-evidence', `${at}.evidence`, 'evidence must be an array of strings.');
    const identity = `${protocol.id}:${protocol.chainId}`;
    if (identities.has(identity)) addError(errors, 'duplicate-protocol', at, 'Protocol ID and chain pair must be unique.');
    identities.add(identity);
  });
}

export function validateProtocolState(bundle) {
  const errors = [];
  if (!isObject(bundle)) return { valid: false, errors: [{ code: 'invalid-state', path: '$', message: 'State bundle must be an object.' }] };
  unknownFields(bundle, new Set(['version', 'payload', 'signatures']), '$', errors);
  if (bundle.version !== 1) addError(errors, 'unsupported-version', '$.version', 'State bundle version must be 1.');
  validatePayload(bundle.payload, errors);
  if (!Array.isArray(bundle.signatures) || !bundle.signatures.length) addError(errors, 'missing-signatures', '$.signatures', 'State bundle requires at least one signature.');
  else {
    const keyIds = new Set();
    bundle.signatures.forEach((signature, index) => {
      const at = `$.signatures[${index}]`;
      if (!isObject(signature)) { addError(errors, 'invalid-signature', at, 'Signature must be an object.'); return; }
      unknownFields(signature, new Set(['keyId', 'algorithm', 'value']), at, errors);
      if (typeof signature.keyId !== 'string' || !signature.keyId.trim()) addError(errors, 'invalid-key-id', `${at}.keyId`, 'Signature requires a keyId.');
      if (signature.algorithm !== 'ed25519') addError(errors, 'invalid-algorithm', `${at}.algorithm`, 'Only Ed25519 signatures are supported.');
      if (typeof signature.value !== 'string' || signature.value.length < 40 || !BASE64.test(signature.value)) addError(errors, 'invalid-signature-value', `${at}.value`, 'Signature must be non-empty base64.');
      if (keyIds.has(signature.keyId)) addError(errors, 'duplicate-signature', at, 'A key may sign a bundle only once.');
      keyIds.add(signature.keyId);
    });
  }
  return { valid: errors.length === 0, errors };
}

function verifySignature(payload, signature, key) {
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(key.publicKey, 'base64'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(canonicalJson(payload)), publicKey, Buffer.from(signature.value, 'base64'));
  } catch { return false; }
}

export function signProtocolState(payload, { keyId, privateKey }) {
  const errors = [];
  validatePayload(payload, errors);
  if (errors.length) throw new Error(`Invalid protocol-state payload:\n${errors.map((error) => `${error.path}: ${error.message}`).join('\n')}`);
  if (typeof keyId !== 'string' || !keyId.trim()) throw new TypeError('keyId is required');
  const key = privateKey instanceof crypto.KeyObject ? privateKey : crypto.createPrivateKey(privateKey);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new TypeError('privateKey must be an Ed25519 private key');
  const value = crypto.sign(null, Buffer.from(canonicalJson(payload)), key).toString('base64');
  return { keyId, algorithm: 'ed25519', value };
}

export function addProtocolStateSignature(bundle, signature) {
  const signatures = (bundle?.signatures ?? []).filter((entry) => entry.keyId !== signature.keyId);
  return { version: 1, payload: bundle?.payload, signatures: [...signatures, signature] };
}

/** Verify authenticity, freshness, rollback floor, protocol status, chain, and exact contract binding. */
export function evaluateProtocolState(bundle, config, { protocolId, chainId, address, now = new Date(), minimumSequence = 0 } = {}) {
  const checks = [];
  const add = (id, ok, detail) => { checks.push({ id, status: ok ? 'pass' : 'deny', detail }); return ok; };
  if (!bundle) {
    add('state:present', false, 'A signed protocol-state bundle is required.');
    return { valid: false, authenticated: false, checks, summary: null };
  }
  add('state:present', true, 'A protocol-state bundle was supplied.');
  const validation = validateProtocolState(bundle);
  add('state:shape', validation.valid, validation.valid ? 'Signed-state structure is valid.' : validation.errors.map((error) => `${error.path}: ${error.message}`).join(' '));
  if (!validation.valid) return { valid: false, authenticated: false, checks, summary: null };

  const trustedKeys = new Map((config?.trustedKeys ?? []).map((key) => [key.id, key]));
  const verifiedSigners = [];
  for (const signature of bundle.signatures) {
    const key = trustedKeys.get(signature.keyId);
    if (key?.algorithm === 'ed25519' && verifySignature(bundle.payload, signature, key)) verifiedSigners.push(signature.keyId);
  }
  const threshold = config?.threshold ?? 0;
  const thresholdOk = verifiedSigners.length >= threshold && threshold > 0;
  add('state:signature-threshold', thresholdOk, `${verifiedSigners.length} trusted signature(s) verified; policy requires ${threshold}.`);

  const instant = new Date(now).getTime();
  const issuedAt = Date.parse(bundle.payload.issuedAt);
  const expiresAt = Date.parse(bundle.payload.expiresAt);
  const skewMs = (config?.maxClockSkewSeconds ?? 30) * 1000;
  const maxAgeMs = (config?.maxAgeSeconds ?? 0) * 1000;
  add('state:not-from-future', issuedAt <= instant + skewMs, `State issuedAt ${bundle.payload.issuedAt} must not exceed allowed clock skew.`);
  add('state:not-expired', expiresAt > instant, `State expiresAt ${bundle.payload.expiresAt} must be in the future.`);
  add('state:fresh', instant - issuedAt <= maxAgeMs, `State age must not exceed ${config?.maxAgeSeconds ?? 0} seconds.`);
  const sequenceFloor = Math.max(config?.minimumSequence ?? 0, minimumSequence ?? 0);
  add('state:no-rollback', bundle.payload.sequence >= sequenceFloor, `State sequence ${bundle.payload.sequence} must be at least ${sequenceFloor}.`);

  const protocol = bundle.payload.protocols.find((entry) => entry.id === protocolId && entry.chainId === chainId);
  add('state:protocol-bound', Boolean(protocol), `State must contain protocol ${protocolId} on chain ${chainId}.`);
  if (protocol) {
    add('state:contract-bound', protocol.contracts.some((entry) => entry.toLowerCase() === String(address).toLowerCase()), `State must bind exact target ${address}.`);
    add('state:operational', protocol.status === 'operational', `Protocol status is ${protocol.status}${protocol.reason ? `: ${protocol.reason}` : '.'}`);
    const observedAt = Date.parse(protocol.observedAt);
    add('state:observation-fresh', instant - observedAt <= maxAgeMs && observedAt <= instant + skewMs, `Protocol observation age must not exceed ${config?.maxAgeSeconds ?? 0} seconds.`);
  }

  const authenticated = validation.valid && thresholdOk;
  const summary = {
    hash: sha256(bundle.payload),
    sequence: bundle.payload.sequence,
    issuedAt: bundle.payload.issuedAt,
    expiresAt: bundle.payload.expiresAt,
    protocolId,
    status: protocol?.status ?? null,
    verifiedSigners,
    authenticated,
  };
  return { valid: checks.every((check) => check.status === 'pass'), authenticated, checks, summary };
}

async function readCache(cachePath) {
  if (!cachePath) return null;
  try { return JSON.parse(await fs.readFile(cachePath, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

async function writeCache(cachePath, value) {
  if (!cachePath) return;
  await fs.mkdir(path.dirname(cachePath), { recursive: true });
  const temporary = `${cachePath}.${process.pid}.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await fs.rename(temporary, cachePath);
}

/** Fetch untrusted state over HTTPS; signature/freshness verification occurs inside authorization. */
export function createLiveStateSource({ url, cachePath, fetchImpl = fetch, timeoutMs = 8_000, maxBytes = 1_000_000 } = {}) {
  const endpoint = new URL(url);
  if (endpoint.protocol !== 'https:') throw new Error('Live protocol state requires an HTTPS URL.');
  if (endpoint.username || endpoint.password) throw new Error('Live protocol-state URLs must not contain credentials.');
  return async function liveStateSource() {
    try {
      const response = await fetchImpl(endpoint, { headers: { accept: 'application/json', 'user-agent': 'keybound/0.1' }, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
      if (!response.ok) throw new Error(`Protocol-state endpoint returned HTTP ${response.status}.`);
      const length = Number(response.headers.get('content-length'));
      if (Number.isFinite(length) && length > maxBytes) throw new Error('Protocol-state response is too large.');
      const bytes = Buffer.from(await response.arrayBuffer());
      if (bytes.length > maxBytes) throw new Error('Protocol-state response is too large.');
      const bundle = JSON.parse(bytes.toString('utf8'));
      await writeCache(cachePath, bundle);
      return bundle;
    } catch (error) {
      const cached = await readCache(cachePath);
      if (cached) return cached;
      throw error;
    }
  };
}

/** Persist the highest authenticated sequence outside the agent's writable environment. */
export function createFileSequenceStore(file) {
  const target = path.resolve(file);
  return Object.freeze({
    async read() {
      try {
        const record = JSON.parse(await fs.readFile(target, 'utf8'));
        if (record.version !== 1 || !Number.isSafeInteger(record.sequence) || record.sequence < 0) throw new Error('Invalid protocol-state sequence store.');
        return record.sequence;
      } catch (error) {
        if (error.code === 'ENOENT') return 0;
        throw error;
      }
    },
    async write(sequence) {
      if (!Number.isSafeInteger(sequence) || sequence < 0) throw new Error('Protocol-state sequence must be a non-negative safe integer.');
      const current = await this.read();
      if (sequence < current) throw new Error(`Refusing to roll sequence back from ${current} to ${sequence}.`);
      await fs.mkdir(path.dirname(target), { recursive: true });
      const temporary = `${target}.${process.pid}.tmp`;
      await fs.writeFile(temporary, `${JSON.stringify({ version: 1, sequence })}\n`, { mode: 0o600 });
      await fs.rename(temporary, target);
    },
  });
}
