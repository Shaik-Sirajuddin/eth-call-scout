import fs from 'node:fs';
import path from 'node:path';
import { summarizeRisk } from '../src/report.js';

const [baseFile, headFile, outputFile] = process.argv.slice(2);
if (!baseFile || !headFile || !outputFile) throw new Error('Usage: node scripts/diff-reports.js <base.json> <head.json> <output.md>');
const read = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const base = read(baseFile);
const head = read(headFile);
const calls = (report) => report.findings.filter((finding) => finding.kind !== 'parse error');
const relFile = (value = '') => {
  const normalized = String(value).replaceAll('\\', '/');
  const marker = normalized.lastIndexOf('/examples/');
  if (marker >= 0) return `examples/${normalized.slice(marker + 10)}`;
  const dependencies = normalized.lastIndexOf('/node_modules/');
  if (dependencies >= 0) return `node_modules/${normalized.slice(dependencies + 14)}`;
  return normalized.replace(/^.*\/(?:base|candidate)\//, '');
};
const canonical = (value) => JSON.stringify(value ?? null);
const protocolKey = (finding) => {
  const match = finding.registryMatch;
  return match?.protocolId ?? match?.id ?? match?.name ?? finding.address?.toLowerCase() ?? null;
};
const signature = (finding) => finding.decoded?.signature ?? finding.functionName ?? finding.rpcMethod ?? (finding.calldata?.slice(0, 10) || 'unresolved');
const interactionKey = (finding) => [relFile(finding.file), finding.function, (finding.address ?? finding.transaction?.to ?? '').toLowerCase(), signature(finding), finding.library, finding.kind, canonical(finding.parameters)].join('|');
const sets = (report) => {
  const parsed = new Map();
  const protocols = new Map();
  const signatures = new Map();
  for (const finding of calls(report)) {
    const key = interactionKey(finding);
    parsed.set(key, finding);
    const pKey = protocolKey(finding);
    if (pKey) protocols.set(pKey, { key: pKey, name: finding.registryMatch?.name ?? pKey, address: finding.address ?? null });
    const sig = signature(finding);
    if (sig && sig !== 'unresolved' && sig !== 'eth_call' && sig !== 'eth_sendTransaction') {
      const sKey = `${protocolKey(finding) ?? finding.address ?? 'unknown'}|${sig}`;
      signatures.set(sKey, { key: sKey, signature: sig, protocol: finding.registryMatch?.name ?? finding.address ?? 'Unmapped target' });
    }
  }
  return { parsed, protocols, signatures };
};
const before = sets(base), after = sets(head);
const difference = (a, b) => [...a].filter(([key]) => !b.has(key)).map(([, value]) => value);
const parsedAdded = difference(after.parsed, before.parsed);
const parsedRemoved = difference(before.parsed, after.parsed);
const protocolsAdded = difference(after.protocols, before.protocols);
const protocolsRemoved = difference(before.protocols, after.protocols);
const signaturesAdded = difference(after.signatures, before.signatures);
const signaturesRemoved = difference(before.signatures, after.signatures);
const risk = summarizeRisk(parsedAdded);
const list = (items, render) => items.slice(0, 30).map((item) => `- ${render(item)}`).join('\n') + (items.length > 30 ? `\n- …and ${items.length - 30} more` : '');
const inline = (value) => `\`${String(value).replaceAll('`', '\\`')}\``;
const status = parsedAdded.length === 0
  ? '✅ LOW RISK · NO NEW CALLS'
  : risk.blacklisted > 0 || risk.band === 'high'
    ? '⛔ BLACKLISTED / HIGH RISK · MAINTAINER REQUIRED'
    : risk.band === 'mid'
      ? '🟠 MAINTAINER REVIEW REQUIRED'
      : '✅ READY TO APPROVE';
const summary = parsedAdded.length || parsedRemoved.length || protocolsAdded.length || protocolsRemoved.length || signaturesAdded.length || signaturesRemoved.length
  ? `+${parsedAdded.length} calls · −${parsedRemoved.length} · +${protocolsAdded.length} protocols · +${signaturesAdded.length}/−${signaturesRemoved.length} functions.`
  : 'No parsed call, protocol, or function changes.';
const section = (title, items, render) => items.length ? `\n### ${title}\n\n${list(items, render)}\n` : '';
const markdown = `## Secu scan diff\n\n## **Risk score: ${risk.score}/100 · ${risk.band.toUpperCase()}**\n\n**${status}**\n\n${risk.blacklisted} blacklisted · ${risk.known} known · ${risk.unknown} unknown · ${risk.unresolved} unresolved\n\n**Diff:** ${summary}\n${section('Calls added', parsedAdded, (f) => `${inline(f.functionName ?? f.rpcMethod ?? 'Raw call')} at ${inline(relFile(f.file))} · ${inline(f.address ?? f.transaction?.to ?? 'unresolved target')} · ${inline(f.library)}`)}${section('Calls removed', parsedRemoved, (f) => `${inline(f.functionName ?? f.rpcMethod ?? 'Raw call')} at ${inline(relFile(f.file))} · ${inline(f.address ?? f.transaction?.to ?? 'unresolved target')} · ${inline(f.library)}`)}${section('Protocols added', protocolsAdded, (p) => `${inline(p.name)}${p.address ? ` · ${inline(p.address)}` : ''}`)}${section('Protocols removed', protocolsRemoved, (p) => `${inline(p.name)}${p.address ? ` · ${inline(p.address)}` : ''}`)}${section('Function signatures added', signaturesAdded, (s) => `${inline(s.signature)} · ${inline(s.protocol)}`)}${section('Function signatures removed', signaturesRemoved, (s) => `${inline(s.signature)} · ${inline(s.protocol)}`)}\n_Risk is scored from newly added parsed calls in this diff only. A zero-call diff scores 0/100; static analysis does not prove runtime behavior._\n`;
fs.mkdirSync(path.dirname(path.resolve(outputFile)), { recursive: true });
fs.writeFileSync(outputFile, markdown, 'utf8');
