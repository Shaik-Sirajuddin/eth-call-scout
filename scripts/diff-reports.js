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
const rb = summarizeRisk(base.findings);
const rh = summarizeRisk(head.findings);
const list = (items, render) => items.length ? items.slice(0, 30).map((item) => `- ${render(item)}`).join('\n') + (items.length > 30 ? `\n- …and ${items.length - 30} more` : '') : '- None';
const inline = (value) => `\`${String(value).replaceAll('`', '\\`')}\``;
const riskDelta = rh.score - rb.score;
const status = rh.blacklisted > 0 || rh.band === 'high'
  ? '⛔ BLOCKED · BLACKLISTED / HIGH RISK'
  : rh.band === 'mid' || riskDelta > 0 || rh.unknown > rb.unknown || rh.unresolved > rb.unresolved
    ? '🟠 MAINTAINER REVIEW REQUIRED'
    : '✅ READY TO APPROVE';
const summary = parsedAdded.length || parsedRemoved.length || protocolsAdded.length || protocolsRemoved.length || signaturesAdded.length || signaturesRemoved.length
  ? `Added ${parsedAdded.length} parsed call site(s), removed ${parsedRemoved.length}; ${protocolsAdded.length} protocol(s) added and ${protocolsRemoved.length} removed; ${signaturesAdded.length} function name/signature(s) added and ${signaturesRemoved.length} removed.`
  : 'No parsed calls, protocols, or function signatures changed in the configured scan paths.';
const markdown = `## Secu scan diff\n\n## **Risk score: ${rh.score}/100 · ${rh.band.toUpperCase()}**\n\n**${status}**\n\nBase: ${rb.score}/100 · ${rb.band.toUpperCase()} · change: ${riskDelta > 0 ? '+' : ''}${riskDelta}\n\n${rh.blacklisted} blacklisted · ${rh.known} known · ${rh.unknown} unknown · ${rh.unresolved} unresolved\n\n### Summary\n\n${summary}\n\nStatic source analysis only; calls are not confirmed on-chain transactions.\n\n### Parsed transactions added\n\n${list(parsedAdded, (f) => `${inline(f.functionName ?? f.rpcMethod ?? 'Raw call')} at ${inline(relFile(f.file))} · ${inline(f.address ?? f.transaction?.to ?? 'unresolved target')} · ${inline(f.library)}`)}\n\n### Parsed transactions removed\n\n${list(parsedRemoved, (f) => `${inline(f.functionName ?? f.rpcMethod ?? 'Raw call')} at ${inline(relFile(f.file))} · ${inline(f.address ?? f.transaction?.to ?? 'unresolved target')} · ${inline(f.library)}`)}\n\n### Protocols added\n\n${list(protocolsAdded, (p) => `${inline(p.name)}${p.address ? ` · ${inline(p.address)}` : ''}`)}\n\n### Protocols removed\n\n${list(protocolsRemoved, (p) => `${inline(p.name)}${p.address ? ` · ${inline(p.address)}` : ''}`)}\n\n### Function signatures added\n\n${list(signaturesAdded, (s) => `${inline(s.signature)} · ${inline(s.protocol)}`)}\n\n### Function signatures removed\n\n${list(signaturesRemoved, (s) => `${inline(s.signature)} · ${inline(s.protocol)}`)}\n`;
fs.mkdirSync(path.dirname(path.resolve(outputFile)), { recursive: true });
fs.writeFileSync(outputFile, markdown, 'utf8');
