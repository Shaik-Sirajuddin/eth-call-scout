import fs from 'node:fs';
import path from 'node:path';
import { collectProjectFiles } from './project.js';
import { scanFiles } from './scanner.js';
import { renderReport } from './report.js';
import { decodeFindings } from './decode.js';
import { applyRuleset, enrichFindings, loadRegistry, searchRegistry, syncRegistry } from './registry.js';

const HELP = `eth-call-scout — find Ethereum calls in JavaScript and TypeScript\n\nUsage:\n  eth-call-scout <file-or-directory...> [options]\n  eth-call-scout registry <sync|list|search> ...\n\nOptions:\n  -o, --out <file>      Write the interactive HTML review report (default: eth-call-report.html)\n      --json <file>     Also write machine-readable findings\n      --decode           Look up verified ABIs and decode raw calldata\n      --chain-id <id>    EVM chain ID for ABI lookups (default: 1)\n      --ruleset <file>  Apply ruleset exported from ruleset.html\n      --no-html          Skip HTML output\n  -h, --help            Show this help\n\nScans .js, .jsx, .mjs, .cjs, .ts, .tsx, .mts, and .cts files.\nFollows transitive JS/TS imports from file entry points, including installed packages.
Directory scans skip common generated and dependency folders; declaration files are excluded.\n`;

const REGISTRY_HELP = `Registry commands:\n  eth-call-scout registry sync [all|tokens|protocols|volume|contracts]\n  eth-call-scout registry list [tokens|protocols|contracts|trackers|sources]\n  eth-call-scout registry search <query>\n\nLive sources are cached locally under .cache/eth-call-scout/registry.json.\n`;

async function runRegistry(args) {
  const action = args[0];
  if (!action || action === '--help' || action === '-h') { process.stdout.write(REGISTRY_HELP); return; }
  if (action === 'sync') {
    const kind = args[1] ?? 'all';
    const { registry, failures } = await syncRegistry({ kind });
    process.stdout.write(`Registry synchronized (${kind}): ${registry.tokens.length} tokens, ${registry.protocols.length} protocols, ${registry.contracts.length} contract addresses, ${registry.liveVolume.length} Ethereum DEX volume records.\nCache: ${registry.cachePath}\n`);
    for (const failure of failures) process.stderr.write(`Warning: ${failure}\n`);
    return;
  }
  const registry = await loadRegistry();
  if (action === 'list') {
    const key = args[1] ?? 'protocols';
    const list = key === 'tokens' ? registry.tokens : key === 'protocols' ? registry.protocols : key === 'contracts' ? registry.contracts : key === 'trackers' ? registry.volumeTrackers : key === 'sources' ? registry.sources : null;
    if (!list) throw new Error(`Unknown registry list: ${key}`);
    process.stdout.write(`${JSON.stringify(list, null, 2)}\n`); return;
  }
  if (action === 'search') {
    const query = args.slice(1).join(' ').trim();
    if (!query) throw new Error('Provide a registry search query');
    process.stdout.write(`${JSON.stringify(searchRegistry(registry, query), null, 2)}\n`); return;
  }
  throw new Error(`Unknown registry command: ${action}\n${REGISTRY_HELP}`);
}

export async function runCli(argv) {
  try {
    if (argv[0] === 'registry') { runRegistry(argv.slice(1)).catch((error) => { process.stderr.write(`eth-call-scout: ${error.message}\n`); process.exitCode = 1; }); return; }
    const paths = [];
    let html = 'eth-call-report.html';
    let json = null;
    let rulesetPath = null;
    let noHtml = false;
    let decode = false;
    let chainId = 1;
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '-h' || arg === '--help') { process.stdout.write(HELP); return; }
      if (arg === '-o' || arg === '--out') { html = argv[++i]; if (!html) throw new Error(`${arg} requires a path`); }
      else if (arg === '--json') { json = argv[++i]; if (!json) throw new Error('--json requires a path'); }
      else if (arg === '--no-html') noHtml = true;
      else if (arg === '--decode') decode = true;
      else if (arg === '--chain-id') { chainId = Number(argv[++i]); if (!Number.isInteger(chainId) || chainId < 1) throw new Error('--chain-id requires a positive integer'); }
      else if (arg === '--ruleset') { rulesetPath = argv[++i]; if (!rulesetPath) throw new Error('--ruleset requires a path'); }
      else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
      else paths.push(arg);
    }
    if (!paths.length) { process.stdout.write(HELP); process.exitCode = 1; return; }
    const files = collectProjectFiles(paths);
    let findings = scanFiles(files);
    let registry = await loadRegistry();
    if (rulesetPath) {
      const ruleset = JSON.parse(fs.readFileSync(path.resolve(rulesetPath), 'utf8'));
      if (ruleset.version !== 1) throw new Error('Unsupported ruleset version (expected version 1)');
      registry = applyRuleset(registry, ruleset);
    }
    findings = enrichFindings(findings, registry);
    if (decode) findings = await decodeFindings(findings, { chainId });
    const reportData = { generatedAt: new Date().toISOString(), scannedFiles: files.length, findings };
    if (!noHtml) {
      fs.mkdirSync(path.dirname(path.resolve(html)), { recursive: true });
      fs.writeFileSync(html, renderReport(reportData), 'utf8');
    }
    if (json) {
      fs.mkdirSync(path.dirname(path.resolve(json)), { recursive: true });
      fs.writeFileSync(json, JSON.stringify(reportData, null, 2) + '\n', 'utf8');
    }
    const contracts = new Set(findings.map((x) => x.address).filter((x) => x && x.startsWith('0x')));
    process.stdout.write(`Scanned ${files.length} source file(s); found ${findings.length} Ethereum call(s) and ${contracts.size} literal contract address(es).${decode ? ' ABI/calldata decode enabled.' : ''}\n`);
    if (!noHtml) process.stdout.write(`HTML review: ${path.resolve(html)}\n`);
    if (json) process.stdout.write(`JSON findings: ${path.resolve(json)}\n`);
  } catch (error) {
    process.stderr.write(`eth-call-scout: ${error.message}\n`);
    process.exitCode = 1;
  }
}
