import fs from 'node:fs';
import path from 'node:path';
import { scanProject } from './rust-scanner.js';
import { renderReport } from './report.js';
import { decodeFindings } from './decode.js';
import { applyRuleset, enrichFindings, loadRegistry, searchRegistry, syncRegistry } from './registry.js';
import { auditPolicy, authorizeIntent, loadPolicy, sha256, validatePolicy } from './policy.js';
import { addProtocolStateSignature, evaluateProtocolState, signProtocolState } from './protocol-state.js';
import { collectProtocolState } from './protocol-monitor.js';
import { verifyAuditLog } from './audit-log.js';
import { ALERT_SEVERITIES, formatAlert, readAlerts } from './alerts.js';
import { DEFAULT_ATTACKER_LIST_URL, localAttackerListPath, updateLocalAttackerList } from './attacker-feed.js';
import { ATTACKER_DOCUMENT, ATTACKER_LIST } from './attacker-list.js';
import { createPolicyFromRuleSet, GENERAL_RULE_SET, ruleSetProfiles, toBaseUnits } from './rule-sets.js';
import { failedSimulation, finalizeSimulation, simulateTransaction } from './transaction-simulator.js';

const HELP = `Keybound — deterministic wallet authorization for AI agents\n\nUsage:\n  keybound authorize <intent.json|-> --policy <policy.json> [--state <bundle.json>] [--out <receipt.json>]\n  keybound policy <validate|audit> <policy.json>\n  keybound state <collect|sign|verify> ...\n  keybound audit verify <receipts.jsonl>\n  keybound scan <file-or-directory...> [scan options]\n  keybound registry <sync|list|search> ...\n\nThe agent may propose transactions, but executable policy and signed live protocol state decide\nwhether the exact request reaches the wallet. All unsupported mutation methods deny.\n\nScan options:\n  -o, --out <file>      Write the interactive monitoring report (default: eth-call-report.html)\n      --json <file>     Also write machine-readable findings\n      --decode          Look up verified ABIs and decode raw calldata\n      --chain-id <id>   EVM chain ID for ABI lookups (default: 1)\n      --ruleset <file>  Apply review terms exported from pr-review-ruleset.html\n      --no-html         Skip HTML output\n  -h, --help            Show this help\n\nThe static scanner is a monitoring feature, not the wallet authorization boundary.\n`;

const POLICY_HELP = `Keybound executable wallet policies:\n  keybound policy init --wallet <address> --state-key <id:base64> --state-key <id:base64> [--profile general|swapper|lender|payments] [--max-per-tx USDC=100] [--max-per-block USDC=100] [--block <address>] [--payee <address>] [--valid-days 90] [--out <policy.json>]\n  keybound policy profiles\n  keybound policy validate <policy.json>\n  keybound policy audit <policy.json>\n  keybound authorize <intent.json|-> --policy <policy.json> --state <bundle.json> [--out <receipt.json>]\n\nAuthorization is deterministic and fail-closed. A successful decision only covers the exact\ntransaction and state hashes in the receipt; the wallet guard must forward those same fields.\n`;

const REGISTRY_HELP = `Registry commands:\n  eth-call-scout registry sync [all|tokens|protocols|volume|contracts]\n  eth-call-scout registry list [tokens|protocols|contracts|trackers|sources]\n  eth-call-scout registry search <query>\n\nLive sources are cached locally under .cache/eth-call-scout/registry.json.\n`;

const STATE_HELP = `Keybound signed protocol state:\n  keybound state collect <monitor.json> --sequence <n> --out <payload.json>\n  keybound state sign <payload.json> --key <private-key.pem> --key-id <id> --out <bundle.json>\n      [--append <existing-bundle.json>]\n  keybound state verify <bundle.json> --policy <policy.json> --intent <intent.json>\n\nCollector RPC URLs are read from environment variables named in monitor config. Private keys\nshould live in an isolated signer or HSM outside the agent process.\n`;

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

async function readJsonInput(file) {
  if (file !== '-') return JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function writeJson(value, output) {
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  if (!output) { process.stdout.write(serialized); return; }
  const target = path.resolve(output);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, serialized, 'utf8');
  process.stdout.write(`${target}\n`);
}

/** Collect repeatable flags such as --state-key a --state-key b. */
function readFlags(args, known) {
  const flags = {};
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (!known.includes(name)) throw new Error(`Unknown option ${name}`);
    const value = args[++index];
    if (value == null) throw new Error(`${name} requires a value`);
    (flags[name] ??= []).push(value);
  }
  return flags;
}

function parseAmounts(entries = [], flag) {
  return entries.map((entry) => {
    const [symbol, amount] = entry.split('=');
    if (!symbol || !amount) throw new Error(`${flag} expects SYMBOL=amount, for example USDC=100.`);
    return [symbol.toUpperCase() === 'ETH' ? 'ETH' : symbol, amount];
  });
}

/** Build a ready policy from the default rule set. Users set limits in normal units, not base units. */
function runPolicyInit(args) {
  const flags = readFlags(args, ['--wallet', '--profile', '--state-key', '--max-per-tx', '--max-per-block', '--block', '--payee', '--valid-days', '--out']);
  if (!flags['--wallet']?.[0]) throw new Error('policy init requires --wallet <address>');
  const trustedKeys = (flags['--state-key'] ?? []).map((entry) => {
    const separator = entry.indexOf(':');
    if (separator < 1) throw new Error('--state-key expects id:base64PublicKey');
    return { id: entry.slice(0, separator), algorithm: 'ed25519', publicKey: entry.slice(separator + 1) };
  });
  if (trustedKeys.length < 2) throw new Error('policy init requires two --state-key id:base64PublicKey values.');
  const limits = {};
  const native = {};
  const decimalsOf = (symbol) => {
    const asset = GENERAL_RULE_SET.assetLimits.find((entry) => entry.symbol === symbol);
    if (!asset) throw new Error(`No limit can be set for ${symbol}. Known: ETH, ${GENERAL_RULE_SET.assetLimits.map((entry) => entry.symbol).join(', ')}.`);
    return asset.decimals;
  };
  for (const [symbol, amount] of parseAmounts(flags['--max-per-tx'], '--max-per-tx')) {
    if (symbol === 'ETH') native.maxValueWei = toBaseUnits(amount, 18);
    else { const units = toBaseUnits(amount, decimalsOf(symbol)); limits[symbol] = { ...limits[symbol], maxOutflow: units, maxApproval: units }; }
  }
  for (const [symbol, amount] of parseAmounts(flags['--max-per-block'], '--max-per-block')) {
    if (symbol === 'ETH') native.maxPerBlockWei = toBaseUnits(amount, 18);
    else limits[symbol] = { ...limits[symbol], maxOutflowPerBlock: toBaseUnits(amount, decimalsOf(symbol)) };
  }
  const days = Number(flags['--valid-days']?.[0] ?? 90);
  if (!Number.isFinite(days) || days <= 0) throw new Error('--valid-days must be a positive number.');
  const policy = createPolicyFromRuleSet({
    wallet: flags['--wallet'][0],
    profile: flags['--profile']?.[0] ?? 'general',
    trustedKeys,
    limits,
    native,
    payees: flags['--payee'] ?? [],
    blockedAddresses: flags['--block'] ?? [],
    validUntil: new Date(Date.now() + days * 86_400_000).toISOString(),
  });
  const validation = validatePolicy(policy);
  if (!validation.valid) throw new Error(`The rule set built an invalid policy: ${validation.errors.map((entry) => entry.message).join(' ')}`);
  writeJson(policy, flags['--out']?.[0]);
}

async function runAttackers(args) {
  const action = args[0];
  if (!action || action === '--help' || action === '-h') {
    process.stdout.write(`Keybound attacker list:\n  keybound attackers info\n  keybound attackers check <address>\n  keybound attackers update [--from <url>] [--out <file>]\n\nThe list is always on. Updates can only add addresses. Default source: ${DEFAULT_ATTACKER_LIST_URL}\n`);
    return;
  }
  if (action === 'info') {
    writeJson({ listVersion: ATTACKER_LIST.version, hash: ATTACKER_LIST.hash, count: ATTACKER_LIST.count, generatedAt: ATTACKER_DOCUMENT.generatedAt ?? null, localFile: localAttackerListPath(), sources: ATTACKER_DOCUMENT.sources ?? [] });
    return;
  }
  if (action === 'check') {
    if (!args[1]) throw new Error('Usage: keybound attackers check <address>');
    const match = ATTACKER_LIST.find(args[1]);
    writeJson({ address: args[1].toLowerCase(), listed: Boolean(match), label: match?.label ?? null, sources: match?.sources ?? [], reference: match?.reference ?? null, listVersion: ATTACKER_LIST.version });
    if (match) process.exitCode = 1;
    return;
  }
  if (action === 'update') {
    const flags = readFlags(args.slice(1), ['--from', '--out']);
    writeJson(await updateLocalAttackerList(ATTACKER_DOCUMENT, { url: flags['--from']?.[0] ?? DEFAULT_ATTACKER_LIST_URL, file: flags['--out']?.[0] ?? localAttackerListPath() }));
    return;
  }
  throw new Error(`Unknown attackers command: ${action}`);
}

async function runAlerts(args) {
  const action = args[0];
  if (!action || action === '--help' || action === '-h') {
    process.stdout.write('Keybound alerts:\n  keybound alerts show <alerts.jsonl> [--severity critical|warning|info]\n  keybound alerts verify <alerts.jsonl>\n');
    return;
  }
  const file = args[1];
  if (!file) throw new Error(`Usage: keybound alerts ${action} <alerts.jsonl>`);
  if (action === 'verify') {
    const result = await verifyAuditLog(path.resolve(file));
    writeJson(result);
    if (!result.valid) process.exitCode = 2;
    return;
  }
  if (action !== 'show') throw new Error(`Unknown alerts command: ${action}`);
  const severity = readFlags(args.slice(2), ['--severity'])['--severity']?.[0] ?? null;
  if (severity && !ALERT_SEVERITIES.includes(severity)) throw new Error(`--severity must be one of ${ALERT_SEVERITIES.join(', ')}`);
  const alerts = (await readAlerts(file)).filter((alert) => !severity || alert.severity === severity);
  if (!alerts.length) { process.stdout.write('No alerts.\n'); return; }
  for (const alert of alerts) process.stdout.write(`${formatAlert(alert)}\n`);
}

async function runPolicy(args) {
  const action = args[0];
  if (!action || action === '--help' || action === '-h') { process.stdout.write(POLICY_HELP); return; }
  if (action === 'init') { runPolicyInit(args.slice(1)); return; }
  if (action === 'profiles') { writeJson(ruleSetProfiles()); return; }
  const file = args[1];
  if (!file) throw new Error(`${action} requires a policy JSON file`);
  const policy = await readJsonInput(file);
  if (action === 'validate') {
    const validation = validatePolicy(policy);
    writeJson({ ...validation, policyHash: validation.valid ? sha256(policy) : null });
    if (!validation.valid) process.exitCode = 1;
    return;
  }
  if (action === 'audit') {
    const audit = auditPolicy(policy);
    writeJson(audit);
    if (!audit.valid || audit.findings.some((finding) => finding.severity === 'high' || finding.severity === 'error')) process.exitCode = 1;
    return;
  }
  throw new Error(`Unknown policy command: ${action}\n${POLICY_HELP}`);
}

async function runAuthorize(args) {
  if (!args.length || args[0] === '--help' || args[0] === '-h') { process.stdout.write(POLICY_HELP); return; }
  const intentPath = args[0];
  let policyPath = null;
  let statePath = null;
  let output = null;
  for (let index = 1; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--policy') { policyPath = args[++index]; if (!policyPath) throw new Error('--policy requires a path'); }
    else if (arg === '--state') { statePath = args[++index]; if (!statePath) throw new Error('--state requires a path'); }
    else if (arg === '--out') { output = args[++index]; if (!output) throw new Error('--out requires a path'); }
    else throw new Error(`Unknown authorize option: ${arg}`);
  }
  if (!policyPath) throw new Error('authorize requires --policy <policy.json>');
  const policy = loadPolicy(path.resolve(policyPath));
  const intent = await readJsonInput(intentPath);
  const protocolState = statePath ? await readJsonInput(statePath) : null;
  let receipt = authorizeIntent(policy, intent, { protocolState });
  if (receipt.decision !== 'deny') {
    try { receipt = finalizeSimulation(receipt, await simulateTransaction(policy, intent, { protocolState })); }
    catch (error) { receipt = failedSimulation(receipt, error); }
  }
  writeJson(receipt, output);
  if (receipt.decision !== 'allow') process.exitCode = 2;
}

async function runState(args) {
  const action = args[0];
  if (!action || action === '--help' || action === '-h') { process.stdout.write(STATE_HELP); return; }
  const input = args[1];
  if (!input) throw new Error(`${action} requires an input JSON file`);
  const options = {};
  for (let index = 2; index < args.length; index++) {
    const arg = args[index];
    if (!['--key', '--key-id', '--out', '--append', '--policy', '--intent', '--sequence'].includes(arg)) throw new Error(`Unknown state option: ${arg}`);
    options[arg.slice(2)] = args[++index];
    if (!options[arg.slice(2)]) throw new Error(`${arg} requires a value`);
  }
  if (action === 'collect') {
    if (!options.out || options.sequence == null) throw new Error('state collect requires --sequence and --out');
    const sequence = Number(options.sequence);
    const config = await readJsonInput(input);
    const payload = await collectProtocolState(config, { sequence });
    writeJson(payload, options.out);
    return;
  }
  if (action === 'sign') {
    if (!options.key || !options['key-id'] || !options.out) throw new Error('state sign requires --key, --key-id, and --out');
    const payload = await readJsonInput(input);
    let bundle = options.append ? await readJsonInput(options.append) : { version: 1, payload, signatures: [] };
    if (sha256(bundle.payload) !== sha256(payload)) throw new Error('The appended bundle payload does not match the input payload');
    const privateKey = fs.readFileSync(path.resolve(options.key), 'utf8');
    bundle = addProtocolStateSignature(bundle, signProtocolState(payload, { keyId: options['key-id'], privateKey }));
    writeJson(bundle, options.out);
    return;
  }
  if (action === 'verify') {
    if (!options.policy || !options.intent) throw new Error('state verify requires --policy and --intent');
    const bundle = await readJsonInput(input);
    const policy = loadPolicy(path.resolve(options.policy));
    const intent = await readJsonInput(options.intent);
    const contract = policy.contracts.find((entry) => entry.chainId === Number(intent.chainId) && entry.address.toLowerCase() === String(intent.to).toLowerCase());
    const result = evaluateProtocolState(bundle, policy.protocolState, { protocolId: contract?.protocolId, chainId: Number(intent.chainId), address: intent.to });
    writeJson(result);
    if (!result.valid) process.exitCode = 2;
    return;
  }
  throw new Error(`Unknown state command: ${action}\n${STATE_HELP}`);
}

async function runAudit(args) {
  const action = args[0];
  const file = args[1];
  if (!action || action === '--help' || action === '-h') { process.stdout.write('Keybound audit log:\n  keybound audit verify <receipts.jsonl>\n'); return; }
  if (action !== 'verify' || !file) throw new Error('Usage: keybound audit verify <receipts.jsonl>');
  const result = await verifyAuditLog(path.resolve(file));
  writeJson(result);
  if (!result.valid) process.exitCode = 2;
}

export async function runCli(argv) {
  try {
    if (argv[0] === 'policy') { await runPolicy(argv.slice(1)); return; }
    if (argv[0] === 'authorize') { await runAuthorize(argv.slice(1)); return; }
    if (argv[0] === 'state') { await runState(argv.slice(1)); return; }
    if (argv[0] === 'audit') { await runAudit(argv.slice(1)); return; }
    if (argv[0] === 'attackers') { await runAttackers(argv.slice(1)); return; }
    if (argv[0] === 'alerts') { await runAlerts(argv.slice(1)); return; }
    if (argv[0] === 'registry') { runRegistry(argv.slice(1)).catch((error) => { process.stderr.write(`eth-call-scout: ${error.message}\n`); process.exitCode = 1; }); return; }
    if (argv[0] === 'scan') argv = argv.slice(1);
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
    const scan = scanProject(paths);
    const filesScanned = scan.scanned_files;
    let findings = scan.findings;
    let registry = await loadRegistry();
    if (rulesetPath) {
      const ruleset = JSON.parse(fs.readFileSync(path.resolve(rulesetPath), 'utf8'));
      if (ruleset.version !== 1) throw new Error('Unsupported ruleset version (expected version 1)');
      registry = applyRuleset(registry, ruleset);
    }
    findings = enrichFindings(findings, registry);
    if (decode) findings = await decodeFindings(findings, { chainId });
    const reportData = { generatedAt: new Date().toISOString(), scannedFiles: filesScanned, findings };
    if (!noHtml) {
      fs.mkdirSync(path.dirname(path.resolve(html)), { recursive: true });
      fs.writeFileSync(html, renderReport(reportData), 'utf8');
    }
    if (json) {
      fs.mkdirSync(path.dirname(path.resolve(json)), { recursive: true });
      fs.writeFileSync(json, JSON.stringify(reportData, null, 2) + '\n', 'utf8');
    }
    const contracts = new Set(findings.map((x) => x.address).filter((x) => x && x.startsWith('0x')));
    process.stdout.write(`Scanned ${filesScanned} source file(s); found ${findings.length} Ethereum call(s) and ${contracts.size} literal contract address(es).${decode ? ' ABI/calldata decode enabled.' : ''}\n`);
    if (!noHtml) process.stdout.write(`HTML review: ${path.resolve(html)}\n`);
    if (json) process.stdout.write(`JSON findings: ${path.resolve(json)}\n`);
  } catch (error) {
    process.stderr.write(`eth-call-scout: ${error.message}\n`);
    process.exitCode = 1;
  }
}
