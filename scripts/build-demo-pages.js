import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../src/rust-scanner.js';
import { applyRuleset, enrichFindings } from '../src/registry.js';
import { renderReport } from '../src/report.js';
import { renderReviewRulesetBuilder, renderRulesetBuilder } from '../src/ruleset-page.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const SITE = path.join(ROOT, 'site');
const DIST = path.join(ROOT, 'dist');

const readJson = async (file) => JSON.parse(await fs.readFile(file, 'utf8'));
const publicPath = (file) => {
  const relative = path.relative(ROOT, file);
  return relative.startsWith('..') ? path.basename(file) : relative.split(path.sep).join('/');
};

const baseRegistry = await readJson(path.join(ROOT, 'data', 'registry.static.json'));
const ruleset = await readJson(path.join(ROOT, '.secu'));
const walletPolicy = await readJson(path.join(ROOT, 'examples', 'wallet-policy.json'));
const registry = applyRuleset(baseRegistry, ruleset);
const scan = scanProject([path.join(ROOT, 'examples')]);
const findings = enrichFindings(scan.findings, registry).map((finding) => ({
  ...finding,
  file: publicPath(finding.file),
}));

await fs.rm(DIST, { recursive: true, force: true });
await fs.mkdir(DIST, { recursive: true });
for (const asset of ['index.html', 'styles.css', 'app.js', 'demo.html', 'demo.css', 'demo.js']) {
  await fs.copyFile(path.join(SITE, asset), path.join(DIST, asset));
}

const report = {
  generatedAt: new Date().toISOString(),
  scannedFiles: scan.scanned_files,
  findings,
};
await fs.writeFile(path.join(DIST, 'report.html'), renderReport(report), 'utf8');
await fs.writeFile(path.join(DIST, 'report.json'), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
await fs.writeFile(path.join(DIST, 'ruleset.html'), renderRulesetBuilder(baseRegistry, walletPolicy), 'utf8');
const reviewRuleset = renderReviewRulesetBuilder(baseRegistry);
await fs.writeFile(path.join(DIST, 'pr-review-ruleset.html'), reviewRuleset, 'utf8');
await fs.writeFile(path.join(DIST, 'scanner-ruleset.html'), reviewRuleset, 'utf8');
await fs.writeFile(path.join(DIST, '.nojekyll'), '', 'utf8');

process.stdout.write(`Demo site: ${DIST}\nAgent control room: ${path.join(DIST, 'demo.html')}\nExample report: ${path.join(DIST, 'report.html')}\nPolicy builder: ${path.join(DIST, 'ruleset.html')}\nPR Review Agent ruleset: ${path.join(DIST, 'pr-review-ruleset.html')}\n`);
