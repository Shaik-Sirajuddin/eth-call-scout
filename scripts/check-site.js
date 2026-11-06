import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.argv[2] ?? 'site');
const htmlPath = path.join(root, 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const css = fs.readFileSync(path.join(root, 'styles.css'), 'utf8');
const errors = [];

function requireMatch(pattern, message) {
  if (!pattern.test(html)) errors.push(message);
}

requireMatch(/<title>Keybound[^<]*<\/title>/, 'Landing page requires a descriptive Keybound title.');
requireMatch(/<meta\s+name="description"\s+content="[^"]+"/, 'Landing page requires a meta description.');
requireMatch(/<meta\s+name="viewport"/, 'Landing page requires a responsive viewport.');
requireMatch(/<h1>[\s\S]*?<\/h1>/, 'Landing page requires one primary heading.');
requireMatch(/class="skip-link"/, 'Landing page requires a keyboard skip link.');
requireMatch(/data-tour/, 'Landing page requires the end-to-end product tour.');
requireMatch(/data-tour-slide="3"/, 'Product tour must cover the complete four-stage trust path.');
requireMatch(/href="\/runs"/, 'Landing page must link to the Next.js agent control room.');
if (/PR Review Agent|pr-review-ruleset|pull\/(?:20|24|11)/i.test(html)) errors.push('Landing page must not expose the unrelated PR-review agent.');
if (!/prefers-reduced-motion/.test(css)) errors.push('Landing page styles must respect reduced motion.');

if ((html.match(/<h1\b/g) ?? []).length !== 1) errors.push('Landing page must contain exactly one h1.');
for (const required of ['report.html', 'ruleset.html']) {
  if (!fs.existsSync(path.join(root, required))) errors.push(`Missing generated web artifact: ${required}`);
}
for (const removed of ['pr-review-ruleset.html', 'scanner-ruleset.html']) {
  if (fs.existsSync(path.join(root, removed))) errors.push(`Public site must not contain unrelated PR-review artifact: ${removed}`);
}
const policyBuilderPath = path.join(root, 'ruleset.html');
if (fs.existsSync(policyBuilderPath)) {
  const builder = fs.readFileSync(policyBuilderPath, 'utf8');
  if (!/id="canvas"/.test(builder)) errors.push('Policy builder must include the visual block canvas.');
  if (!/id="zoomIn"/.test(builder) || !/id="fitView"/.test(builder)) errors.push('Policy builder must include zoom and fit-view controls.');
  if (!/__callScoutPolicyBuilder/.test(builder)) errors.push('Policy builder must expose deterministic compile and validation hooks.');
  if (!/keybound policy validate/.test(builder)) errors.push('Policy builder must disclose the authoritative CLI validation boundary.');
}
const reportPath = path.join(root, 'report.html');
if (fs.existsSync(reportPath)) {
  const report = fs.readFileSync(reportPath, 'utf8');
  if (!/const DATA=\{/.test(report)) errors.push('Generated report must embed its scan data.');
  if (!/function drawGraph\(\)/.test(report)) errors.push('Generated report must include the interactive call graph.');
  if (!/href="\/policy"/.test(report)) errors.push('Generated report must link to the policy studio route.');
  if (/PR Review Agent|pr-review-ruleset/i.test(report)) errors.push('Generated call report must not present itself as a PR-review agent.');
}
for (const match of html.matchAll(/<(?:a|link|script)\b[^>]*(?:href|src)="([^"]+)"/g)) {
  const reference = match[1];
  if (/^(?:https?:|\/|#|mailto:|tel:|data:)/.test(reference)) continue;
  const target = path.resolve(root, reference);
  if (!target.startsWith(root) || !fs.existsSync(target)) errors.push(`Missing local site asset: ${reference}`);
}
for (const match of html.matchAll(/<button\b([^>]*)>/g)) {
  if (!/\btype="button"/.test(match[1])) errors.push('Every landing-page button must declare type="button".');
}

if (errors.length) {
  process.stderr.write(`${errors.map((error) => `- ${error}`).join('\n')}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write('Landing page structure and local assets are valid.\n');
}
