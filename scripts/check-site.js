import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.argv[2] ?? 'dist');
const secuRoot = path.join(root, 'products', 'secu');
const errors = [];
const requireFile = (base, file) => { if (!fs.existsSync(path.join(base, file))) errors.push(`Missing generated page: ${path.relative(root, path.join(base, file))}`); };
const mainHtml = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const mainCss = fs.readFileSync(path.join(root, 'styles.css'), 'utf8');
const secuHtml = fs.readFileSync(path.join(secuRoot, 'index.html'), 'utf8');
const secuCss = fs.readFileSync(path.join(secuRoot, 'styles.css'), 'utf8');
if (!/<title>CallScout[^<]*<\/title>/.test(mainHtml)) errors.push('Main homepage must use the CallScout title.');
if (!/href="\.\/products\/secu\/"/.test(mainHtml)) errors.push('Main homepage must link to the Secu product subsite.');
if (!/<title>Secu[^<]*<\/title>/.test(secuHtml)) errors.push('Secu subsite must use its own descriptive title.');
if (!/prefers-reduced-motion/.test(mainCss) || !/prefers-reduced-motion/.test(secuCss)) errors.push('Both sites must respect reduced motion.');
for (const file of ['report.html', 'ruleset.html', 'pr-review-ruleset.html']) requireFile(root, file);
for (const file of ['index.html', 'setup.html', 'report.html', 'scanner-ruleset.html']) requireFile(secuRoot, file);
const policyBuilder = fs.readFileSync(path.join(root, 'ruleset.html'), 'utf8');
for (const [pattern, message] of [[/id="canvas"/, 'Policy builder must include the visual block canvas.'], [/id="zoomIn"/, 'Policy builder must include zoom controls.'], [/__callScoutPolicyBuilder/, 'Policy builder must expose deterministic validation hooks.'], [/callscout policy validate/, 'Policy builder must disclose CLI validation.']]) if (!pattern.test(policyBuilder)) errors.push(message);
const closedPRs = (mainHtml + secuHtml).match(/pull\/(?:11|17|18|19|20|21|23|24)(?:["/?#])/g) ?? [];
if (closedPRs.length) errors.push('Site pages must not link to closed pull requests.');
for (const [base, html] of [[root, mainHtml], [secuRoot, secuHtml]]) {
  for (const match of html.matchAll(/<(?:a|link|script)\b[^>]*(?:href|src)="([^"]+)"/g)) {
    const reference = match[1];
    if (/^(?:https?:|#|mailto:|tel:|data:)/.test(reference)) continue;
    const target = path.resolve(base, reference);
    if (!target.startsWith(root) || !fs.existsSync(target)) errors.push(`Missing local site asset: ${path.relative(root, base)}${path.sep}${reference}`);
  }
}
if (errors.length) {
  process.stderr.write(`${errors.map((error) => `- ${error}`).join('\n')}\n`);
  process.exitCode = 1;
} else process.stdout.write('Main site and Secu product subsite are valid.\n');
