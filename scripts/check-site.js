import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve('site');
const htmlPath = path.join(root, 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const css = fs.readFileSync(path.join(root, 'styles.css'), 'utf8');
const errors = [];

function requireMatch(pattern, message) {
  if (!pattern.test(html)) errors.push(message);
}

requireMatch(/<title>CallScout[^<]*<\/title>/, 'Landing page requires a descriptive CallScout title.');
requireMatch(/<meta\s+name="description"\s+content="[^"]+"/, 'Landing page requires a meta description.');
requireMatch(/<meta\s+name="viewport"/, 'Landing page requires a responsive viewport.');
requireMatch(/<h1>[\s\S]*?<\/h1>/, 'Landing page requires one primary heading.');
requireMatch(/class="skip-link"/, 'Landing page requires a keyboard skip link.');
if (!/prefers-reduced-motion/.test(css)) errors.push('Landing page styles must respect reduced motion.');

if ((html.match(/<h1\b/g) ?? []).length !== 1) errors.push('Landing page must contain exactly one h1.');
for (const match of html.matchAll(/<(?:a|link|script)\b[^>]*(?:href|src)="([^"]+)"/g)) {
  const reference = match[1];
  if (/^(?:https?:|#|mailto:|tel:|data:)/.test(reference)) continue;
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
