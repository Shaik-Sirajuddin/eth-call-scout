import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderRulesetBuilder } from '../src/ruleset-page.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const registry = JSON.parse(fs.readFileSync(path.join(root, 'data', 'registry.static.json'), 'utf8'));
const target = path.join(root, 'ruleset.html');
const html = renderRulesetBuilder(registry);
fs.writeFileSync(target, html, 'utf8');
const servedCopy = path.join(root, 'reports', 'ruleset.html');
fs.mkdirSync(path.dirname(servedCopy), { recursive: true });
fs.writeFileSync(servedCopy, html, 'utf8');
process.stdout.write(`Ruleset builder: ${target}\nServed copy: ${servedCopy}\n`);
