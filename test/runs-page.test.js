import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const css = fs.readFileSync(path.join(root, 'site', 'demo.css'), 'utf8');

test('Agent Runs uses the readable product typography scale', () => {
  assert.match(css, /--type-micro:\s*9px/);
  assert.match(css, /--type-label:\s*10px/);
  assert.match(css, /--type-small:\s*11px/);
  assert.match(css, /--type-body:\s*13px/);
  assert.match(css, /\.side-nav a\s*\{[^}]*font-size:\s*13px/);
  assert.match(css, /\.run-prompt\s*\{[^}]*font-size:\s*var\(--type-body\)/);
  assert.match(css, /\.event-copy p\s*\{[^}]*font-size:\s*12px/);
  assert.match(css, /\.code-box\s*\{[^}]*font:\s*var\(--type-label\)\/1\.65/);
});
