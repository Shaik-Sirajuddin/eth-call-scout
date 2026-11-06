import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const css = fs.readFileSync(path.join(root, 'site', 'demo.css'), 'utf8');

test('Agent Runs uses the WalletCordon readable typography scale', () => {
  assert.match(css, /--type-micro:\s*12px/);
  assert.match(css, /--type-label:\s*13px/);
  assert.match(css, /--type-small:\s*14px/);
  assert.match(css, /--type-body:\s*16px/);
  assert.match(css, /\.side-nav a\s*\{[^}]*font-size:\s*15px/);
  assert.match(css, /\.side-nav a span\s*\{[^}]*var\(--type-label\)/);
  assert.match(css, /\.run-count\s*\{[^}]*var\(--type-label\)/);
  assert.match(css, /\.run-prompt\s*\{[^}]*font-size:\s*var\(--type-body\)/);
  assert.match(css, /\.event-copy p\s*\{[^}]*font-size:\s*var\(--type-small\)/);
  assert.match(css, /\.code-box\s*\{[^}]*font:\s*var\(--type-label\)\/1\.65/);
});

test('Recent Runs fills the desktop rail and keeps bounded mobile scrolling', () => {
  assert.match(css, /\.run-rail\s*\{[^}]*position:\s*sticky[^}]*height:\s*100vh[^}]*display:\s*flex[^}]*flex-direction:\s*column/);
  assert.match(css, /\.run-list\s*\{[^}]*flex:\s*1[^}]*min-height:\s*0[^}]*overflow-y:\s*auto/);
  assert.match(css, /@media\s*\(max-width:\s*820px\)[\s\S]*\.run-rail\s*\{[^}]*position:\s*static[^}]*height:\s*auto/);
  assert.match(css, /@media\s*\(max-width:\s*820px\)[\s\S]*\.run-list\s*\{[^}]*flex:\s*none[^}]*max-height:\s*390px[^}]*overflow-y:\s*auto/);
});
