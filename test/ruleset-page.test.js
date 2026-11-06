import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { validatePolicy } from '../src/policy.js';
import { renderReviewRulesetBuilder, renderRulesetBuilder } from '../src/ruleset-page.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const registry = JSON.parse(fs.readFileSync(path.join(root, 'data', 'registry.static.json'), 'utf8'));
const policy = JSON.parse(fs.readFileSync(path.join(root, 'examples', 'wallet-policy.json'), 'utf8'));

test('visual policy builder exposes the complete local authoring workflow', () => {
  assert.equal(validatePolicy(policy).valid, true);
  const html = renderRulesetBuilder(registry, policy);

  for (const marker of [
    'id="canvas"',
    'id="policyPrompt"',
    'id="compilePrompt"',
    'id="promptMode"',
    'id="blocksMode"',
    '/api/policy/compile-prompt',
    'AI suggests; deterministic code decides',
    'id="zoomIn"',
    'id="zoomOut"',
    'id="fitView"',
    'id="minimap"',
    'Policy block library',
    'EIP-7702 boundary',
    'Live state quorum',
    'Simulation quorum',
    'Authorization receipt',
    'keybound policy validate',
    'window.__callScoutPolicyBuilder',
  ]) assert.match(html, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  assert.doesNotMatch(html, /pr-review-ruleset\.html/);
  assert.match(html, /@media\(max-width:820px\)/);
  assert.match(html, /prefers-reduced-motion/);
  assert.match(html, /localStorage\.setItem\(STORAGE_KEY/);
  assert.match(html, /application\/keybound-block/);
});

test('policy seed and registry data cannot break out of the builder script', () => {
  const hostile = structuredClone(policy);
  hostile.name = '</script><script>globalThis.pwned=true</script>';
  const html = renderRulesetBuilder({ tokens: [{ name: '</script><img src=x onerror=alert(1)>', address: policy.wallets[0] }] }, hostile);

  assert.doesNotMatch(html, /<script>globalThis\.pwned/);
  assert.doesNotMatch(html, /<img src=x onerror/);
  assert.match(html, /\\u003c\/script\\u003e/);
});

test('PR Review Agent term editor remains a separate monitoring-only surface', () => {
  const html = renderReviewRulesetBuilder(registry);
  assert.match(html, /PR Review Agent Ruleset/);
  assert.match(html, /High slippage threshold/);
  assert.match(html, /Wallet authorization remains a separate executable policy/i);
  assert.doesNotMatch(html, /Authorization policy studio/);
});
