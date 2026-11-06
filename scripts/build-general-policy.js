#!/usr/bin/env node
// Writes examples/general-policy.json, the default rules the policy builder opens with.
// The keys below are public sample keys from examples/wallet-policy-live.json, so replace them before real use.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPolicyFromRuleSet } from '../src/rule-sets.js';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const sample = JSON.parse(fs.readFileSync(path.join(ROOT, 'examples', 'wallet-policy-live.json'), 'utf8'));
export const policy = createPolicyFromRuleSet({
  wallet: sample.wallets[0],
  trustedKeys: sample.protocolState.trustedKeys,
  validUntil: '2030-01-01T00:00:00.000Z',
  name: 'General user: default rules',
});
fs.writeFileSync(path.join(ROOT, 'examples', 'general-policy.json'), `${JSON.stringify(policy, null, 2)}\n`);
console.log('Wrote examples/general-policy.json');
