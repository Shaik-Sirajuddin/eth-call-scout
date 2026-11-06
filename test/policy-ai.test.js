import assert from 'node:assert/strict';
import test from 'node:test';
import { translatePolicyPromptWithAI } from '../src/policy-ai.js';

test('AI translator uses server authentication and strict structured output', async () => {
  let request;
  const translated = {
    summary: 'Conservative Uniswap approval policy.',
    rules: [{ source: 'let Uniswap spend 100 USDC', canonical: 'Allow Uniswap to spend up to 100 USDC.' }],
    unresolved: [],
  };
  const result = await translatePolicyPromptWithAI('let Uniswap spend 100 USDC', {
    apiKey: 'test-secret',
    model: 'test-model',
    registry: { tokens: [{ chainId: 1, symbol: 'USDC', name: 'USD Coin' }], protocols: [{ id: 'uniswap', name: 'Uniswap' }] },
    fetchImpl: async (url, options) => {
      request = { url, options, body: JSON.parse(options.body) };
      return { ok: true, json: async () => ({ status: 'completed', output: [{ content: [{ type: 'output_text', text: JSON.stringify(translated) }] }] }) };
    },
  });

  assert.equal(request.url, 'https://api.openai.com/v1/responses');
  assert.equal(request.options.headers.authorization, 'Bearer test-secret');
  assert.equal(request.body.store, false);
  assert.equal(request.body.text.format.type, 'json_schema');
  assert.equal(request.body.text.format.strict, true);
  assert.equal(request.body.text.format.schema.additionalProperties, false);
  assert.equal(request.body.model, 'test-model');
  assert.deepEqual(result.rules, translated.rules);
});

test('AI translator fails closed when no structured output is returned', async () => {
  await assert.rejects(() => translatePolicyPromptWithAI('allow something', {
    apiKey: 'test-secret',
    fetchImpl: async () => ({ ok: true, json: async () => ({ status: 'completed', output: [] }) }),
  }), /no structured output/i);
});
