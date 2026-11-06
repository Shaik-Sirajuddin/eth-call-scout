import assert from 'node:assert/strict';
import test from 'node:test';
import { parseDemoTradePrompt } from '../src/demo-agent.js';

const wallet = '0x1111111111111111111111111111111111111111';

test('demo agent parses a bounded swap and preserves a minimum output', () => {
  const trade = parseDemoTradePrompt('Swap 100 dUSD for dETH with at least 190 dETH out.', { wallet });
  assert.equal(trade.amountIn, '100000000000000000000');
  assert.equal(trade.minimumOut, '190000000000000000000');
  assert.equal(trade.recipient, wallet);
});

test('demo agent supplies a conservative default minimum output', () => {
  const trade = parseDemoTradePrompt('Trade 10 USDC for dETH', { wallet });
  assert.equal(trade.minimumOut, '18000000000000000000');
});

test('demo agent rejects broad, oversized, and redirected requests', () => {
  assert.throws(() => parseDemoTradePrompt('Send everything everywhere', { wallet }), /supports/);
  assert.throws(() => parseDemoTradePrompt('Swap 1001 dUSD for dETH', { wallet }), /1,000/);
  assert.throws(() => parseDemoTradePrompt('Swap 10 dUSD for dETH to 0x2222222222222222222222222222222222222222', { wallet }), /redirect/);
});
