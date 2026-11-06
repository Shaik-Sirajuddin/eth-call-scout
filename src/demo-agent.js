import { parseUnits } from 'ethers';

const SWAP_PATTERN = /\b(?:swap|trade|exchange)\s+([0-9]+(?:\.[0-9]{1,6})?)\s*(?:d?usd|usdc|demo\s*usd|tokens?)/i;
const MINIMUM_PATTERN = /(?:at\s+least|minimum(?:\s+out(?:put)?)?|min(?:\s+out(?:put)?)?)\s*[:=]?\s*([0-9]+(?:\.[0-9]{1,6})?)/i;
const ADDRESS_PATTERN = /0x[a-fA-F0-9]{40}/g;
const MAX_INPUT = parseUnits('1000', 18);

/**
 * A deliberately narrow demo agent. It converts a natural-language swap request into
 * structured data, but it has no signer and its output remains untrusted input to CallScout.
 */
export function parseDemoTradePrompt(prompt, { wallet } = {}) {
  if (typeof prompt !== 'string' || prompt.trim().length < 8 || prompt.length > 500) {
    throw new Error('Describe one bounded swap in 8–500 characters.');
  }
  const match = prompt.match(SWAP_PATTERN);
  if (!match) throw new Error('Demo agent supports “Swap <amount> dUSD for dETH” requests.');
  const amountIn = parseUnits(match[1], 18);
  if (amountIn <= 0n || amountIn > MAX_INPUT) throw new Error('Swap amount must be greater than 0 and no more than 1,000 dUSD.');

  const minimumMatch = prompt.match(MINIMUM_PATTERN);
  const minimumOut = minimumMatch ? parseUnits(minimumMatch[1], 18) : amountIn * 18n / 10n;
  if (minimumOut <= 0n) throw new Error('Minimum output must be greater than zero.');

  const mentionedAddresses = prompt.match(ADDRESS_PATTERN) ?? [];
  if (mentionedAddresses.length && (!wallet || mentionedAddresses.some((address) => address.toLowerCase() !== wallet.toLowerCase()))) {
    throw new Error('The demo agent cannot redirect proceeds to an arbitrary address.');
  }

  return Object.freeze({
    action: 'swapExactTokensForTokens',
    tokenIn: 'dUSD',
    tokenOut: 'dETH',
    amountIn: amountIn.toString(),
    minimumOut: minimumOut.toString(),
    recipient: wallet ?? null,
    summary: `Swap ${match[1]} dUSD for dETH with at least ${minimumMatch ? `${minimumMatch[1]} dETH` : '90% of quoted output'} received.`,
  });
}

export const DEMO_AGENT_LIMITS = Object.freeze({ maxInput: MAX_INPUT.toString(), decimals: 18 });
