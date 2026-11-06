import fs from 'node:fs/promises';
import path from 'node:path';
import { renderRulesetBuilder } from '../../src/ruleset-page.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const [registry, policy] = await Promise.all([
      fs.readFile(path.join(process.cwd(), 'data', 'registry.static.json'), 'utf8').then(JSON.parse),
      fs.readFile(path.join(process.cwd(), 'examples', 'wallet-policy.json'), 'utf8').then(JSON.parse),
    ]);
    return new Response(renderRulesetBuilder(registry, policy), {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
      },
    });
  } catch (error) {
    return new Response(`Policy studio is unavailable: ${error.message}`, { status: 503, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  }
}
