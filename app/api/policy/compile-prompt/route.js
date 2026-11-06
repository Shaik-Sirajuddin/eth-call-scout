import fs from 'node:fs/promises';
import path from 'node:path';
import { translatePolicyPromptWithAI } from '../../../../src/policy-ai.js';
import { compilePolicyPrompt } from '../../../../src/policy-prompt.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function json(body, status = 200) {
  return Response.json(body, { status, headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
}

export async function POST(request) {
  try {
    const length = Number(request.headers.get('content-length') ?? 0);
    if (length > 16_384) return json({ error: 'Request body exceeds 16 KB.' }, 413);
    const body = await request.json();
    const prompt = typeof body.prompt === 'string' ? body.prompt.trim() : '';
    if (!prompt || prompt.length > 4_000) return json({ error: 'Policy description must be between 1 and 4,000 characters.' }, 400);
    const [registry, seedPolicy] = await Promise.all([
      fs.readFile(path.join(process.cwd(), 'data', 'registry.static.json'), 'utf8').then(JSON.parse),
      fs.readFile(path.join(process.cwd(), 'examples', 'wallet-policy.json'), 'utf8').then(JSON.parse),
    ]);

    let translation = null;
    let canonicalPrompt = prompt;
    let authoringMode = 'deterministic-fallback';
    if (process.env.OPENAI_API_KEY) {
      translation = await translatePolicyPromptWithAI(prompt, { registry });
      canonicalPrompt = translation.rules.map((rule) => rule.canonical).join('\n');
      authoringMode = 'ai-assisted';
    }
    const result = compilePolicyPrompt(canonicalPrompt, { registry, seedPolicy });
    if (translation?.unresolved?.length) {
      for (const unresolved of translation.unresolved) result.errors.push({ code: 'unresolved-requirement', clause: unresolved.source, message: unresolved.reason });
      result.valid = false;
    }
    if (!process.env.OPENAI_API_KEY) result.warnings.unshift({ code: 'ai-not-configured', message: 'OPENAI_API_KEY is not configured; the strict canonical-rule parser handled this request without AI.' });
    return json({ ...result, authoringMode, translation }, result.valid ? 200 : 422);
  } catch (error) {
    return json({ error: error.message }, 502);
  }
}
