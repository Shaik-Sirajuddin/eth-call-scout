import { getWalletGateway } from '../../../src/wallet-gateway-service.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  const gateway = await getWalletGateway();
  return Response.json({ runs: await gateway.listRuns() }, { headers: { 'cache-control': 'no-store' } });
}

export async function POST(request) {
  try {
    const length = Number(request.headers.get('content-length') ?? 0);
    if (length > 16_384) return Response.json({ error: 'Request body exceeds 16 KB.' }, { status: 413 });
    const body = await request.json();
    const prompt = String(body.prompt ?? '').trim();
    if (!prompt || prompt.length > 500) return Response.json({ error: 'Prompt must be between 1 and 500 characters.' }, { status: 400 });
    const gateway = await getWalletGateway();
    return Response.json(await gateway.createRun(prompt, { scenario: body.scenario }), { status: 202, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 400, headers: { 'cache-control': 'no-store' } });
  }
}
