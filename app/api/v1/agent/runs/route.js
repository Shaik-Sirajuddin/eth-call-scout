import { getWalletGateway } from '../../../../../src/wallet-gateway-service.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  const gateway = await getWalletGateway();
  return Response.json({ runs: gateway.listRuns().filter((run) => run.source === 'agent-api') }, { headers: { 'cache-control': 'no-store' } });
}

export async function POST(request) {
  try {
    const length = Number(request.headers.get('content-length') ?? 0);
    if (length > 32_768) return Response.json({ error: 'Request body exceeds 32 KB.' }, { status: 413 });
    const body = await request.json();
    const gateway = await getWalletGateway();
    const existing = body.requestId ? gateway.listRuns().find((run) => run.requestId === body.requestId) : null;
    const run = gateway.createAgentRun({ requestId: body.requestId, goal: body.goal, proposal: body.proposal });
    return Response.json(run, { status: existing ? 200 : 202, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 400, headers: { 'cache-control': 'no-store' } });
  }
}
