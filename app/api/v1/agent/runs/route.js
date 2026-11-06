import { getWalletGateway } from '../../../../../src/wallet-gateway-service.js';
import { requireAgentAuthentication } from '../../../../../src/agent-api-auth.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  try {
    const denied = requireAgentAuthentication(request);
    if (denied) return denied;
    const gateway = await getWalletGateway();
    return Response.json({ runs: (await gateway.listRuns()).filter((run) => run.source === 'agent-api') }, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
}

export async function POST(request) {
  try {
    const denied = requireAgentAuthentication(request);
    if (denied) return denied;
    const length = Number(request.headers.get('content-length') ?? 0);
    if (length > 32_768) return Response.json({ error: 'Request body exceeds 32 KB.' }, { status: 413 });
    const body = await request.json();
    const gateway = await getWalletGateway();
    const existing = body.requestId ? (await gateway.listRuns()).find((run) => run.requestId === body.requestId) : null;
    const run = await gateway.createAgentRun({ requestId: body.requestId, goal: body.goal, proposal: body.proposal });
    return Response.json(run, { status: existing ? 200 : 202, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 400, headers: { 'cache-control': 'no-store' } });
  }
}
