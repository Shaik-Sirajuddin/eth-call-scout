import { getWalletGateway } from '../../../../../../src/wallet-gateway-service.js';
import { requireAgentAuthentication } from '../../../../../../src/agent-api-auth.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request, { params }) {
  try {
    const denied = requireAgentAuthentication(request);
    if (denied) return denied;
    const { id } = await params;
    const gateway = await getWalletGateway();
    const run = await gateway.getRun(id);
    if (!run || run.source !== 'agent-api') return Response.json({ error: 'Agent run not found.' }, { status: 404, headers: { 'cache-control': 'no-store' } });
    return Response.json(run, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
}
