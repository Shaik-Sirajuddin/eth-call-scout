import { getWalletGateway } from '../../../../../src/wallet-gateway-service.js';
import { requireAgentAuthentication } from '../../../../../src/agent-api-auth.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request) {
  try {
    const denied = requireAgentAuthentication(request);
    if (denied) return denied;
    const gateway = await getWalletGateway();
    return Response.json(await gateway.capabilities(), { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
}
