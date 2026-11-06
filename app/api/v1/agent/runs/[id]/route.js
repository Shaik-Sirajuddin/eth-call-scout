import { getWalletGateway } from '../../../../../../src/wallet-gateway-service.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(_request, { params }) {
  const { id } = await params;
  const gateway = await getWalletGateway();
  const run = gateway.getRun(id);
  if (!run || run.source !== 'agent-api') return Response.json({ error: 'Agent run not found.' }, { status: 404 });
  return Response.json(run, { headers: { 'cache-control': 'no-store' } });
}
