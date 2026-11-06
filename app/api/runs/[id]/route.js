import { getWalletGateway } from '../../../../src/wallet-gateway-service.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(_request, { params }) {
  const { id } = await params;
  const gateway = await getWalletGateway();
  const run = await gateway.getRun(id);
  return run
    ? Response.json(run, { headers: { 'cache-control': 'no-store' } })
    : Response.json({ error: 'Run not found.' }, { status: 404, headers: { 'cache-control': 'no-store' } });
}
