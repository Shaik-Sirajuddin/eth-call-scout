import { getWalletGateway } from '../../../src/wallet-gateway-service.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const gateway = await getWalletGateway();
    return Response.json({ ...gateway.describe(), mode: 'local-anvil', history: 'persistent-local' }, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ ready: false, error: error.message }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
}
