import { getWalletGateway } from '../../../../../src/wallet-gateway-service.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const gateway = await getWalletGateway();
    return Response.json(await gateway.capabilities(), { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
}
