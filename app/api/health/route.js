import { getWalletGateway } from '../../../src/wallet-gateway-service.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const gateway = await getWalletGateway();
    const descriptor = gateway.describe();
    return Response.json({
      ...descriptor,
      mode: descriptor.mode ?? 'local-anvil',
      history: descriptor.history ?? 'persistent-local',
    }, { headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    return Response.json({ ready: false, error: error.message }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
}
