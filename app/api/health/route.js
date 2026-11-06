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
    const hosted = Boolean(process.env.VERCEL || process.env.WALLETCORDON_GATEWAY_URL);
    return Response.json({
      ready: false,
      mode: hosted ? 'sepolia-beta' : 'local-anvil',
      chainId: hosted ? 11_155_111 : null,
      history: hosted ? 'durable-remote' : 'persistent-local',
      eip7702: hosted ? 'denied-by-policy' : undefined,
      error: error.message,
    }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
}
