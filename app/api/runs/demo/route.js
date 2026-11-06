import { getWalletGateway } from '../../../../src/wallet-gateway-service.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST() {
  try {
    const gateway = await getWalletGateway();
    return Response.json(gateway.createTwoTransactionDemo(), {
      status: 202,
      headers: { 'cache-control': 'no-store' },
    });
  } catch (error) {
    return Response.json({ error: error.message }, {
      status: 400,
      headers: { 'cache-control': 'no-store' },
    });
  }
}
