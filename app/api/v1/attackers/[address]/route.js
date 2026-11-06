import { attackerLookupResponse } from '../../../../../src/attacker-api.js';

export const runtime = 'nodejs';

export async function GET(_request, { params }) {
  const { address } = await params;
  return attackerLookupResponse(address);
}
