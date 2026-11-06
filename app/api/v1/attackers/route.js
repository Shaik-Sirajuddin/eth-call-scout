import { attackerListResponse } from '../../../../src/attacker-api.js';

export const runtime = 'nodejs';

export function GET(request) {
  return attackerListResponse(request);
}
