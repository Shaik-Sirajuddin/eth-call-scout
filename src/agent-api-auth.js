import crypto from 'node:crypto';

function digest(value) {
  return crypto.createHash('sha256').update(value).digest();
}

function configuredKeys() {
  return String(process.env.WALLETCORDON_AGENT_API_KEYS ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

function unauthorized(message, status = 401) {
  return Response.json({ error: message }, {
    status,
    headers: {
      'cache-control': 'no-store',
      ...(status === 401 ? { 'www-authenticate': 'Bearer realm="WalletCordon Agent API"' } : {}),
    },
  });
}

export function requireAgentAuthentication(request) {
  const required = Boolean(process.env.VERCEL) || process.env.WALLETCORDON_REQUIRE_AGENT_AUTH === '1';
  if (!required) return null;
  const keys = configuredKeys();
  if (!keys.length || keys.some((key) => key.length < 32)) {
    return unauthorized('Agent API authentication is not configured.', 503);
  }
  const header = request.headers.get('authorization') ?? '';
  const match = /^Bearer ([^\s]+)$/.exec(header);
  if (!match) return unauthorized('A valid agent bearer token is required.');
  const candidate = digest(match[1]);
  const accepted = keys.some((key) => crypto.timingSafeEqual(candidate, digest(key)));
  return accepted ? null : unauthorized('A valid agent bearer token is required.');
}
