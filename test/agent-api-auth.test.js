import test from 'node:test';
import assert from 'node:assert/strict';
import { requireAgentAuthentication } from '../src/agent-api-auth.js';

const KEY = 'agent-secret-with-at-least-32-characters';

async function withAuthEnvironment(callback) {
  const previous = {
    requireAuth: process.env.WALLETCORDON_REQUIRE_AGENT_AUTH,
    keys: process.env.WALLETCORDON_AGENT_API_KEYS,
  };
  process.env.WALLETCORDON_REQUIRE_AGENT_AUTH = '1';
  process.env.WALLETCORDON_AGENT_API_KEYS = KEY;
  try { await callback(); }
  finally {
    for (const [name, value] of Object.entries({
      WALLETCORDON_REQUIRE_AGENT_AUTH: previous.requireAuth,
      WALLETCORDON_AGENT_API_KEYS: previous.keys,
    })) {
      if (value == null) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test('agent API accepts only an exact configured bearer token when required', async () => {
  await withAuthEnvironment(async () => {
    const accepted = requireAgentAuthentication(new Request('https://app.example/api/v1/agent/runs', { headers: { authorization: `Bearer ${KEY}` } }));
    assert.equal(accepted, null);
    const denied = requireAgentAuthentication(new Request('https://app.example/api/v1/agent/runs', { headers: { authorization: 'Bearer wrong' } }));
    assert.equal(denied.status, 401);
    assert.match(denied.headers.get('www-authenticate'), /Bearer/);
  });
});

test('agent API fails closed when authentication is enabled without keys', async () => {
  await withAuthEnvironment(async () => {
    delete process.env.WALLETCORDON_AGENT_API_KEYS;
    const response = requireAgentAuthentication(new Request('https://app.example/api/v1/agent/runs'));
    assert.equal(response.status, 503);
  });
});
