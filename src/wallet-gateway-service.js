import { WalletPolicyGateway } from './wallet-policy-gateway.js';
import { remoteGatewayFromEnvironment } from './remote-wallet-gateway.js';

const KEY = Symbol.for('keybound.runtime');

function state() {
  if (!globalThis[KEY]) globalThis[KEY] = { runtime: null, startPromise: null };
  return globalThis[KEY];
}

export function installWalletGateway(runtime) {
  const current = state();
  current.runtime = runtime;
  current.startPromise = Promise.resolve(runtime.describe());
  return runtime;
}

export async function getWalletGateway() {
  const current = state();
  if (!current.runtime) {
    if (process.env.VERCEL || process.env.WALLETCORDON_GATEWAY_URL) current.runtime = remoteGatewayFromEnvironment();
    else current.runtime = new WalletPolicyGateway();
  }
  if (!current.startPromise) {
    current.startPromise = current.runtime.start().catch((error) => {
      current.startPromise = null;
      throw error;
    });
  }
  await current.startPromise;
  return current.runtime;
}
