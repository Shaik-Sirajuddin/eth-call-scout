import { WalletPolicyGateway } from './wallet-policy-gateway.js';

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
  if (process.env.VERCEL) {
    throw new Error('Live wallet execution is disabled on the hosted UI until the authenticated testnet Gateway is configured.');
  }
  const current = state();
  if (!current.runtime) current.runtime = new WalletPolicyGateway();
  if (!current.startPromise) {
    current.startPromise = current.runtime.start().catch((error) => {
      current.startPromise = null;
      throw error;
    });
  }
  await current.startPromise;
  return current.runtime;
}
