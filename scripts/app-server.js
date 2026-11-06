import http from 'node:http';
import next from 'next';
import { WalletPolicyGateway } from '../src/wallet-policy-gateway.js';
import { installWalletGateway } from '../src/wallet-gateway-service.js';

const development = process.argv.includes('--dev');
const portIndex = process.argv.indexOf('--port');
const port = Number(portIndex >= 0 ? process.argv[portIndex + 1] : process.env.PORT ?? 3000);
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error('App port must be an integer from 1 to 65535.');

const hostname = '127.0.0.1';
const runtime = new WalletPolicyGateway();
await runtime.start();
installWalletGateway(runtime);

const app = next({ dev: development, hostname, port });
const handle = app.getRequestHandler();
let server;
try {
  await app.prepare();
  server = http.createServer((request, response) => handle(request, response));
  await new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once('error', onError);
    server.listen(port, hostname, () => {
      server.off('error', onError);
      resolve();
    });
  });
} catch (error) {
  await runtime.stop().catch(() => {});
  throw error;
}

process.stdout.write(`Keybound Next.js app: http://${hostname}:${port}/\n`);
process.stdout.write(`Agent runs: http://${hostname}:${port}/runs\n`);
process.stdout.write(`Agent API: http://${hostname}:${port}/api/v1/agent/capabilities\n`);

let stopping = false;
async function shutdown() {
  if (stopping) return;
  stopping = true;
  const closed = new Promise((resolve) => server.close(resolve));
  server.closeAllConnections?.();
  await closed;
  await runtime.stop();
}

process.once('SIGINT', async () => { await shutdown(); process.exit(0); });
process.once('SIGTERM', async () => { await shutdown(); process.exit(0); });
