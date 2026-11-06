import { loadSepoliaGatewayEnvironment } from '../src/sepolia-gateway-config.js';
import { listenSepoliaGateway } from '../src/sepolia-gateway-server.js';
import { SepoliaWalletGateway } from '../src/sepolia-wallet-gateway.js';

const environment = await loadSepoliaGatewayEnvironment();
const gateway = new SepoliaWalletGateway(environment);
await gateway.start();
const server = await listenSepoliaGateway({ gateway, serviceToken: environment.serviceToken });
const address = server.address();
process.stdout.write(`WalletCordon Sepolia Gateway listening on ${typeof address === 'object' ? address.port : address}.\n`);

let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await new Promise((resolve) => server.close(resolve));
  await gateway.stop();
}

process.once('SIGINT', async () => { await stop(); process.exit(0); });
process.once('SIGTERM', async () => { await stop(); process.exit(0); });
