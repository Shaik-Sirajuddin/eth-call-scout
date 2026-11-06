import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const demoDirectory = path.join(root, 'demo');
const runtimeDirectory = path.join(demoDirectory, 'runtime');

if (
  path.basename(runtimeDirectory) !== 'runtime'
  || path.basename(path.dirname(runtimeDirectory)) !== 'demo'
  || !runtimeDirectory.startsWith(`${root}${path.sep}`)
) {
  throw new Error(`Refusing to reset unexpected path: ${runtimeDirectory}`);
}

await fs.rm(runtimeDirectory, { recursive: true, force: true });
await fs.mkdir(path.join(runtimeDirectory, 'runs'), { recursive: true, mode: 0o700 });
await fs.chmod(runtimeDirectory, 0o700);

process.stdout.write(`Reset generated local demo history at ${runtimeDirectory}\n`);
