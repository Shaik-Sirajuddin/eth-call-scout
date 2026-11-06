import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const legacy = path.join(root, 'public', 'legacy');

await fs.mkdir(legacy, { recursive: true });
await Promise.all([
  fs.copyFile(path.join(root, 'site', 'styles.css'), path.join(legacy, 'landing.css')),
  fs.copyFile(path.join(root, 'site', 'app.js'), path.join(legacy, 'landing.js')),
  fs.copyFile(path.join(root, 'site', 'demo.css'), path.join(legacy, 'runs.css')),
]);

process.stdout.write(`Prepared Next.js assets in ${legacy}\n`);
