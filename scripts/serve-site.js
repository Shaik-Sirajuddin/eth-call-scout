import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve('dist');
const port = Number(process.env.CALLSCOUT_SITE_PORT ?? 4173);
const types = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
]);

if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) throw new Error('CALLSCOUT_SITE_PORT must be an integer from 1024 to 65535.');

const server = http.createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname);
    const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const target = path.resolve(root, relative);
    if (!target.startsWith(`${root}${path.sep}`)) throw new Error('Invalid path');
    const body = await fs.readFile(target);
    response.writeHead(200, {
      'content-type': types.get(path.extname(target)) ?? 'application/octet-stream',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    });
    response.end(body);
  } catch {
    response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('Not found\n');
  }
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`CallScout demo: http://127.0.0.1:${port}/\n`);
  process.stdout.write(`Agent control room (example evidence): http://127.0.0.1:${port}/demo.html\n`);
  process.stdout.write(`Example report: http://127.0.0.1:${port}/report.html\n`);
  process.stdout.write(`Policy builder: http://127.0.0.1:${port}/ruleset.html\n`);
  process.stdout.write(`PR Review Agent ruleset: http://127.0.0.1:${port}/pr-review-ruleset.html\n`);
});
