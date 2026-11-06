import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DemoRuntime } from '../src/demo-runtime.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const dist = path.join(root, 'dist');
const portIndex = process.argv.indexOf('--port');
const port = Number(portIndex >= 0 ? process.argv[portIndex + 1] : process.env.PORT ?? 4174);
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error('Demo server port must be an integer from 1 to 65535.');

const runtime = new DemoRuntime();

function sendJson(response, status, data) {
  const body = Buffer.from(JSON.stringify(data));
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  response.end(body);
}

async function readJson(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > 16_384) throw new Error('Request body exceeds 16 KB.');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function contentType(target) {
  if (target.endsWith('.html')) return 'text/html; charset=utf-8';
  if (target.endsWith('.css')) return 'text/css; charset=utf-8';
  if (target.endsWith('.js')) return 'text/javascript; charset=utf-8';
  if (target.endsWith('.json')) return 'application/json; charset=utf-8';
  if (target.endsWith('.svg')) return 'image/svg+xml';
  return 'application/octet-stream';
}

async function serveStatic(request, response, url) {
  const requested = url.pathname === '/' ? '/index.html' : url.pathname === '/demo' ? '/demo.html' : url.pathname;
  const target = path.resolve(dist, `.${requested}`);
  if (!target.startsWith(`${dist}${path.sep}`)) return sendJson(response, 403, { error: 'Forbidden' });
  try {
    const body = await fs.readFile(target);
    response.writeHead(200, {
      'content-type': contentType(target),
      'content-length': body.length,
      'cache-control': target.endsWith('.html') ? 'no-cache' : 'public, max-age=60',
      'x-content-type-options': 'nosniff',
    });
    response.end(body);
  } catch (error) {
    if (error.code === 'ENOENT') return sendJson(response, 404, { error: 'Not found' });
    throw error;
  }
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host ?? `127.0.0.1:${port}`}`);
    if (request.method === 'GET' && url.pathname === '/api/health') return sendJson(response, 200, runtime.describe());
    if (request.method === 'GET' && url.pathname === '/api/runs') return sendJson(response, 200, { runs: runtime.listRuns() });
    if (request.method === 'GET' && url.pathname.startsWith('/api/runs/')) {
      const run = runtime.getRun(decodeURIComponent(url.pathname.slice('/api/runs/'.length)));
      return run ? sendJson(response, 200, run) : sendJson(response, 404, { error: 'Run not found' });
    }
    if (request.method === 'POST' && url.pathname === '/api/runs') {
      const body = await readJson(request);
      const run = runtime.createRun(body.prompt, { scenario: body.scenario });
      return sendJson(response, 202, run);
    }
    if (url.pathname.startsWith('/api/')) return sendJson(response, 404, { error: 'Unknown API route' });
    if (!['GET', 'HEAD'].includes(request.method)) return sendJson(response, 405, { error: 'Method not allowed' });
    return serveStatic(request, response, url);
  } catch (error) {
    return sendJson(response, 400, { error: error.message });
  }
});

await runtime.start();
server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`CallScout product site: http://127.0.0.1:${port}/\n`);
  process.stdout.write(`Run API: http://127.0.0.1:${port}/api/health\n`);
});

async function shutdown() {
  await new Promise((resolve) => server.close(resolve));
  await runtime.stop();
}

process.once('SIGINT', async () => { await shutdown(); process.exit(0); });
process.once('SIGTERM', async () => { await shutdown(); process.exit(0); });
