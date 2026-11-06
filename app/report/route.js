import fs from 'node:fs/promises';
import path from 'node:path';
import { renderReport } from '../../src/report.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const report = JSON.parse(await fs.readFile(path.join(process.cwd(), 'dist', 'report.json'), 'utf8'));
    return new Response(renderReport(report), {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
      },
    });
  } catch (error) {
    return new Response(`Call report is unavailable: ${error.message}`, { status: 503, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  }
}
