import fs from 'node:fs';
import path from 'node:path';
import Script from 'next/script';

export const dynamic = 'force-static';

function landingBody() {
  const source = fs.readFileSync(path.join(process.cwd(), 'site', 'index.html'), 'utf8');
  const body = source.match(/<body>([\s\S]*?)<\/body>/i)?.[1] ?? '';
  return body.replaceAll('./index.html', '/');
}

export default function HomePage() {
  return (
    <>
      <link rel="stylesheet" href="/legacy/landing.css" />
      <div dangerouslySetInnerHTML={{ __html: landingBody() }} />
      <Script src="/legacy/landing.js" strategy="afterInteractive" />
    </>
  );
}
