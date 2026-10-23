import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

// Local test site. It is deliberately "dated" so that version-based correlation has something to find:
// a jQuery 3.4.1 global, a WordPress 6.4.2 generator and an nginx/1.18.0 Server banner.
const PAGE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>TechRecon e2e fixture</title>
  <meta name="generator" content="WordPress 6.4.2">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'">
  <link rel="https://api.w.org/" href="/wp-json/">
  <link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2">
  <script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.2"></script>
  <script>
    window.jQuery = { fn: { jquery: '3.4.1' } };
    document.cookie = '_ga=GA1.1.123456.789; path=/';
  </script>
</head>
<body><h1>Fixture</h1></body>
</html>`;

export async function startServer(): Promise<{ url: string; server: Server; requests: string[] }> {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    const common = { Server: 'nginx/1.18.0 (Ubuntu)', 'X-Powered-By': 'PHP/7.4.3', 'X-Content-Type-Options': 'nosniff' };
    if (req.url?.startsWith('/wp-includes/')) {
      res.writeHead(200, { ...common, 'Content-Type': req.url.includes('.css') ? 'text/css' : 'text/javascript' });
      res.end('');
      return;
    }
    res.writeHead(200, { ...common, 'Content-Type': 'text/html; charset=utf-8' });
    res.end(PAGE);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/`, server, requests };
}
