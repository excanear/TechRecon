import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

// Local multi-page test site. Deliberately "dated" so version-based correlation has something to
// find (jQuery 3.4.1, WordPress 6.4.2, nginx/1.18.0) and linked across several pages so the
// crawler has a graph to traverse. Includes a /logout link the crawler must never follow.

const HEAD = `<meta charset="utf-8">
  <meta name="generator" content="WordPress 6.4.2">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'">
  <link rel="https://api.w.org/" href="/wp-json/">
  <link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2">
  <script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.2"></script>
  <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.4.1"></script>
  <script>window.jQuery = { fn: { jquery: '3.4.1' } }; document.cookie = '_ga=GA1.1.123456.789; path=/';</script>`;

function page(title: string, links: string[]): string {
  const nav = links.map((l) => `<a href="${l}">${l}</a>`).join(' ');
  return `<!doctype html><html lang="en"><head><title>${title}</title>${HEAD}</head><body><h1>${title}</h1><nav>${nav}</nav></body></html>`;
}

const ROUTES: Record<string, { title: string; links: string[] }> = {
  '/': { title: 'Home', links: ['/about', '/products', '/contact', '/logout'] },
  '/about': { title: 'About', links: ['/', '/team'] },
  '/team': { title: 'Team', links: ['/about'] },
  '/products': { title: 'Products', links: ['/products/widget', '/'] },
  '/products/widget': { title: 'Widget', links: ['/products'] },
  '/contact': { title: 'Contact', links: ['/'] },
};

export async function startServer(): Promise<{ url: string; server: Server; requests: string[] }> {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0]!;
    requests.push(`${req.method} ${req.url}`);
    const common = { Server: 'nginx/1.18.0 (Ubuntu)', 'X-Powered-By': 'PHP/7.4.3', 'X-Content-Type-Options': 'nosniff' };
    if (path.startsWith('/wp-includes/')) {
      res.writeHead(200, { ...common, 'Content-Type': path.includes('.css') ? 'text/css' : 'text/javascript' });
      res.end('');
      return;
    }
    if (path === '/logout') {
      // If the crawler ever hits this, the test fails — but respond anyway.
      res.writeHead(200, { ...common, 'Content-Type': 'text/html' });
      res.end(page('Logged out', ['/']));
      return;
    }
    const route = ROUTES[path];
    if (!route) {
      res.writeHead(404, { ...common, 'Content-Type': 'text/html' });
      res.end(page('Not found', ['/']));
      return;
    }
    res.writeHead(200, { ...common, 'Content-Type': 'text/html; charset=utf-8' });
    res.end(page(route.title, route.links));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/`, server, requests };
}
