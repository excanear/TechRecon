import { cookie, exists, r, type Signature } from '../signature';

export const backendSignatures: Signature[] = [
  // ─────────── Languages / runtimes ───────────
  {
    id: 'php',
    name: 'PHP',
    categories: ['language'],
    website: 'https://www.php.net',
    cpe: ['php:php'],
    rules: {
      headers: {
        'x-powered-by': [r(/\bPHP\/(\d+(?:\.\d+)+)/i, { version: '$1' })],
        server: [r(/\bPHP\/(\d+(?:\.\d+)+)/i, { version: '$1' })],
      },
      cookies: [cookie(/^PHPSESSID$/)],
      url: [r(/\.php(?:[?#]|$)/, { confidence: 50 })],
    },
  },
  {
    id: 'aspnet',
    name: 'ASP.NET',
    categories: ['web-framework'],
    website: 'https://dotnet.microsoft.com/apps/aspnet',
    rules: {
      headers: {
        'x-powered-by': [r(/^ASP\.NET$/i)],
        // X-AspNet-Version reports the CLR version (e.g. 4.0.30319), not a product release: evidence only.
        'x-aspnet-version': [exists()],
        'x-aspnetmvc-version': [exists()],
      },
      cookies: [cookie(/^ASP\.NET_SessionId$/), cookie(/^\.ASPXAUTH$/), cookie(/^\.AspNetCore\./)],
      html: [r(/<input[^>]+name="__VIEWSTATE"/, { confidence: 100 })],
      url: [r(/\.aspx(?:[?#]|$)/, { confidence: 75 })],
    },
  },
  {
    id: 'blazor',
    name: 'Blazor',
    categories: ['web-framework'],
    website: 'https://dotnet.microsoft.com/apps/aspnet/web-apps/blazor',
    implies: ['aspnet'],
    rules: { scriptSrc: [r(/\/_framework\/blazor\.(?:web|server|webassembly)\.js/)] },
  },
  {
    id: 'java',
    name: 'Java',
    categories: ['language'],
    website: 'https://www.java.com',
    rules: { cookies: [cookie(/^JSESSIONID$/, 75)], url: [r(/\.(?:jsp|do|jsf)(?:[?#;]|$)/, { confidence: 50 })] },
  },
  { id: 'python', name: 'Python', categories: ['language'], website: 'https://www.python.org', rules: {} },
  { id: 'ruby', name: 'Ruby', categories: ['language'], website: 'https://www.ruby-lang.org', rules: {} },
  { id: 'nodejs', name: 'Node.js', categories: ['language'], website: 'https://nodejs.org', rules: {} },

  // ─────────── Web frameworks ───────────
  {
    id: 'express',
    name: 'Express',
    categories: ['web-framework'],
    website: 'https://expressjs.com',
    npm: 'express',
    implies: ['nodejs'],
    rules: { headers: { 'x-powered-by': [r(/^Express$/i)] } },
  },
  {
    id: 'laravel',
    name: 'Laravel',
    categories: ['web-framework'],
    website: 'https://laravel.com',
    implies: ['php'],
    rules: { cookies: [cookie(/^laravel_session$/)] },
  },
  {
    id: 'codeigniter',
    name: 'CodeIgniter',
    categories: ['web-framework'],
    website: 'https://codeigniter.com',
    implies: ['php'],
    rules: { cookies: [cookie(/^ci_session$/)] },
  },
  {
    id: 'django',
    name: 'Django',
    categories: ['web-framework'],
    website: 'https://www.djangoproject.com',
    implies: ['python'],
    rules: {
      html: [r(/<input[^>]+name=["']csrfmiddlewaretoken["']/, { confidence: 100 })],
      cookies: [cookie(/^django_language$/), cookie(/^csrftoken$/, 50)],
    },
  },
  {
    id: 'rails',
    name: 'Ruby on Rails',
    categories: ['web-framework'],
    website: 'https://rubyonrails.org',
    implies: ['ruby'],
    rules: {
      meta: { 'csrf-param': [r(/^authenticity_token$/, { confidence: 75 })] },
      cookies: [cookie(/^_[a-z0-9_]+_session$/, 25)],
      scriptSrc: [r(/\/assets\/(?:application|rails-ujs)-[0-9a-f]{32,64}\.js/, { confidence: 50 })],
    },
  },
  {
    id: 'flask',
    name: 'Flask',
    categories: ['web-framework'],
    website: 'https://flask.palletsprojects.com',
    implies: ['python'],
    rules: { headers: { server: [r(/^Werkzeug(?:\/(\d+(?:\.\d+)+))?/i, { confidence: 75 })] } },
  },
  {
    id: 'spring',
    name: 'Spring',
    categories: ['web-framework'],
    website: 'https://spring.io',
    implies: ['java'],
    rules: { headers: { 'x-application-context': [exists(75)] } },
  },
];
