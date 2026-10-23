import { cookie, exists, r, type Signature } from '../signature';

const SEMVER_TAIL = String.raw`(\d+(?:\.\d+)+[a-z]?)`;

function serverBanner(prefix: string, flags = 'i'): RegExp {
  return new RegExp(String.raw`^${prefix}(?:\/${SEMVER_TAIL})?(?:[\s(;]|$)`, flags);
}

export const infrastructureSignatures: Signature[] = [
  // ─────────── Web servers ───────────
  {
    id: 'nginx',
    name: 'Nginx',
    categories: ['web-server'],
    website: 'https://nginx.org',
    cpe: ['f5:nginx', 'nginx:nginx'],
    rules: { headers: { server: [r(serverBanner('nginx'), { version: '$1' })] } },
  },
  {
    id: 'apache-httpd',
    name: 'Apache HTTP Server',
    categories: ['web-server'],
    website: 'https://httpd.apache.org',
    cpe: ['apache:http_server'],
    rules: { headers: { server: [r(serverBanner('Apache'), { version: '$1' })] } },
  },
  {
    id: 'iis',
    name: 'Microsoft IIS',
    categories: ['web-server'],
    website: 'https://www.iis.net',
    cpe: ['microsoft:internet_information_services'],
    implies: ['windows-server'],
    rules: { headers: { server: [r(serverBanner('Microsoft-IIS'), { version: '$1' })] } },
  },
  {
    id: 'litespeed',
    name: 'LiteSpeed',
    categories: ['web-server'],
    website: 'https://www.litespeedtech.com',
    cpe: ['litespeedtech:litespeed_web_server'],
    rules: {
      headers: { server: [r(serverBanner('LiteSpeed'), { version: '$1' })], 'x-litespeed-cache': [exists()] },
    },
  },
  {
    id: 'openresty',
    name: 'OpenResty',
    categories: ['web-server'],
    website: 'https://openresty.org',
    cpe: ['openresty:openresty'],
    implies: ['nginx'],
    rules: { headers: { server: [r(serverBanner('openresty'), { version: '$1' })] } },
  },
  {
    id: 'caddy',
    name: 'Caddy',
    categories: ['web-server'],
    website: 'https://caddyserver.com',
    cpe: ['caddyserver:caddy'],
    rules: { headers: { server: [r(/^Caddy$/i)] } },
  },
  {
    id: 'tomcat',
    name: 'Apache Tomcat',
    categories: ['web-server'],
    website: 'https://tomcat.apache.org',
    cpe: ['apache:tomcat'],
    implies: ['java'],
    rules: {
      headers: { server: [r(/^Apache-Coyote\/\d/, { confidence: 75 })] },
      html: [r(/<h3>Apache Tomcat\/(\d+(?:\.\d+)+)<\/h3>/, { version: '$1' })],
    },
  },
  {
    id: 'jetty',
    name: 'Jetty',
    categories: ['web-server'],
    website: 'https://jetty.org',
    cpe: ['eclipse:jetty'],
    implies: ['java'],
    rules: { headers: { server: [r(/^Jetty\((\d+(?:\.\d+)+)/, { version: '$1' }), r(/^Jetty/)] } },
  },
  {
    id: 'gunicorn',
    name: 'Gunicorn',
    categories: ['web-server'],
    website: 'https://gunicorn.org',
    cpe: ['gunicorn:gunicorn'],
    implies: ['python'],
    rules: { headers: { server: [r(serverBanner('gunicorn'), { version: '$1' })] } },
  },
  {
    id: 'envoy',
    name: 'Envoy',
    categories: ['web-server'],
    website: 'https://www.envoyproxy.io',
    rules: { headers: { server: [r(/^envoy$/i)], 'x-envoy-upstream-service-time': [exists()] } },
  },
  {
    id: 'kestrel',
    name: 'Kestrel',
    categories: ['web-server'],
    website: 'https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel',
    implies: ['aspnet'],
    rules: { headers: { server: [r(/^Kestrel$/i)] } },
  },
  {
    id: 'passenger',
    name: 'Phusion Passenger',
    categories: ['web-server'],
    website: 'https://www.phusionpassenger.com',
    cpe: ['phusion:passenger'],
    rules: {
      headers: {
        server: [r(/Phusion[ _]Passenger(?:\/(\d+(?:\.\d+)+))?/, { version: '$1' })],
        'x-powered-by': [r(/Phusion[ _]Passenger(?:\/(\d+(?:\.\d+)+))?/, { version: '$1' })],
      },
    },
  },
  {
    id: 'windows-server',
    name: 'Windows Server',
    categories: ['web-server'],
    website: 'https://www.microsoft.com/windows-server',
    rules: {},
  },

  // ─────────── Caching ───────────
  {
    id: 'varnish',
    name: 'Varnish',
    categories: ['cache'],
    website: 'https://varnish-cache.org',
    cpe: ['varnish-cache:varnish'],
    rules: {
      headers: {
        via: [r(/varnish(?: \(Varnish\/(\d+(?:\.\d+)+)\))?/i, { version: '$1' })],
        'x-varnish': [exists(75)],
      },
    },
  },

  // ─────────── CDN ───────────
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    categories: ['cdn'],
    website: 'https://www.cloudflare.com',
    rules: {
      headers: { server: [r(/^cloudflare$/i)], 'cf-ray': [exists()], 'cf-cache-status': [exists()] },
      scriptSrc: [r(/\/cdn-cgi\/(?:scripts|challenge-platform|rum|zaraz)\//, { confidence: 75 })],
      cookies: [cookie(/^__cflb$/), cookie(/^__cfruid$/)],
    },
  },
  {
    id: 'cloudfront',
    name: 'Amazon CloudFront',
    categories: ['cdn'],
    website: 'https://aws.amazon.com/cloudfront/',
    rules: {
      headers: {
        via: [r(/\(CloudFront\)/)],
        'x-amz-cf-id': [exists()],
        'x-amz-cf-pop': [exists()],
        'x-cache': [r(/ from cloudfront$/i)],
      },
    },
  },
  {
    id: 'fastly',
    name: 'Fastly',
    categories: ['cdn'],
    website: 'https://www.fastly.com',
    rules: {
      headers: {
        'x-fastly-request-id': [exists()],
        'fastly-debug-digest': [exists()],
        'x-served-by': [r(/^cache-[a-z0-9-]+(?:,|$)/, { confidence: 50 })],
      },
    },
  },
  {
    id: 'akamai',
    name: 'Akamai',
    categories: ['cdn'],
    website: 'https://www.akamai.com',
    rules: {
      headers: {
        server: [r(/^AkamaiGHost$/i), r(/^AkamaiNetStorage$/i)],
        'x-akamai-transformed': [exists()],
        'akamai-grn': [exists()],
        'x-akamai-request-id': [exists()],
      },
    },
  },
  {
    id: 'bunnycdn',
    name: 'Bunny CDN',
    categories: ['cdn'],
    website: 'https://bunny.net',
    rules: { headers: { server: [r(/^BunnyCDN/i)], 'cdn-pullzone': [exists()] } },
  },
  {
    id: 'keycdn',
    name: 'KeyCDN',
    categories: ['cdn'],
    website: 'https://www.keycdn.com',
    rules: { headers: { server: [r(/^keycdn-engine$/i)] } },
  },
  {
    id: 'azure-front-door',
    name: 'Azure Front Door',
    categories: ['cdn'],
    website: 'https://azure.microsoft.com/products/frontdoor',
    rules: { headers: { 'x-azure-ref': [exists()] } },
  },
  {
    id: 'jsdelivr',
    name: 'jsDelivr',
    categories: ['cdn'],
    website: 'https://www.jsdelivr.com',
    rules: { scriptSrc: [r(/\/\/(?:cdn|fastly|gcore)\.jsdelivr\.net\//)], stylesheet: [r(/\/\/cdn\.jsdelivr\.net\//)] },
  },
  {
    id: 'cdnjs',
    name: 'cdnjs',
    categories: ['cdn'],
    website: 'https://cdnjs.com',
    rules: { scriptSrc: [r(/\/\/cdnjs\.cloudflare\.com\//)], stylesheet: [r(/\/\/cdnjs\.cloudflare\.com\//)] },
  },
  {
    id: 'unpkg',
    name: 'UNPKG',
    categories: ['cdn'],
    website: 'https://unpkg.com',
    rules: { scriptSrc: [r(/\/\/unpkg\.com\//)], stylesheet: [r(/\/\/unpkg\.com\//)] },
  },
  {
    id: 'google-hosted-libraries',
    name: 'Google Hosted Libraries',
    categories: ['cdn'],
    website: 'https://developers.google.com/speed/libraries',
    rules: { scriptSrc: [r(/\/\/ajax\.googleapis\.com\/ajax\/libs\//)] },
  },

  // ─────────── WAF / bot protection ───────────
  {
    id: 'cloudflare-bot-management',
    name: 'Cloudflare Bot Management',
    categories: ['waf'],
    website: 'https://www.cloudflare.com/application-services/products/bot-management/',
    implies: ['cloudflare'],
    rules: {
      cookies: [cookie(/^__cf_bm$/), cookie(/^cf_clearance$/)],
      scriptSrc: [r(/\/cdn-cgi\/challenge-platform\//)],
    },
  },
  {
    id: 'cloudflare-turnstile',
    name: 'Cloudflare Turnstile',
    categories: ['security'],
    website: 'https://www.cloudflare.com/products/turnstile/',
    rules: { scriptSrc: [r(/\/\/challenges\.cloudflare\.com\/turnstile\//)] },
  },
  {
    id: 'sucuri',
    name: 'Sucuri WAF',
    categories: ['waf'],
    website: 'https://sucuri.net/website-firewall/',
    rules: {
      headers: { server: [r(/^Sucuri\/Cloudproxy$/i)], 'x-sucuri-id': [exists()], 'x-sucuri-cache': [exists()] },
    },
  },
  {
    id: 'imperva',
    name: 'Imperva Incapsula',
    categories: ['waf', 'cdn'],
    website: 'https://www.imperva.com',
    rules: {
      cookies: [cookie(/^incap_ses_/), cookie(/^visid_incap_/), cookie(/^nlbi_/)],
      headers: { 'x-iinfo': [exists()], 'x-cdn': [r(/Incapsula|Imperva/i)] },
    },
  },
  {
    id: 'akamai-bot-manager',
    name: 'Akamai Bot Manager',
    categories: ['waf'],
    website: 'https://www.akamai.com/products/bot-manager',
    rules: { cookies: [cookie(/^ak_bmsc$/), cookie(/^bm_sv$/), cookie(/^_abck$/)] },
  },
  {
    id: 'aws-waf',
    name: 'AWS WAF',
    categories: ['waf'],
    website: 'https://aws.amazon.com/waf/',
    rules: {
      cookies: [cookie(/^aws-waf-token$/)],
      scriptSrc: [r(/\.token\.awswaf\.com\//), r(/\.captcha\.awswaf\.com\//)],
    },
  },
  {
    id: 'f5-bigip',
    name: 'F5 BIG-IP',
    categories: ['waf'],
    website: 'https://www.f5.com/products/big-ip-services',
    rules: {
      cookies: [cookie(/^BIGipServer/), cookie(/^F5_ST$/), cookie(/^TS[0-9a-f]{8}$/, 50)],
      headers: { server: [r(/^BigIP$/i)] },
    },
  },
  {
    id: 'datadome',
    name: 'DataDome',
    categories: ['waf'],
    website: 'https://datadome.co',
    rules: {
      cookies: [cookie(/^datadome$/)],
      headers: { 'x-datadome': [exists()], 'x-datadome-cid': [exists()] },
      scriptSrc: [r(/\/\/js\.datadome\.co\//)],
    },
  },
  {
    id: 'perimeterx',
    name: 'HUMAN (PerimeterX)',
    categories: ['waf'],
    website: 'https://www.humansecurity.com',
    rules: { cookies: [cookie(/^_px[23]$/), cookie(/^_pxvid$/), cookie(/^_pxhd$/)] },
  },
  {
    id: 'barracuda',
    name: 'Barracuda WAF',
    categories: ['waf'],
    website: 'https://www.barracuda.com/products/application-protection',
    rules: { cookies: [cookie(/^barra_counter_session$/), cookie(/^BNI__BARRACUDA_LB_COOKIE$/)] },
  },
  {
    id: 'wordfence',
    name: 'Wordfence',
    categories: ['waf'],
    website: 'https://www.wordfence.com',
    implies: ['wordpress'],
    rules: {
      cookies: [cookie(/^wfwaf-authcookie-/)],
      scriptSrc: [r(/\/plugins\/wordfence\//)],
    },
  },
  {
    id: 'recaptcha',
    name: 'reCAPTCHA',
    categories: ['security'],
    website: 'https://www.google.com/recaptcha/',
    rules: {
      scriptSrc: [r(/\/\/www\.(?:google|gstatic|recaptcha)\.(?:com|net)\/recaptcha\//)],
      globals: { grecaptcha: [exists(75)] },
    },
  },
  {
    id: 'hcaptcha',
    name: 'hCaptcha',
    categories: ['security'],
    website: 'https://www.hcaptcha.com',
    rules: { scriptSrc: [r(/\/\/(?:js\.)?hcaptcha\.com\/1\/api\.js/)], globals: { hcaptcha: [exists(75)] } },
  },

  // ─────────── Hosting / PaaS ───────────
  {
    id: 'vercel',
    name: 'Vercel',
    categories: ['paas'],
    website: 'https://vercel.com',
    rules: { headers: { server: [r(/^Vercel$/i)], 'x-vercel-id': [exists()], 'x-vercel-cache': [exists()] } },
  },
  {
    id: 'netlify',
    name: 'Netlify',
    categories: ['paas'],
    website: 'https://www.netlify.com',
    rules: { headers: { server: [r(/^Netlify$/i)], 'x-nf-request-id': [exists()] } },
  },
  {
    id: 'github-pages',
    name: 'GitHub Pages',
    categories: ['paas'],
    website: 'https://pages.github.com',
    rules: { headers: { server: [r(/^GitHub\.com$/i)], 'x-github-request-id': [exists(50)] } },
  },
  {
    id: 'heroku',
    name: 'Heroku',
    categories: ['paas'],
    website: 'https://www.heroku.com',
    rules: { headers: { via: [r(/\bvegur\b/i)], 'heroku-edge': [exists()], 'nel': [r(/heroku/i, { confidence: 50 })] } },
  },
  {
    id: 'amazon-s3',
    name: 'Amazon S3',
    categories: ['paas'],
    website: 'https://aws.amazon.com/s3/',
    rules: { headers: { server: [r(/^AmazonS3$/i)], 'x-amz-bucket-region': [exists()] } },
  },
  {
    id: 'google-cloud',
    name: 'Google Cloud',
    categories: ['paas'],
    website: 'https://cloud.google.com',
    rules: { headers: { server: [r(/^Google Frontend$/i)], via: [r(/^1\.1 google$/i, { confidence: 75 })] } },
  },
  {
    id: 'firebase-hosting',
    name: 'Firebase Hosting',
    categories: ['paas'],
    website: 'https://firebase.google.com/products/hosting',
    rules: { headers: { 'x-firebase-hosting': [exists()] }, scriptSrc: [r(/\/__\/firebase\/(\d+(?:\.\d+)+)\//)] },
  },
];
