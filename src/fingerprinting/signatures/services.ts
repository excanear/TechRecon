import { cookie, exists, r, type Signature } from '../signature';
import { VERSION_VALUE } from './javascript';

export const serviceSignatures: Signature[] = [
  // ─────────── Analytics ───────────
  {
    id: 'google-analytics',
    name: 'Google Analytics',
    categories: ['analytics'],
    website: 'https://marketingplatform.google.com/about/analytics/',
    rules: {
      scriptSrc: [
        r(/\/\/www\.google-analytics\.com\/(?:analytics|ga)\.js/),
        r(/\/\/www\.googletagmanager\.com\/gtag\/js\?id=(?:G|UA)-/),
      ],
      globals: { GoogleAnalyticsObject: [exists()], gaGlobal: [exists(75)] },
      cookies: [cookie(/^_ga$/, 75), cookie(/^_ga_[A-Z0-9]+$/), cookie(/^_gid$/, 50)],
    },
  },
  {
    id: 'google-tag-manager',
    name: 'Google Tag Manager',
    categories: ['tag-manager'],
    website: 'https://tagmanager.google.com',
    rules: {
      scriptSrc: [r(/\/\/www\.googletagmanager\.com\/gtm\.js/)],
      globals: { google_tag_manager: [exists()] },
      html: [r(/\/\/www\.googletagmanager\.com\/ns\.html\?id=GTM-/, { confidence: 100 })],
    },
  },
  {
    id: 'adobe-launch',
    name: 'Adobe Experience Platform Tags',
    categories: ['tag-manager'],
    website: 'https://experienceleague.adobe.com/docs/experience-platform/tags/home.html',
    rules: { scriptSrc: [r(/\/\/assets\.adobedtm\.com\//)], globals: { _satellite: [exists()] } },
  },
  {
    id: 'tealium',
    name: 'Tealium iQ',
    categories: ['tag-manager'],
    website: 'https://tealium.com',
    rules: { scriptSrc: [r(/\/\/tags\.tiqcdn\.com\/utag\//)], globals: { utag: [exists(75)] } },
  },
  {
    id: 'hotjar',
    name: 'Hotjar',
    categories: ['analytics'],
    website: 'https://www.hotjar.com',
    rules: { scriptSrc: [r(/\/\/static\.hotjar\.com\//)], globals: { hjSiteSettings: [exists()], hj: [exists(25)] } },
  },
  {
    id: 'matomo',
    name: 'Matomo',
    categories: ['analytics'],
    website: 'https://matomo.org',
    cpe: ['matomo:matomo'],
    rules: {
      scriptSrc: [r(/\/(?:matomo|piwik)\.js(?:[?#]|$)/, { confidence: 75 })],
      globals: { Matomo: [exists()], Piwik: [exists()] },
      cookies: [cookie(/^_pk_id\./), cookie(/^_pk_ses\./)],
    },
  },
  {
    id: 'plausible',
    name: 'Plausible',
    categories: ['analytics'],
    website: 'https://plausible.io',
    rules: { scriptSrc: [r(/\/\/plausible\.io\/js\//)], globals: { plausible: [exists(50)] } },
  },
  {
    id: 'segment',
    name: 'Segment',
    categories: ['analytics'],
    website: 'https://segment.com',
    rules: {
      scriptSrc: [r(/\/\/cdn\.segment\.com\/analytics\.js\//)],
      globals: { 'analytics.VERSION': [r(VERSION_VALUE, { confidence: 25 })] },
      cookies: [cookie(/^ajs_anonymous_id$/)],
    },
  },
  {
    id: 'mixpanel',
    name: 'Mixpanel',
    categories: ['analytics'],
    website: 'https://mixpanel.com',
    rules: { scriptSrc: [r(/\/\/cdn(?:4)?\.mxpnl\.com\//), r(/\/\/cdn\.mixpanel\.com\//)], globals: { 'mixpanel.__loaded': [exists()] } },
  },
  {
    id: 'facebook-pixel',
    name: 'Meta Pixel',
    categories: ['analytics'],
    website: 'https://www.facebook.com/business/tools/meta-pixel',
    rules: { scriptSrc: [r(/\/\/connect\.facebook\.net\/[^/]+\/fbevents\.js/)], globals: { _fbq: [exists(75)] }, cookies: [cookie(/^_fbp$/)] },
  },
  {
    id: 'clarity',
    name: 'Microsoft Clarity',
    categories: ['analytics'],
    website: 'https://clarity.microsoft.com',
    rules: { scriptSrc: [r(/\/\/www\.clarity\.ms\/(?:tag|s)\//)], cookies: [cookie(/^_clck$/), cookie(/^_clsk$/)] },
  },
  {
    id: 'cloudflare-web-analytics',
    name: 'Cloudflare Web Analytics',
    categories: ['analytics'],
    website: 'https://www.cloudflare.com/web-analytics/',
    rules: { scriptSrc: [r(/\/\/static\.cloudflareinsights\.com\/beacon(?:\.min)?\.js/)] },
  },
  {
    id: 'yandex-metrika',
    name: 'Yandex Metrica',
    categories: ['analytics'],
    website: 'https://metrica.yandex.com',
    rules: { scriptSrc: [r(/\/\/mc\.yandex\.(?:ru|com)\/metrika\//)], cookies: [cookie(/^_ym_uid$/)] },
  },

  // ─────────── Monitoring / RUM ───────────
  {
    id: 'new-relic',
    name: 'New Relic',
    categories: ['monitoring'],
    website: 'https://newrelic.com',
    rules: { globals: { NREUM: [exists()], newrelic: [exists(75)] }, scriptSrc: [r(/\/\/js-agent\.newrelic\.com\//)] },
  },
  {
    id: 'sentry',
    name: 'Sentry',
    categories: ['monitoring'],
    website: 'https://sentry.io',
    npm: '@sentry/browser',
    rules: {
      globals: { __SENTRY__: [exists()], 'Sentry.SDK_VERSION': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [r(/\/\/browser\.sentry-cdn\.com\/(\d+(?:\.\d+)+)\//, { version: '$1' }), r(/\/\/js\.sentry-cdn\.com\//)],
    },
  },
  {
    id: 'datadog-rum',
    name: 'Datadog RUM',
    categories: ['monitoring'],
    website: 'https://www.datadoghq.com/product/real-user-monitoring/',
    rules: { globals: { DD_RUM: [exists()], 'DD_RUM.version': [r(VERSION_VALUE, { version: '$1' })] }, scriptSrc: [r(/\/\/www\.datadoghq-browser-agent\.com\//)] },
  },

  // ─────────── Payments ───────────
  {
    id: 'stripe',
    name: 'Stripe',
    categories: ['payment'],
    website: 'https://stripe.com',
    rules: { scriptSrc: [r(/\/\/js\.stripe\.com\/(?:v\d|basil|acacia|clover)\//), r(/\/\/js\.stripe\.com\//, { confidence: 75 })], globals: { Stripe: [exists(50)] } },
  },
  {
    id: 'paypal',
    name: 'PayPal',
    categories: ['payment'],
    website: 'https://www.paypal.com',
    rules: { scriptSrc: [r(/\/\/www\.paypal\.com\/sdk\/js/), r(/\/\/www\.paypalobjects\.com\//, { confidence: 75 })], globals: { paypal: [exists(50)] } },
  },

  // ─────────── Widgets / marketing ───────────
  {
    id: 'intercom',
    name: 'Intercom',
    categories: ['widget'],
    website: 'https://www.intercom.com',
    rules: { scriptSrc: [r(/\/\/widget\.intercom\.io\//), r(/\/\/js\.intercomcdn\.com\//)], globals: { Intercom: [exists(75)] } },
  },
  {
    id: 'zendesk',
    name: 'Zendesk',
    categories: ['widget'],
    website: 'https://www.zendesk.com',
    rules: { scriptSrc: [r(/\/\/static\.zdassets\.com\//)], globals: { zE: [exists(50)] } },
  },
  {
    id: 'hubspot',
    name: 'HubSpot',
    categories: ['widget', 'analytics'],
    website: 'https://www.hubspot.com',
    rules: {
      scriptSrc: [r(/\/\/js\.hs-scripts\.com\//), r(/\/\/js\.hsforms\.net\//), r(/\/\/js\.hs-analytics\.net\//)],
      globals: { _hsq: [exists(75)] },
      cookies: [cookie(/^hubspotutk$/), cookie(/^__hstc$/)],
    },
  },
  {
    id: 'youtube-embed',
    name: 'YouTube',
    categories: ['widget'],
    website: 'https://www.youtube.com',
    rules: { html: [r(/<iframe[^>]+src=["'](?:https?:)?\/\/www\.youtube(?:-nocookie)?\.com\/embed\//, { confidence: 100 })] },
  },

  // ─────────── Consent ───────────
  {
    id: 'onetrust',
    name: 'OneTrust',
    categories: ['consent'],
    website: 'https://www.onetrust.com',
    rules: { scriptSrc: [r(/\/\/cdn(?:-ukwest)?\.cookielaw\.org\//)], globals: { OneTrust: [exists()] }, cookies: [cookie(/^OptanonConsent$/)] },
  },
  {
    id: 'cookiebot',
    name: 'Cookiebot',
    categories: ['consent'],
    website: 'https://www.cookiebot.com',
    rules: { scriptSrc: [r(/\/\/consent\.cookiebot\.(?:com|eu)\//)], globals: { Cookiebot: [exists()] }, cookies: [cookie(/^CookieConsent$/, 50)] },
  },

  // ─────────── Fonts ───────────
  {
    id: 'google-fonts',
    name: 'Google Fonts',
    categories: ['font'],
    website: 'https://fonts.google.com',
    rules: { stylesheet: [r(/\/\/fonts\.googleapis\.com\//)], resource: [r(/\/\/fonts\.gstatic\.com\//, { confidence: 75 })] },
  },
  {
    id: 'adobe-fonts',
    name: 'Adobe Fonts',
    categories: ['font'],
    website: 'https://fonts.adobe.com',
    rules: { stylesheet: [r(/\/\/use\.typekit\.net\//)], scriptSrc: [r(/\/\/use\.typekit\.net\//)] },
  },
  {
    id: 'font-awesome',
    name: 'Font Awesome',
    categories: ['font'],
    website: 'https://fontawesome.com',
    rules: {
      stylesheet: [
        r(/\/font-awesome\/(\d+(?:\.\d+)+)\/css\//, { version: '$1' }),
        r(/\/@fortawesome\/fontawesome-free@(\d+(?:\.\d+)+)\//, { version: '$1' }),
        r(/\/font-?awesome(?:\.min)?\.css/i, { confidence: 75 }),
        r(/\/\/use\.fontawesome\.com\//),
      ],
      scriptSrc: [r(/\/\/kit\.fontawesome\.com\//)],
    },
  },
];
