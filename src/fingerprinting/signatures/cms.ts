import { cookie, exists, r, type Signature } from '../signature';
import { VERSION_VALUE } from './javascript';

export const cmsSignatures: Signature[] = [
  {
    id: 'wordpress',
    name: 'WordPress',
    categories: ['cms'],
    website: 'https://wordpress.org',
    cpe: ['wordpress:wordpress'],
    implies: ['php'],
    rules: {
      meta: { generator: [r(/^WordPress(?: (\d+(?:\.\d+)+))?/, { version: '$1' })] },
      html: [
        r(/<link[^>]+rel=["']https:\/\/api\.w\.org\/["']/, { confidence: 100 }),
        r(/\/wp-(?:content|includes)\//, { confidence: 75 }),
      ],
      scriptSrc: [
        // Core assets carry the core version in ?ver= (plugins/themes use their own versions, so only core files count).
        r(/\/wp-includes\/js\/wp-emoji-release\.min\.js\?ver=(\d+(?:\.\d+)+)/, { version: '$1' }),
        r(/\/wp-includes\/js\/(?:comment-reply|wp-embed)(?:\.min)?\.js\?ver=(\d+(?:\.\d+)+)/, { version: '$1' }),
        r(/\/wp-includes\//, { confidence: 75 }),
        r(/\/wp-content\//, { confidence: 50 }),
      ],
      stylesheet: [
        r(/\/wp-includes\/css\/dist\/block-library\/style(?:\.min)?\.css\?ver=(\d+(?:\.\d+)+)/, { version: '$1' }),
        r(/\/wp-content\//, { confidence: 50 }),
      ],
      headers: {
        link: [r(/rel="https:\/\/api\.w\.org\/"/, { confidence: 100 })],
        'x-pingback': [r(/\/xmlrpc\.php$/, { confidence: 100 })],
      },
    },
  },
  {
    id: 'woocommerce',
    name: 'WooCommerce',
    categories: ['ecommerce'],
    website: 'https://woocommerce.com',
    cpe: ['woocommerce:woocommerce'],
    implies: ['wordpress'],
    rules: {
      meta: { generator: [r(/^WooCommerce (\d+(?:\.\d+)+)/, { version: '$1' })] },
      scriptSrc: [
        r(/\/plugins\/woocommerce\/assets\/js\/.+\?ver=(\d+(?:\.\d+)+)/, { version: '$1', confidence: 100 }),
        r(/\/plugins\/woocommerce\//, { confidence: 100 }),
      ],
      stylesheet: [r(/\/plugins\/woocommerce\//, { confidence: 100 })],
      globals: { woocommerce_params: [exists()], wc_add_to_cart_params: [exists()] },
    },
  },
  {
    id: 'drupal',
    name: 'Drupal',
    categories: ['cms'],
    website: 'https://www.drupal.org',
    cpe: ['drupal:drupal'],
    implies: ['php'],
    rules: {
      // Drupal's generator meta exposes only the major version ("Drupal 10"), which is not exact.
      meta: { generator: [r(/^Drupal (\d+(?:\.\d+)*)/, { version: '$1' })] },
      headers: {
        'x-generator': [r(/^Drupal (\d+(?:\.\d+)*)/, { version: '$1' })],
        'x-drupal-cache': [exists()],
        'x-drupal-dynamic-cache': [exists()],
      },
      globals: { Drupal: [exists(75)], drupalSettings: [exists()] },
      scriptSrc: [r(/\/(?:core\/misc|misc)\/drupal\.js/, { confidence: 100 })],
      html: [r(/<script[^>]+data-drupal-selector="drupal-settings-json"/, { confidence: 100 })],
    },
  },
  {
    id: 'joomla',
    name: 'Joomla',
    categories: ['cms'],
    website: 'https://www.joomla.org',
    cpe: ['joomla:joomla\\!'],
    implies: ['php'],
    rules: {
      meta: { generator: [r(/^Joomla!(?: - Open Source Content Management)?(?: - Version (\d+(?:\.\d+)+))?/, { version: '$1' })] },
      globals: { Joomla: [exists(75)] },
      scriptSrc: [r(/\/media\/(?:system|jui)\/js\//, { confidence: 75 })],
      html: [r(/<script[^>]+class="joomla-script-options/, { confidence: 100 })],
    },
  },
  {
    id: 'magento',
    name: 'Magento',
    categories: ['ecommerce'],
    website: 'https://business.adobe.com/products/magento/magento-commerce.html',
    implies: ['php'],
    rules: {
      cookies: [cookie(/^X-Magento-Vary$/), cookie(/^mage-cache-(?:storage|sessid)$/)],
      globals: { Mage: [exists(75)], 'require.s.contexts._.config.paths.mage': [exists(50)] },
      html: [r(/\/static\/(?:version\d+\/)?frontend\/[^/]+\/[^/]+\/[a-z]{2}_[A-Z]{2}\//, { confidence: 100 }), r(/Mage\.Cookies\./, { confidence: 100 })],
      headers: { 'x-magento-tags': [exists()], 'x-magento-cache-debug': [exists()] },
    },
  },
  {
    id: 'shopify',
    name: 'Shopify',
    categories: ['ecommerce'],
    website: 'https://www.shopify.com',
    rules: {
      globals: { Shopify: [exists(75)], 'Shopify.shop': [exists()] },
      html: [r(/\/\/cdn\.shopify\.com\//, { confidence: 75 })],
      scriptSrc: [r(/\/\/cdn\.shopify\.com\//, { confidence: 75 })],
      cookies: [cookie(/^_shopify_[ys]$/), cookie(/^_secure_session_id$/, 25)],
      headers: { 'x-shopid': [exists()], 'x-shopify-stage': [exists()], 'powered-by': [r(/Shopify/)] },
    },
  },
  {
    id: 'prestashop',
    name: 'PrestaShop',
    categories: ['ecommerce'],
    website: 'https://www.prestashop.com',
    cpe: ['prestashop:prestashop'],
    implies: ['php'],
    rules: {
      globals: { prestashop: [exists()], 'prestashop.version': [r(VERSION_VALUE, { version: '$1' })] },
      meta: { generator: [r(/^PrestaShop/)] },
      headers: { 'powered-by': [r(/PrestaShop/)] },
    },
  },
  {
    id: 'wix',
    name: 'Wix',
    categories: ['cms'],
    website: 'https://www.wix.com',
    rules: {
      meta: { generator: [r(/^Wix\.com Website Builder/)] },
      html: [r(/\/\/static\.(?:wixstatic|parastorage)\.com\//, { confidence: 75 })],
      headers: { 'x-wix-request-id': [exists()] },
    },
  },
  {
    id: 'squarespace',
    name: 'Squarespace',
    categories: ['cms'],
    website: 'https://www.squarespace.com',
    rules: {
      globals: { 'Static.SQUARESPACE_CONTEXT': [exists()] },
      html: [r(/\/\/(?:static1|assets)\.squarespace\.com\//, { confidence: 75 })],
      headers: { server: [r(/^Squarespace$/)] },
    },
  },
  {
    id: 'webflow',
    name: 'Webflow',
    categories: ['cms'],
    website: 'https://webflow.com',
    rules: {
      meta: { generator: [r(/^Webflow$/)] },
      html: [r(/<html[^>]+data-wf-(?:page|site)=/, { confidence: 100 })],
      globals: { Webflow: [exists(75)] },
    },
  },
  {
    id: 'ghost',
    name: 'Ghost',
    categories: ['cms'],
    website: 'https://ghost.org',
    cpe: ['ghost:ghost'],
    implies: ['nodejs'],
    rules: {
      meta: { generator: [r(/^Ghost (\d+(?:\.\d+)+)/, { version: '$1' })] },
      headers: { 'x-ghost-cache-status': [exists()] },
    },
  },
  {
    id: 'typo3',
    name: 'TYPO3',
    categories: ['cms'],
    website: 'https://typo3.org',
    cpe: ['typo3:typo3'],
    implies: ['php'],
    rules: {
      meta: { generator: [r(/^TYPO3(?: (\d+(?:\.\d+)*))? CMS/, { version: '$1' })] },
      html: [r(/\/typo3(?:conf|temp)\//, { confidence: 75 })],
    },
  },
  {
    id: 'hubspot-cms',
    name: 'HubSpot CMS',
    categories: ['cms'],
    website: 'https://www.hubspot.com/products/cms',
    rules: {
      meta: { generator: [r(/^HubSpot$/)] },
      headers: { 'x-hs-hub-id': [exists()] },
    },
  },
  {
    id: 'hugo',
    name: 'Hugo',
    categories: ['ssg'],
    website: 'https://gohugo.io',
    rules: { meta: { generator: [r(/^Hugo (\d+(?:\.\d+)+)/, { version: '$1' })] } },
  },
  {
    id: 'jekyll',
    name: 'Jekyll',
    categories: ['ssg'],
    website: 'https://jekyllrb.com',
    implies: ['ruby'],
    rules: {
      meta: { generator: [r(/^Jekyll v?(\d+(?:\.\d+)+)/, { version: '$1' })] },
      html: [r(/<!-- Begin Jekyll SEO tag v(\d+(?:\.\d+)+)/, { confidence: 75 })],
    },
  },
  {
    id: 'docusaurus',
    name: 'Docusaurus',
    categories: ['ssg'],
    website: 'https://docusaurus.io',
    npm: '@docusaurus/core',
    implies: ['react'],
    rules: {
      meta: { generator: [r(/^Docusaurus v?(\d+(?:\.\d+)+)/, { version: '$1' })] },
      globals: { docusaurus: [exists()] },
    },
  },
];
