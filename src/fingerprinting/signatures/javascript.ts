import { exists, r, versionOnly, type Signature } from '../signature';

/** A global holding a version string such as "3.7.1" or "v2.6.14". */
export const VERSION_VALUE = /^v?(\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.]+)?)$/;

export const javascriptSignatures: Signature[] = [
  // ─────────── Frameworks ───────────
  {
    id: 'react',
    name: 'React',
    categories: ['js-framework'],
    website: 'https://react.dev',
    npm: 'react',
    rules: {
      globals: { 'React.version': [r(VERSION_VALUE, { version: '$1' })] },
      dom: [
        { selector: '[data-reactroot]', rule: r(/[\s\S]*/, { confidence: 100 }) },
        { selector: '#root, #app, #__next, body > div', keyPrefix: '__reactContainer$', rule: exists() },
        { selector: '#root, #app, body > div', keyPrefix: '_reactRootContainer', rule: exists() },
      ],
      scriptSrc: [
        r(/\/react(?:-dom)?@(\d+(?:\.\d+)+)\//, { version: '$1' }),
        r(/\/react\/(\d+(?:\.\d+)+)\/(?:umd\/)?react(?:\.production)?(?:\.min)?\.js/, { version: '$1' }),
        r(/\/react(?:-dom)?(?:\.production)?(?:\.min)?\.js(?:[?#]|$)/, { confidence: 50 }),
      ],
    },
  },
  {
    id: 'nextjs',
    name: 'Next.js',
    categories: ['js-framework', 'web-framework'],
    website: 'https://nextjs.org',
    npm: 'next',
    implies: ['react', 'nodejs'],
    rules: {
      globals: {
        'next.version': [r(VERSION_VALUE, { version: '$1' })],
        __NEXT_DATA__: [exists()],
      },
      html: [r(/<script[^>]+id="__NEXT_DATA__"/, { confidence: 100 })],
      scriptSrc: [r(/\/_next\/static\//, { confidence: 100 })],
      headers: {
        'x-powered-by': [r(/^Next\.js(?: (\d+(?:\.\d+)+))?/, { version: '$1' })],
        'x-nextjs-cache': [exists()],
        'x-nextjs-prerender': [exists()],
      },
    },
  },
  {
    id: 'vue',
    name: 'Vue.js',
    categories: ['js-framework'],
    website: 'https://vuejs.org',
    npm: 'vue',
    rules: {
      globals: { 'Vue.version': [r(VERSION_VALUE, { version: '$1' })] },
      dom: [
        { selector: '[data-v-app]', rule: exists() },
        { selector: '#app, #__nuxt, body > div', keyPrefix: '__vue_app__', rule: exists() },
        { selector: '#app, #__nuxt, body > div', keyPrefix: '__vue__', rule: exists() },
      ],
      html: [r(/<[a-z][^>]+\sdata-v-[0-9a-f]{8}(?:[\s=>])/, { confidence: 50 })],
      scriptSrc: [
        r(/\/vue@(\d+(?:\.\d+)+)\//, { version: '$1' }),
        r(/\/vue\/(\d+(?:\.\d+)+)\/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js/, { version: '$1' }),
        r(/\/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js(?:[?#]|$)/, { confidence: 50 }),
      ],
    },
  },
  {
    id: 'nuxt',
    name: 'Nuxt',
    categories: ['js-framework', 'web-framework'],
    website: 'https://nuxt.com',
    npm: 'nuxt',
    implies: ['vue', 'nodejs'],
    rules: {
      globals: { __NUXT__: [exists()], $nuxt: [exists()], useNuxtApp: [exists(50)] },
      html: [r(/<div[^>]+id="__nuxt"/, { confidence: 100 })],
      scriptSrc: [r(/\/_nuxt\//, { confidence: 100 })],
      headers: { 'x-powered-by': [r(/^Nuxt/)] },
    },
  },
  {
    id: 'angular',
    name: 'Angular',
    categories: ['js-framework'],
    website: 'https://angular.dev',
    npm: '@angular/core',
    excludes: ['angularjs'],
    rules: {
      dom: [{ selector: '[ng-version]', attribute: 'ng-version', rule: r(VERSION_VALUE, { version: '$1' }) }],
      globals: { ng: [exists(25)] },
    },
  },
  {
    id: 'angularjs',
    name: 'AngularJS',
    categories: ['js-framework'],
    website: 'https://angularjs.org',
    npm: 'angular',
    cpe: ['angularjs:angular.js'],
    rules: {
      globals: { 'angular.version.full': [r(VERSION_VALUE, { version: '$1' })] },
      dom: [{ selector: '[ng-app], [data-ng-app]', rule: exists(75) }],
      scriptSrc: [
        r(/\/angularjs\/(\d+(?:\.\d+)+)\/angular(?:\.min)?\.js/, { version: '$1' }),
        r(/\/angular(?:js)?@(\d+(?:\.\d+)+)\//, { version: '$1' }),
        r(/\/angular[.-](\d+(?:\.\d+)+)(?:\.min)?\.js/, { version: '$1' }),
        r(/\/angular(?:\.min)?\.js(?:[?#]|$)/, { confidence: 50 }),
      ],
    },
  },
  {
    id: 'svelte',
    name: 'Svelte',
    categories: ['js-framework'],
    website: 'https://svelte.dev',
    npm: 'svelte',
    rules: {
      html: [r(/<[a-z][^>]+class="[^"]*\bsvelte-[a-z0-9]{5,7}\b/, { confidence: 75 })],
    },
  },
  {
    id: 'sveltekit',
    name: 'SvelteKit',
    categories: ['web-framework'],
    website: 'https://svelte.dev/docs/kit',
    npm: '@sveltejs/kit',
    implies: ['svelte'],
    rules: {
      html: [r(/\sdata-sveltekit-(?:preload-data|reload|hydrate|noscroll)/, { confidence: 100 })],
      scriptSrc: [r(/\/_app\/immutable\/(?:entry|chunks)\//, { confidence: 75 })],
    },
  },
  {
    id: 'ember',
    name: 'Ember.js',
    categories: ['js-framework'],
    website: 'https://emberjs.com',
    npm: 'ember-source',
    rules: {
      globals: { 'Ember.VERSION': [r(VERSION_VALUE, { version: '$1' })] },
      html: [r(/<[a-z][^>]+class="[^"]*\bember-application\b/, { confidence: 75 })],
    },
  },
  {
    id: 'backbone',
    name: 'Backbone.js',
    categories: ['js-framework'],
    website: 'https://backbonejs.org',
    npm: 'backbone',
    implies: ['underscore'],
    rules: {
      globals: { 'Backbone.VERSION': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [r(/\/backbone[.-]?(\d+(?:\.\d+)+)?(?:\.min)?\.js/, { version: '$1', confidence: 75 })],
    },
  },
  {
    id: 'alpinejs',
    name: 'Alpine.js',
    categories: ['js-framework'],
    website: 'https://alpinejs.dev',
    npm: 'alpinejs',
    rules: {
      globals: { 'Alpine.version': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [r(/\/alpinejs@(\d+(?:\.\d+)+)\//, { version: '$1' })],
      dom: [{ selector: '[x-data]', rule: exists(25) }],
    },
  },
  {
    id: 'gatsby',
    name: 'Gatsby',
    categories: ['ssg', 'js-framework'],
    website: 'https://www.gatsbyjs.com',
    npm: 'gatsby',
    implies: ['react'],
    rules: {
      meta: { generator: [r(/^Gatsby(?: (\d+(?:\.\d+)+))?/, { version: '$1' })] },
      html: [r(/<div[^>]+id="___gatsby"/, { confidence: 100 })],
      globals: { ___loader: [exists(50)] },
    },
  },
  {
    id: 'remix',
    name: 'Remix',
    categories: ['web-framework'],
    website: 'https://remix.run',
    npm: '@remix-run/react',
    implies: ['react'],
    rules: { globals: { __remixContext: [exists()], __remixManifest: [exists()] } },
  },
  {
    id: 'astro',
    name: 'Astro',
    categories: ['ssg', 'web-framework'],
    website: 'https://astro.build',
    npm: 'astro',
    rules: {
      meta: { generator: [r(/^Astro v?(\d+(?:\.\d+)+)/, { version: '$1' })] },
      html: [r(/<astro-island[\s>]/, { confidence: 100 })],
    },
  },
  {
    id: 'knockout',
    name: 'Knockout.js',
    categories: ['js-framework'],
    website: 'https://knockoutjs.com',
    npm: 'knockout',
    rules: { globals: { 'ko.version': [r(VERSION_VALUE, { version: '$1' })] } },
  },

  // ─────────── Libraries ───────────
  {
    id: 'jquery',
    name: 'jQuery',
    categories: ['js-library'],
    website: 'https://jquery.com',
    npm: 'jquery',
    cpe: ['jquery:jquery'],
    rules: {
      globals: {
        'jQuery.fn.jquery': [r(VERSION_VALUE, { version: '$1' })],
        '$.fn.jquery': [r(VERSION_VALUE, { version: '$1', confidence: 75 })],
      },
      scriptSrc: [
        r(/\/jquery[.-](\d+(?:\.\d+)+)(?:\.slim)?(?:\.min)?\.js/i, { version: '$1' }),
        r(/\/jquery\/(\d+(?:\.\d+)+)\/jquery(?:\.slim)?(?:\.min)?\.js/i, { version: '$1' }),
        r(/\/jquery@(\d+(?:\.\d+)+)\//i, { version: '$1' }),
        r(/\/wp-includes\/js\/jquery\/jquery(?:\.min)?\.js\?ver=(\d+(?:\.\d+)+)/, { version: '$1' }),
        r(/\/jquery(?:\.slim)?(?:\.min)?\.js(?:[?#]|$)/i, { confidence: 50 }),
      ],
    },
  },
  {
    id: 'jquery-ui',
    name: 'jQuery UI',
    categories: ['js-library', 'ui-framework'],
    website: 'https://jqueryui.com',
    npm: 'jquery-ui',
    cpe: ['jqueryui:jquery_ui'],
    implies: ['jquery'],
    rules: {
      globals: { 'jQuery.ui.version': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [
        r(/\/jqueryui\/(\d+(?:\.\d+)+)\/jquery-ui(?:\.min)?\.js/, { version: '$1' }),
        r(/\/jquery-ui[.-](\d+(?:\.\d+)+)(?:\.custom)?(?:\.min)?\.js/, { version: '$1' }),
        r(/\/jquery-ui(?:\.min)?\.js(?:[?#]|$)/, { confidence: 50 }),
      ],
    },
  },
  {
    id: 'jquery-migrate',
    name: 'jQuery Migrate',
    categories: ['js-library'],
    website: 'https://github.com/jquery/jquery-migrate',
    npm: 'jquery-migrate',
    implies: ['jquery'],
    rules: {
      globals: { 'jQuery.migrateVersion': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [
        r(/\/jquery-migrate[.-](\d+(?:\.\d+)+)(?:\.min)?\.js/, { version: '$1' }),
        r(/\/jquery-migrate(?:\.min)?\.js(?:\?ver=(\d+(?:\.\d+)+))?/, { version: '$1', confidence: 75 }),
      ],
    },
  },
  {
    id: 'lodash',
    name: 'Lodash',
    categories: ['js-library'],
    website: 'https://lodash.com',
    npm: 'lodash',
    cpe: ['lodash:lodash'],
    excludes: ['underscore'],
    rules: {
      // Lodash and Underscore both expose `_.VERSION`; `_.cloneDeepWith` only exists in Lodash.
      globals: {
        '_.cloneDeepWith': [exists()],
        '_.VERSION': [versionOnly(VERSION_VALUE)],
      },
      scriptSrc: [
        r(/\/lodash(?:\.js)?\/(\d+(?:\.\d+)+)\/lodash(?:\.core)?(?:\.min)?\.js/, { version: '$1' }),
        r(/\/lodash@(\d+(?:\.\d+)+)\//, { version: '$1' }),
      ],
    },
  },
  {
    id: 'underscore',
    name: 'Underscore.js',
    categories: ['js-library'],
    website: 'https://underscorejs.org',
    npm: 'underscore',
    cpe: ['underscorejs:underscore'],
    rules: {
      globals: { '_.VERSION': [r(VERSION_VALUE, { version: '$1', confidence: 75 })] },
      scriptSrc: [
        r(/\/underscore\.js\/(\d+(?:\.\d+)+)\/underscore(?:-min|\.min)?\.js/, { version: '$1' }),
        r(/\/underscore(?:-min|\.min)?\.js\?ver=(\d+(?:\.\d+)+)/, { version: '$1' }),
        r(/\/underscore@(\d+(?:\.\d+)+)\//, { version: '$1' }),
      ],
    },
  },
  {
    id: 'moment',
    name: 'Moment.js',
    categories: ['js-library'],
    website: 'https://momentjs.com',
    npm: 'moment',
    cpe: ['momentjs:moment'],
    rules: {
      globals: { 'moment.version': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [
        r(/\/moment\.js\/(\d+(?:\.\d+)+)\/moment(?:-with-locales)?(?:\.min)?\.js/, { version: '$1' }),
        r(/\/moment@(\d+(?:\.\d+)+)\//, { version: '$1' }),
        r(/\/moment(?:-with-locales)?(?:\.min)?\.js(?:[?#]|$)/, { confidence: 50 }),
      ],
    },
  },
  {
    id: 'bootstrap',
    name: 'Bootstrap',
    categories: ['ui-framework'],
    website: 'https://getbootstrap.com',
    npm: 'bootstrap',
    cpe: ['getbootstrap:bootstrap'],
    rules: {
      globals: {
        'bootstrap.Tooltip.VERSION': [r(VERSION_VALUE, { version: '$1' })],
        'jQuery.fn.tooltip.Constructor.VERSION': [r(VERSION_VALUE, { version: '$1', confidence: 75 })],
      },
      scriptSrc: [
        r(/\/bootstrap@(\d+(?:\.\d+)+)\//, { version: '$1' }),
        r(/\/(?:twitter-)?bootstrap\/(\d+(?:\.\d+)+)\/(?:js\/)?bootstrap(?:\.bundle)?(?:\.min)?\.js/, { version: '$1' }),
        r(/\/bootstrap(?:\.bundle)?(?:\.min)?\.js(?:[?#]|$)/, { confidence: 50 }),
      ],
      stylesheet: [
        r(/\/bootstrap@(\d+(?:\.\d+)+)\//, { version: '$1' }),
        r(/\/(?:twitter-)?bootstrap\/(\d+(?:\.\d+)+)\/(?:css\/)?bootstrap(?:\.min)?\.css/, { version: '$1' }),
        r(/\/bootstrap(?:\.min)?\.css(?:[?#]|$)/, { confidence: 50 }),
      ],
    },
  },
  {
    id: 'axios',
    name: 'Axios',
    categories: ['js-library'],
    website: 'https://axios-http.com',
    npm: 'axios',
    rules: {
      globals: { 'axios.VERSION': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [r(/\/axios@(\d+(?:\.\d+)+)\//, { version: '$1' }), r(/\/axios\/(\d+(?:\.\d+)+)\/axios(?:\.min)?\.js/, { version: '$1' })],
    },
  },
  {
    id: 'core-js',
    name: 'core-js',
    categories: ['js-library'],
    website: 'https://github.com/zloirock/core-js',
    npm: 'core-js',
    rules: {
      globals: {
        '__core-js_shared__.versions.0.version': [r(VERSION_VALUE, { version: '$1' })],
        'core.version': [r(VERSION_VALUE, { version: '$1', confidence: 50 })],
      },
    },
  },
  {
    id: 'd3',
    name: 'D3',
    categories: ['js-library'],
    website: 'https://d3js.org',
    npm: 'd3',
    rules: {
      globals: { 'd3.version': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [r(/\/d3@(\d+(?:\.\d+)*)\//, { version: '$1' }), r(/\/d3(?:\.v\d)?(?:\.min)?\.js(?:[?#]|$)/, { confidence: 50 })],
    },
  },
  {
    id: 'chartjs',
    name: 'Chart.js',
    categories: ['js-library'],
    website: 'https://www.chartjs.org',
    npm: 'chart.js',
    rules: {
      globals: { 'Chart.version': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [r(/\/chart\.js@(\d+(?:\.\d+)+)\//, { version: '$1' }), r(/\/Chart\.js\/(\d+(?:\.\d+)+)\//, { version: '$1' })],
    },
  },
  {
    id: 'threejs',
    name: 'Three.js',
    categories: ['js-library'],
    website: 'https://threejs.org',
    npm: 'three',
    rules: {
      // THREE.REVISION is "160" for npm three@0.160.x: only the minor is known, so this is not an exact version.
      globals: { 'THREE.REVISION': [r(/^(\d{2,3})(?:dev)?$/, { version: '0.$1' })] },
      scriptSrc: [r(/\/three@(\d+(?:\.\d+)+)\//, { version: '$1' })],
    },
  },
  {
    id: 'gsap',
    name: 'GSAP',
    categories: ['js-library'],
    website: 'https://gsap.com',
    npm: 'gsap',
    rules: {
      globals: { 'gsap.version': [r(VERSION_VALUE, { version: '$1' })], 'TweenMax.version': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [r(/\/gsap@(\d+(?:\.\d+)+)\//, { version: '$1' }), r(/\/gsap\/(\d+(?:\.\d+)+)\/gsap(?:\.min)?\.js/, { version: '$1' })],
    },
  },
  {
    id: 'modernizr',
    name: 'Modernizr',
    categories: ['js-library'],
    website: 'https://modernizr.com',
    npm: 'modernizr',
    rules: {
      globals: { 'Modernizr._version': [r(VERSION_VALUE, { version: '$1' })], Modernizr: [exists(75)] },
      scriptSrc: [r(/\/modernizr(?:[.-](\d+(?:\.\d+)+))?(?:[.-]custom)?(?:\.min)?\.js/i, { version: '$1', confidence: 75 })],
    },
  },
  {
    id: 'handlebars',
    name: 'Handlebars',
    categories: ['js-library'],
    website: 'https://handlebarsjs.com',
    npm: 'handlebars',
    cpe: ['handlebarsjs:handlebars'],
    rules: {
      globals: { 'Handlebars.VERSION': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [r(/\/handlebars(?:\.js)?\/(\d+(?:\.\d+)+)\/handlebars(?:\.runtime)?(?:\.min)?\.js/, { version: '$1' })],
    },
  },
  {
    id: 'dompurify',
    name: 'DOMPurify',
    categories: ['js-library', 'security'],
    website: 'https://github.com/cure53/DOMPurify',
    npm: 'dompurify',
    rules: {
      globals: { 'DOMPurify.version': [r(VERSION_VALUE, { version: '$1' })] },
      scriptSrc: [r(/\/dompurify@(\d+(?:\.\d+)+)\//, { version: '$1' }), r(/\/dompurify\/(\d+(?:\.\d+)+)\/purify(?:\.min)?\.js/, { version: '$1' })],
    },
  },
  {
    id: 'prototype',
    name: 'Prototype',
    categories: ['js-library'],
    website: 'http://prototypejs.org',
    cpe: ['prototypejs:prototype'],
    rules: { globals: { 'Prototype.Version': [r(VERSION_VALUE, { version: '$1' })] } },
  },
  {
    id: 'mootools',
    name: 'MooTools',
    categories: ['js-framework'],
    website: 'https://mootools.net',
    rules: { globals: { 'MooTools.version': [r(VERSION_VALUE, { version: '$1' })] } },
  },
  {
    id: 'socketio',
    name: 'Socket.IO',
    categories: ['js-library'],
    website: 'https://socket.io',
    npm: 'socket.io-client',
    rules: {
      scriptSrc: [
        r(/\/socket\.io\/(\d+(?:\.\d+)+)\/socket\.io(?:\.min)?\.js/, { version: '$1' }),
        r(/\/socket\.io(?:\.min)?\.js(?:[?#]|$)/, { confidence: 75 }),
      ],
      globals: { io: [exists(25)] },
    },
  },
  {
    id: 'swiper',
    name: 'Swiper',
    categories: ['js-library'],
    website: 'https://swiperjs.com',
    npm: 'swiper',
    rules: {
      scriptSrc: [r(/\/swiper@(\d+(?:\.\d+)*)\//, { version: '$1' }), r(/\/swiper(?:-bundle)?(?:\.min)?\.js(?:[?#]|$)/, { confidence: 75 })],
      globals: { Swiper: [exists(50)] },
    },
  },
  {
    id: 'webpack',
    name: 'webpack',
    categories: ['build-tool'],
    website: 'https://webpack.js.org',
    rules: { globals: { 'webpackChunk*': [exists()], webpackJsonp: [exists()] } },
  },
  {
    id: 'vite',
    name: 'Vite (dev server)',
    categories: ['build-tool'],
    website: 'https://vite.dev',
    rules: { scriptSrc: [r(/\/@vite\/client(?:[?#]|$)/, { confidence: 100 })] },
  },
  {
    id: 'polyfill-io',
    name: 'Polyfill.io',
    categories: ['js-library', 'cdn'],
    website: 'https://www.cloudflare.com/polyfill-io-supply-chain-attack/',
    note: 'O domínio polyfill.io foi comprometido em 2024 e passou a servir código malicioso (ataque à cadeia de suprimentos). Remova ou substitua a referência.',
    rules: { scriptSrc: [r(/\/\/(?:cdn\.)?polyfill\.io\//, { confidence: 100 })] },
  },
];
