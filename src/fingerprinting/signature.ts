import type { CategoryId, SignatureSource } from '../types';

/**
 * A single detection rule. `pattern` is tested against one piece of evidence;
 * `version` is a template where `$1`…`$9` are replaced by capture groups.
 */
export interface Rule {
  pattern: RegExp;
  version?: string;
  /** Contribution to the technology's confidence (0–100). Default 100. 0 = version-only rule. */
  confidence: number;
}

export interface DomRule {
  selector: string;
  /** Attribute to read; `pattern` is tested against its value. */
  attribute?: string;
  /** Test `pattern` against textContent. */
  text?: boolean;
  /** MAIN-world expando property prefix on matching elements (e.g. "__reactContainer$"). */
  keyPrefix?: string;
  rule: Rule;
}

export interface CookieRule {
  name: RegExp;
  confidence: number;
}

export interface SignatureRules {
  html?: Rule[];
  scriptSrc?: Rule[];
  /** Inline script contents. */
  script?: Rule[];
  stylesheet?: Rule[];
  /** Keyed by lower-case meta name/property/http-equiv. */
  meta?: Record<string, Rule[]>;
  /** Keyed by lower-case header name. Only usable when headers were observed. */
  headers?: Record<string, Rule[]>;
  cookies?: CookieRule[];
  /** Keyed by a dotted global path (e.g. "jQuery.fn.jquery"); a trailing "*" means "any window key with this prefix". */
  globals?: Record<string, Rule[]>;
  dom?: DomRule[];
  url?: Rule[];
  /** URLs of loaded resources (Performance API). */
  resource?: Rule[];
}

export interface Signature {
  id: string;
  name: string;
  categories: CategoryId[];
  website?: string;
  /** CPE vendor:product pairs for NVD correlation (part "a"). */
  cpe?: string[];
  /** npm package name for OSV correlation. */
  npm?: string;
  implies?: string[];
  excludes?: string[];
  /** Only reported when at least one of these technologies is also present (detected or inferred). */
  requires?: string[];
  /** Only reported when some present technology has one of these categories. */
  requiresCategories?: CategoryId[];
  /** Factual caveat shown with the detection. */
  note?: string;
  /** Absent = curated. */
  source?: SignatureSource;
  rules: SignatureRules;
}

export interface RuleOptions {
  version?: string;
  confidence?: number;
}

/** Rule helper. */
export function r(pattern: RegExp, opts: RuleOptions = {}): Rule {
  return { pattern, version: opts.version, confidence: opts.confidence ?? 100 };
}

/** Matches any observed value: used for "this global/cookie/header exists". */
export function exists(confidence = 100): Rule {
  return { pattern: /[\s\S]*/, confidence };
}

/** Rule that only supplies a version and never detects on its own. */
export function versionOnly(pattern: RegExp, version = '$1'): Rule {
  return { pattern, version, confidence: 0 };
}

export function cookie(name: RegExp, confidence = 100): CookieRule {
  return { name, confidence };
}

export const CATEGORY_LABELS: Record<CategoryId, string> = {
  'js-framework': 'Frameworks JavaScript',
  'js-library': 'Bibliotecas JavaScript',
  'ui-framework': 'Frameworks de UI',
  cms: 'CMS',
  ecommerce: 'E-commerce',
  analytics: 'Analytics',
  'tag-manager': 'Tag managers',
  cdn: 'CDN',
  waf: 'WAF / Proteção contra bots',
  security: 'Segurança',
  'web-server': 'Servidores web',
  language: 'Linguagens',
  'web-framework': 'Frameworks web',
  paas: 'Hospedagem / PaaS',
  ssg: 'Geradores de sites estáticos',
  font: 'Fontes',
  payment: 'Pagamentos',
  widget: 'Widgets',
  monitoring: 'Monitoramento / RUM',
  'build-tool': 'Ferramentas de build',
  cache: 'Cache',
  consent: 'Consentimento de cookies',
  'cms-extension': 'Plugins e temas de CMS',
  database: 'Bancos de dados',
  os: 'Sistemas operacionais',
  marketing: 'Marketing / Publicidade',
  other: 'Outros',
};

/** Display order for category groups in the popup. */
export const CATEGORY_ORDER: CategoryId[] = [
  'cms',
  'cms-extension',
  'ecommerce',
  'js-framework',
  'web-framework',
  'js-library',
  'ui-framework',
  'web-server',
  'language',
  'database',
  'os',
  'cdn',
  'waf',
  'security',
  'paas',
  'cache',
  'ssg',
  'build-tool',
  'analytics',
  'tag-manager',
  'monitoring',
  'payment',
  'widget',
  'consent',
  'marketing',
  'font',
  'other',
];
