// Shared data models. Everything that crosses a module boundary is defined here.

// ───────────────────────── Page collection ─────────────────────────

/** A DOM query requested by a signature, executed by the collector in the page. */
export interface DomQuery {
  id: string;
  selector: string;
  /** Attribute whose value should be returned (truncated). */
  attribute?: string;
  /** Return textContent (truncated). */
  text?: boolean;
}

/** A DOM expando query: properties set by page JS on elements are only visible from the MAIN world. */
export interface DomPropertyQuery {
  id: string;
  selector: string;
  /** Own-property name prefix, e.g. "__reactContainer$". */
  keyPrefix: string;
}

export interface DomQueryResult {
  count: number;
  values: string[];
}

export interface ScriptInfo {
  src: string;
  /** SRI integrity attribute present. */
  integrity: boolean;
  crossorigin: string | null;
  async: boolean;
  defer: boolean;
  module: boolean;
}

export interface ResourceEntry {
  url: string;
  initiatorType: string;
}

/** Raw data gathered from the page in the isolated content-script world. */
export interface CollectedDom {
  url: string;
  title: string;
  /** document.documentElement.outerHTML, capped. Never persisted. */
  html: string;
  htmlTruncated: boolean;
  scripts: ScriptInfo[];
  /** Concatenated inline script text, capped. Never persisted. */
  inlineScripts: string;
  inlineScriptCount: number;
  stylesheets: string[];
  meta: Record<string, string[]>;
  /** Cookie names readable through document.cookie (values are never collected). */
  cookieNames: string[];
  /** Length of each readable cookie's value, to hint at token-like cookies without storing them. */
  cookieValueLengths: Record<string, number>;
  resources: ResourceEntry[];
  dom: Record<string, DomQueryResult>;
  protocol: string;
  contentType: string;
  characterSet: string;
}

/** Values read from the page's MAIN world. Only primitives (truncated) or "[object]" markers. */
export type GlobalValues = Record<string, string>;

export interface HeaderProbe {
  status: number;
  url: string;
  /** Lower-cased header name → value (sensitive values redacted). */
  headers: Record<string, string>;
  fetchedAt: string;
}

export type HeaderSource = 'none' | 'probe';

/** Everything the fingerprinting engine looks at. */
export interface PageSnapshot {
  url: string;
  html: string;
  scriptSrcs: string[];
  inlineScripts: string;
  stylesheets: string[];
  meta: Record<string, string[]>;
  cookieNames: string[];
  headers: Record<string, string> | null;
  globals: GlobalValues;
  dom: Record<string, DomQueryResult>;
  resources: ResourceEntry[];
}

// ───────────────────────── Fingerprinting ─────────────────────────

export type CategoryId =
  | 'js-framework'
  | 'js-library'
  | 'ui-framework'
  | 'cms'
  | 'ecommerce'
  | 'analytics'
  | 'tag-manager'
  | 'cdn'
  | 'waf'
  | 'security'
  | 'web-server'
  | 'language'
  | 'web-framework'
  | 'paas'
  | 'ssg'
  | 'font'
  | 'payment'
  | 'widget'
  | 'monitoring'
  | 'build-tool'
  | 'cache'
  | 'consent';

export type EvidenceType =
  | 'html'
  | 'scriptSrc'
  | 'script'
  | 'stylesheet'
  | 'meta'
  | 'header'
  | 'cookie'
  | 'global'
  | 'dom'
  | 'url'
  | 'resource'
  | 'implied';

export type ConfidenceLevel = 'high' | 'medium' | 'low';

export interface Evidence {
  type: EvidenceType;
  /** Header/meta/cookie/global name, DOM selector, etc. */
  key?: string;
  /** Short, redacted excerpt of what matched. */
  value: string;
  version?: string;
  confidence: number;
  /** false for inferences (implied technologies). */
  observed: boolean;
}

export interface Detection {
  id: string;
  name: string;
  categories: CategoryId[];
  website?: string;
  /** 0–100. */
  confidence: number;
  confidenceLevel: ConfidenceLevel;
  version?: string;
  /** Version is a concrete release (at least major.minor) and unambiguous. */
  versionExact: boolean;
  /** Other distinct versions seen in the evidence (conflict). */
  versionConflicts: string[];
  /** True when the technology was only inferred from another detection. */
  inferred: boolean;
  impliedBy?: string[];
  evidence: Evidence[];
  notes: string[];
  /** Distribution named in a version banner (backport risk), e.g. "Ubuntu". */
  distroPackage?: string;
  cpe?: string[];
  npm?: string;
}

// ───────────────────────── Vulnerabilities ─────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN';

export interface CvssInfo {
  version: string;
  score: number | null;
  vector: string;
  severity: Severity;
  source?: string;
}

export interface Reference {
  url: string;
  label: string;
}

export type VulnSourceId = 'nvd' | 'osv';

export interface Vulnerability {
  /** Preferred display id: CVE if known, otherwise advisory id. */
  id: string;
  aliases: string[];
  title: string;
  description: string;
  cvss: CvssInfo | null;
  severity: Severity;
  published?: string;
  modified?: string;
  /** Human-readable affected version ranges that matched. */
  affected: string[];
  /** Earliest fixed version from the matching range, when the source states it. */
  fixedIn?: string;
  /** Why this was matched (version + range + criteria). */
  matchBasis: string;
  /** Extra platform/config conditions from the source (e.g. AND configurations). */
  conditions?: string;
  source: VulnSourceId;
  sourceUrl: string;
  references: Reference[];
}

export type VulnReportStatus =
  | 'pending'
  | 'ok'
  | 'no-version'
  | 'version-uncertain'
  | 'unmapped'
  | 'disabled'
  | 'error';

export interface SourceQueryResult {
  source: VulnSourceId;
  query: string;
  ok: boolean;
  cached: boolean;
  fetchedAt?: string;
  error?: string;
  /** Results returned by the source but rejected by local range verification. */
  discarded: number;
}

export interface TechVulnReport {
  techId: string;
  techName: string;
  version?: string;
  status: VulnReportStatus;
  message?: string;
  queries: SourceQueryResult[];
  vulns: Vulnerability[];
}

/** Analyst-confirmed findings (manual), keyed by vulnerability id. */
export type Confirmations = Record<string, { at: string; techId: string }>;

// ───────────────────────── Recon ─────────────────────────

export type HeaderCheckState = 'present' | 'absent' | 'not-observed';

export interface SecurityHeaderCheck {
  id: string;
  label: string;
  state: HeaderCheckState;
  value?: string;
  /** Where it came from: response header probe or meta tag. */
  origin?: 'header' | 'meta';
  notes: string[];
}

export interface ScriptInventoryItem {
  url: string;
  host: string;
  thirdParty: boolean;
  integrity: boolean;
  crossorigin: string | null;
  loading: string;
  insecure: boolean;
}

export interface HostInventory {
  host: string;
  thirdParty: boolean;
  count: number;
  types: Record<string, number>;
}

export interface CookieObservation {
  name: string;
  valueLength: number;
}

export interface ReconData {
  https: boolean;
  headerSource: HeaderSource;
  headerStatus?: number;
  /** Redacted headers from the probe (if run). */
  headers: Record<string, string>;
  securityHeaders: SecurityHeaderCheck[];
  scripts: ScriptInventoryItem[];
  inlineScriptCount: number;
  hosts: HostInventory[];
  cookies: CookieObservation[];
  mixedContent: string[];
  notes: string[];
}

// ───────────────────────── Analysis state ─────────────────────────

export type AnalysisStatus = 'idle' | 'collecting' | 'correlating' | 'done' | 'unsupported' | 'error';

export interface AnalysisState {
  tabId: number;
  url: string;
  domain: string;
  status: AnalysisStatus;
  error?: string;
  startedAt: string;
  finishedAt?: string;
  technologies: Detection[];
  recon: ReconData | null;
  vulnReports: Record<string, TechVulnReport>;
  cveLookupEnabled: boolean;
}

export interface Settings {
  nvdApiKey: string;
  autoHeaderProbe: boolean;
  cveLookup: boolean;
  cacheTtlHours: number;
  theme: 'dark' | 'light';
}

// ───────────────────────── Messaging ─────────────────────────

export type PopupRequest =
  | { type: 'analyze'; tabId: number; force?: boolean; probeHeaders?: boolean }
  | { type: 'retry-cve'; tabId: number };

export type BackgroundMessage = { type: 'state'; state: AnalysisState };
