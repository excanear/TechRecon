import { compareVersions, describeRange, isVersionInRange, type VersionRange } from './version';

export interface Cpe {
  part: string;
  vendor: string;
  product: string;
  version: string;
  update: string;
  edition: string;
  language: string;
  swEdition: string;
  targetSw: string;
  targetHw: string;
  other: string;
}

/** Splits a CPE 2.3 formatted string on unescaped colons. */
export function parseCpe(criteria: string): Cpe | null {
  const fields: string[] = [];
  let current = '';
  for (let i = 0; i < criteria.length; i++) {
    const ch = criteria[i]!;
    if (ch === '\\' && i + 1 < criteria.length) {
      current += ch + criteria[i + 1];
      i++;
    } else if (ch === ':') {
      fields.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current);
  if (fields.length !== 13 || fields[0] !== 'cpe' || fields[1] !== '2.3') return null;
  const [, , part, vendor, product, version, update, edition, language, swEdition, targetSw, targetHw, other] = fields as [
    string, string, string, string, string, string, string, string, string, string, string, string, string,
  ];
  return { part, vendor, product, version, update, edition, language, swEdition, targetSw, targetHw, other };
}

/** CPE values use backslash escapes ("joomla\!"); compare unescaped, case-insensitively. */
export function unescapeCpeValue(value: string): string {
  return value.replace(/\\(.)/g, '$1').toLowerCase();
}

export function vendorProductOf(cpe: Cpe): string {
  return `${unescapeCpeValue(cpe.vendor)}:${unescapeCpeValue(cpe.product)}`;
}

// ───────── NVD configuration evaluation ─────────

export interface NvdCpeMatch {
  vulnerable: boolean;
  criteria: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

export interface NvdNode {
  operator?: 'OR' | 'AND';
  negate?: boolean;
  cpeMatch?: NvdCpeMatch[];
}

export interface NvdConfiguration {
  operator?: 'OR' | 'AND';
  negate?: boolean;
  nodes?: NvdNode[];
}

export interface ConfigMatch {
  matched: boolean;
  /** Human-readable ranges that contained the version. */
  ranges: string[];
  criteria: string[];
  fixedIn?: string;
  /** Extra conditions (AND configurations: platform/OS/other component). */
  conditions?: string;
}

const ANY = new Set(['*', '']);

function matchCpeEntry(entry: NvdCpeMatch, targets: Set<string>, version: string): { range: string } | null {
  if (!entry.vulnerable) return null;
  const cpe = parseCpe(entry.criteria);
  if (!cpe || cpe.part !== 'a' || !targets.has(vendorProductOf(cpe))) return null;

  if (!ANY.has(cpe.version)) {
    // A specific version in the criteria. "-" (not applicable) cannot be matched to a release number.
    if (cpe.version === '-') return null;
    if (!ANY.has(cpe.update) && cpe.update !== '-') return null;
    return compareVersions(version, unescapeCpeValue(cpe.version)) === 0 ? { range: `= ${unescapeCpeValue(cpe.version)}` } : null;
  }

  const range: VersionRange = {
    startIncluding: entry.versionStartIncluding,
    startExcluding: entry.versionStartExcluding,
    endIncluding: entry.versionEndIncluding,
    endExcluding: entry.versionEndExcluding,
  };
  // null (incomparable, e.g. NGINX Plus "r22" bounds) is never a match.
  return isVersionInRange(version, range) === true ? { range: describeRange(range) } : null;
}

function describeOtherNode(node: NvdNode): string {
  const names = new Set<string>();
  for (const m of node.cpeMatch ?? []) {
    const cpe = parseCpe(m.criteria);
    if (cpe) names.add(`${unescapeCpeValue(cpe.vendor)} ${unescapeCpeValue(cpe.product)}`.replace(/_/g, ' '));
  }
  const list = [...names];
  return list.length > 3 ? `${list.slice(0, 3).join(', ')} (+${list.length - 3})` : list.join(', ');
}

/**
 * Checks whether `version` of any of `vendorProducts` is inside a vulnerable range of the
 * CVE's applicability statements. This is the local verification step that turns an NVD
 * search result into a version-based match.
 */
export function evaluateNvdConfigurations(
  configurations: NvdConfiguration[] | undefined,
  vendorProducts: string[],
  version: string,
): ConfigMatch {
  const targets = new Set(vendorProducts.map((vp) => vp.split(':').map(unescapeCpeValue).join(':')));
  const ranges = new Set<string>();
  const criteria = new Set<string>();
  const fixes: string[] = [];
  const conditions = new Set<string>();
  let unconditional = false;

  for (const config of configurations ?? []) {
    if (config.negate) continue;
    const nodes = config.nodes ?? [];
    nodes.forEach((node, index) => {
      if (node.negate) return;
      for (const entry of node.cpeMatch ?? []) {
        const hit = matchCpeEntry(entry, targets, version);
        if (!hit) continue;
        ranges.add(hit.range);
        criteria.add(entry.criteria);
        if (entry.versionEndExcluding) fixes.push(entry.versionEndExcluding);
        if (config.operator === 'AND' && nodes.length > 1) {
          const others = nodes
            .filter((_, i) => i !== index)
            .map(describeOtherNode)
            .filter(Boolean);
          if (others.length) conditions.add(`Somente em combinação com: ${others.join('; ')}`);
          else unconditional = true;
        } else {
          unconditional = true;
        }
      }
    });
  }

  const fixedIn = fixes
    .filter((f) => compareVersions(f, version) !== null)
    .sort((a, b) => compareVersions(a, b) ?? 0)[0];

  return {
    matched: ranges.size > 0,
    ranges: [...ranges],
    criteria: [...criteria],
    fixedIn,
    // Any match without extra platform requirements makes the conditions informational only.
    conditions: !unconditional && conditions.size ? [...conditions].join(' · ') : undefined,
  };
}

/** NVD virtualMatchString for a vendor:product at a given version. */
export function buildMatchString(vendorProduct: string, version: string): string {
  const [vendor, product] = vendorProduct.split(':');
  const escapedVersion = version.replace(/([^A-Za-z0-9._-])/g, '\\$1');
  return `cpe:2.3:a:${vendor}:${product}:${escapedVersion}`;
}
