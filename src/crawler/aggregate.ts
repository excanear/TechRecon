// Aggregates per-page detections into a single site-wide technology inventory. A technology
// seen on many pages keeps its strongest evidence and most-supported exact version, plus the
// set of pages where it appeared. This is what makes whole-site fingerprinting stronger than
// looking at one page.

import { mergeVersionCandidates } from '../fingerprinting/version';
import type { ConfidenceLevel, Detection, Evidence } from '../types';

export interface AggregatedTech {
  id: string;
  name: string;
  categories: Detection['categories'];
  website?: string;
  confidence: number;
  confidenceLevel: ConfidenceLevel;
  version?: string;
  versionExact: boolean;
  versionConflicts: string[];
  inferred: boolean;
  evidence: Evidence[];
  notes: string[];
  cpe?: string[];
  npm?: string;
  distroPackage?: string;
  /** Number of crawled pages this technology was detected on. */
  pageCount: number;
  /** A few example page URLs (capped). */
  samplePages: string[];
}

const MAX_EVIDENCE = 8;
const MAX_SAMPLE_PAGES = 5;

function level(confidence: number): ConfidenceLevel {
  if (confidence >= 80) return 'high';
  if (confidence >= 50) return 'medium';
  return 'low';
}

export class TechAggregator {
  private readonly map = new Map<string, AggregatedTech & { _versions: Array<{ version: string; weight: number }>; _pages: Set<string> }>();

  add(detections: Detection[], pageUrl: string): void {
    for (const det of detections) {
      const existing = this.map.get(det.id);
      if (!existing) {
        this.map.set(det.id, {
          id: det.id,
          name: det.name,
          categories: det.categories,
          website: det.website,
          confidence: det.confidence,
          confidenceLevel: det.confidenceLevel,
          version: det.version,
          versionExact: det.versionExact,
          versionConflicts: [...det.versionConflicts],
          inferred: det.inferred,
          evidence: dedupeEvidence(det.evidence),
          notes: [...det.notes],
          cpe: det.cpe,
          npm: det.npm,
          distroPackage: det.distroPackage,
          pageCount: 1,
          samplePages: [pageUrl],
          _versions: versionCandidates(det),
          _pages: new Set([pageUrl]),
        });
        continue;
      }

      existing._pages.add(pageUrl);
      existing.pageCount = existing._pages.size;
      if (existing.samplePages.length < MAX_SAMPLE_PAGES && !existing.samplePages.includes(pageUrl)) {
        existing.samplePages.push(pageUrl);
      }
      // A directly observed detection overrides an inference.
      if (existing.inferred && !det.inferred) existing.inferred = false;
      existing.confidence = Math.max(existing.confidence, det.confidence);
      existing.confidenceLevel = level(existing.confidence);
      existing.evidence = dedupeEvidence([...existing.evidence, ...det.evidence]).slice(0, MAX_EVIDENCE);
      existing.distroPackage ??= det.distroPackage;
      for (const note of det.notes) if (!existing.notes.includes(note)) existing.notes.push(note);
      existing._versions.push(...versionCandidates(det));
    }
  }

  get size(): number {
    return this.map.size;
  }

  finish(): AggregatedTech[] {
    const result: AggregatedTech[] = [];
    for (const tech of this.map.values()) {
      const { version, conflicts } = mergeVersionCandidates(tech._versions);
      tech.version = version ?? tech.version;
      tech.versionConflicts = conflicts;
      tech.versionExact = Boolean(version && /^\d+\.\d+/.test(version) && conflicts.length === 0 && !tech.inferred);
      const { _versions, _pages, ...clean } = tech;
      void _versions;
      void _pages;
      result.push(clean);
    }
    return result.sort((a, b) => Number(a.inferred) - Number(b.inferred) || b.pageCount - a.pageCount || a.name.localeCompare(b.name));
  }
}

function versionCandidates(det: Detection): Array<{ version: string; weight: number }> {
  return det.evidence
    .filter((e) => e.version)
    .map((e) => ({ version: e.version!, weight: Math.max(e.confidence, 25) + (e.type === 'global' ? 10 : 0) }));
}

function dedupeEvidence(evidence: Evidence[]): Evidence[] {
  const seen = new Set<string>();
  const out: Evidence[] = [];
  for (const e of evidence) {
    const key = `${e.type}:${e.key ?? ''}:${e.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}
