// The active signature set: the curated signatures, plus the converted Wappalyzer dataset when
// the operator has installed it. Conversion compiles ~15k regexes, so the result is memoized in
// the service worker and rebuilt only after an install/removal (or a worker restart).

import { del, get, put } from '../db';
import { buildCollectionPlan, type CollectionPlan } from './engine';
import type { Signature } from './signature';
import { SIGNATURES } from './signatures';
import { convertWappalyzer, type ConversionStats } from './wappalyzer/convert';
import { downloadDataset, WAPPALYZER_LICENSE, WAPPALYZER_REPO, type FetchLike, type WappalyzerDataset } from './wappalyzer/dataset';

export interface SignatureSet {
  signatures: Signature[];
  plan: CollectionPlan;
  wappalyzer: ConversionStats | null;
}

export interface WappalyzerStatus {
  installed: boolean;
  commit?: string;
  fetchedAt?: string;
  stats?: ConversionStats;
  curated: number;
  repo: string;
  license: string;
  /** Set when the stored dataset could not be loaded; the curated set is used meanwhile. */
  error?: string;
}

const STORE = 'datasets';
const KEY = 'wappalyzer';

type LoadedSet = SignatureSet & { dataset: WappalyzerDataset | null; error?: string };

let active: Promise<LoadedSet> | null = null;

function curatedOnly(): SignatureSet {
  return { signatures: SIGNATURES, plan: buildCollectionPlan(SIGNATURES), wappalyzer: null };
}

async function load(): Promise<LoadedSet> {
  let dataset: WappalyzerDataset | undefined;
  try {
    dataset = await get<WappalyzerDataset>(STORE, KEY);
  } catch (err) {
    return { ...curatedOnly(), dataset: null, error: `Falha ao ler a base Wappalyzer: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (!dataset) return { ...curatedOnly(), dataset: null };
  const { signatures: extra, stats } = convertWappalyzer(dataset.technologies, SIGNATURES);
  const signatures = [...SIGNATURES, ...extra];
  return { signatures, plan: buildCollectionPlan(signatures), wappalyzer: stats, dataset };
}

/** The signatures every detection should run with right now. */
export async function getSignatureSet(): Promise<SignatureSet> {
  active ??= load();
  return active;
}

export async function wappalyzerStatus(): Promise<WappalyzerStatus> {
  const set = await (active ??= load());
  return {
    installed: Boolean(set.dataset),
    commit: set.dataset?.commit,
    fetchedAt: set.dataset?.fetchedAt,
    stats: set.wappalyzer ?? undefined,
    curated: SIGNATURES.length,
    repo: WAPPALYZER_REPO,
    license: WAPPALYZER_LICENSE,
    error: set.error,
  };
}

/** Downloads, verifies and stores the dataset, then activates it. Nothing is stored on failure. */
export async function installWappalyzer(fetchFn: FetchLike, onProgress?: (done: number, total: number) => void): Promise<WappalyzerStatus> {
  const dataset = await downloadDataset(fetchFn, { onProgress });
  await put(STORE, dataset);
  active = null;
  return wappalyzerStatus();
}

export async function removeWappalyzer(): Promise<WappalyzerStatus> {
  await del(STORE, KEY);
  active = null;
  return wappalyzerStatus();
}
