/**
 * Reuse of an earlier verdict is never silent (0.31.0).
 *
 * A match is logged as `reused`, which is not a `checked` event. A mismatch fails the
 * reuse and is a `stale-answer` carrying both hashes. A file on disk that the verdict
 * never opened fails the reuse too. A docs-only delta keeps the verdict only when the
 * caller opted into executable scope and the executable digest still matches.
 */
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import type { JudgedFile } from './digests.ts';

export const DOCS_ONLY_LABEL = 'reused, docs-only delta';

export type ReuseAudit = 'reused' | typeof DOCS_ONLY_LABEL;

export interface ReuseObservation {
  at: string;
  skill: string;
  /** `mismatch` always lands in the log. `docs-only` is a labelled reuse, not a failure. */
  kind: 'match' | 'mismatch' | 'docs-only';
  judged: string | null;
  current: string | null;
  /** Set on a real reuse. Absent on a stale answer, and never the value `checked`. */
  reused?: 'reused' | 'reused, docs-only delta';
  event?: 'stale-answer';
  operator?: string;
}

export interface ReuseInput {
  judgedDigest: string | null;
  currentDigest: string | null;
  judgedFiles: JudgedFile[];
  currentFiles: JudgedFile[];
  /** True only when this caller opted into executable scope. */
  executableScope: boolean;
  /** True when the original verdict stored an executable digest. */
  verdictOptedIn: boolean;
  judgedExecutable: string | null;
  currentExecutable: string | null;
  /** False for a verdict that did not record the files it opened. Extra-file checks need the list. */
  manifestKnown: boolean;
}

export type ReuseDecision =
  | { ok: true; audit: ReuseAudit; judged: string | null; current: string | null }
  | {
      ok: false;
      event: 'stale-answer';
      reason: string;
      judged: string | null;
      current: string | null;
      operator: string;
    };

const byPath = (files: JudgedFile[]): Map<string, JudgedFile> =>
  new Map(files.map((f) => [f.path, f]));

/** Paths on disk now that the verdict's manifest does not contain. */
export function unopenedFiles(judged: JudgedFile[], current: JudgedFile[]): JudgedFile[] {
  const seen = new Set(judged.map((f) => f.path));
  return current.filter((f) => !seen.has(f.path));
}

/**
 * True when every added, removed or edited path is a documentation file.
 * A config, data or executable change is not a docs-only delta.
 */
export function isDocsOnlyDelta(judged: JudgedFile[], current: JudgedFile[]): boolean {
  const j = byPath(judged);
  const c = byPath(current);
  const paths = new Set([...j.keys(), ...c.keys()]);
  let changed = false;
  for (const path of paths) {
    const before = j.get(path);
    const after = c.get(path);
    if (before?.sha256 === after?.sha256) continue;
    changed = true;
    const role = after?.role ?? before?.role;
    if (role !== 'doc') return false;
  }
  return changed;
}

export function judgeReuse(input: ReuseInput): ReuseDecision {
  const judged = input.judgedDigest;
  const current = input.currentDigest;
  const extra = input.manifestKnown ? unopenedFiles(input.judgedFiles, input.currentFiles) : [];
  const digestsMatch = Boolean(judged) && judged === current;
  const docsOnly =
    input.executableScope &&
    input.verdictOptedIn &&
    input.judgedExecutable !== null &&
    input.judgedExecutable === input.currentExecutable &&
    isDocsOnlyDelta(input.judgedFiles, input.currentFiles);
  if (docsOnly && extra.every((f) => f.role === 'doc'))
    return { ok: true, audit: DOCS_ONLY_LABEL, judged, current };
  if (extra.length && !docsOnly)
    return fail(
      judged,
      current,
      `the skill now contains ${extra.map((f) => f.path).join(', ')}, which this verdict never opened`,
    );
  if (!current) return fail(judged, current, 'the checked files are not on disk to re-hash');
  if (!digestsMatch)
    return fail(judged, current, 'the files on disk do not match the digest this verdict judged');
  return { ok: true, audit: 'reused', judged, current };
}

function fail(judged: string | null, current: string | null, why: string): ReuseDecision {
  const j = judged ? `sha256:${judged}` : 'none';
  const c = current ? `sha256:${current}` : 'none';
  return {
    ok: false,
    event: 'stale-answer',
    reason: why,
    judged,
    current,
    operator: `Stale answer: judged ${j}, disk now ${c}. ${why}. The reused verdict does not apply; re-check before use.`,
  };
}

export function reuseLogPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(ironheightsHome(env), 'reuse-observations.jsonl');
}

export async function logReuse(path: string, row: ReuseObservation): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, JSON.stringify(row) + '\n');
}

export async function readObservations(path: string): Promise<ReuseObservation[]> {
  let raw = '';
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    return [];
  }
  const out: ReuseObservation[] = [];
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line) as ReuseObservation;
      if (row && typeof row.skill === 'string' && typeof row.kind === 'string') out.push(row);
    } catch {
      /* skip a bad line */
    }
  }
  return out;
}

/** Recent rate must be more than twice this skill's own historical rate before an alert. */
export const RELATIVE_THRESHOLD = 2;
const RECENT = 3;
const MIN_HISTORY = 4;

export interface ChangeRate {
  observations: number;
  mismatches: number;
  /** Mismatch rate over this skill's older observations. Null until it has a history. */
  baseline: number | null;
  recent: number | null;
  relativeThreshold: number;
  alert: boolean;
  reason: string;
}

/**
 * Per-skill change rate. Mismatches are counted from the log (they are always written).
 * An alert fires only when the recent rate breaks from this skill's own baseline.
 */
export function changeRate(rows: ReuseObservation[]): ChangeRate {
  const mismatches = rows.filter((r) => r.kind === 'mismatch').length;
  const rate = (slice: ReuseObservation[]): number =>
    slice.length ? slice.filter((r) => r.kind === 'mismatch').length / slice.length : 0;
  if (rows.length < MIN_HISTORY)
    return {
      observations: rows.length,
      mismatches,
      baseline: null,
      recent: rows.length ? round(rate(rows)) : null,
      relativeThreshold: RELATIVE_THRESHOLD,
      alert: false,
      reason: `no alert: ${rows.length} reuse observation(s), fewer than ${MIN_HISTORY}; mismatches are still logged`,
    };
  const recentRows = rows.slice(-RECENT);
  const baseRows = rows.slice(0, -RECENT);
  const baseline = rate(baseRows);
  const recent = rate(recentRows);
  const alert = recent > baseline * RELATIVE_THRESHOLD;
  return {
    observations: rows.length,
    mismatches,
    baseline: round(baseline),
    recent: round(recent),
    relativeThreshold: RELATIVE_THRESHOLD,
    alert,
    reason: alert
      ? `alert: recent mismatch rate ${round(recent)} is more than ${RELATIVE_THRESHOLD}× this skill's own baseline ${round(baseline)}`
      : `no alert: recent mismatch rate ${round(recent)} is within ${RELATIVE_THRESHOLD}× this skill's own baseline ${round(baseline)}`,
  };
}

const round = (n: number): number => Math.round(n * 1000) / 1000;
