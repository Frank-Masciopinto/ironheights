/**
 * A bare skill name that resolves to more than one copy (0.31.0).
 *
 * Every copy is returned with its load-order position (the order of the roots the
 * caller passed, which is the search path). An overall allow is withheld until a
 * runtime resolver or environment selects exactly one copy. Ambiguity never allows.
 */
import { lstat, realpath } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';

export interface NameCopy {
  path: string;
  /** Absolute path after realpath. This is the key a caller uses to tell copies apart. */
  resolvedPath: string;
  /** 1-based position on the search path (roots in the order given). */
  loadOrder: number;
  /**
   * Loader precedence. Same as loadOrder when it can be computed (lower loads first).
   * Null when the directory cannot be resolved, which must not produce an overall allow.
   */
  precedence: number | null;
  root: string;
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/;

export function bareName(name: string): string | null {
  const n = name.trim();
  if (!NAME.test(n) || n.includes('/') || n.includes('\\') || n === '.' || n === '..') return null;
  return n;
}

/** Copies of `name` directly under each root, in root order. */
export async function copiesOnPath(name: string, roots: string[]): Promise<NameCopy[]> {
  const bare = bareName(name);
  if (!bare) return [];
  const out: NameCopy[] = [];
  const seen = new Set<string>();
  let order = 0;
  for (const root of roots) {
    order += 1;
    const dir = join(resolve(root), bare);
    const st = await lstat(dir).catch(() => undefined);
    if (!st?.isDirectory()) continue;
    const abs = resolve(dir);
    let resolvedPath = abs;
    let precedence: number | null = order;
    try {
      resolvedPath = await realpath(dir);
    } catch {
      precedence = null;
    }
    if (seen.has(resolvedPath)) continue;
    seen.add(resolvedPath);
    out.push({ path: dir, resolvedPath, loadOrder: order, precedence, root: resolve(root) });
  }
  return out;
}

export interface DescribedCopy {
  path: string;
  resolvedPath: string;
  loadOrder: number;
  precedence: number | null;
  findings: unknown[];
  digest: unknown;
  verdict: string;
  decision: string;
}

export interface NamedCopyRecord {
  path: string;
  resolvedPath: string;
  loadOrder: number;
  precedence: number | null;
  /** True for the copy that wins: the selected copy, or the load-order winner when none is selected. */
  winner: boolean;
  /** True for the earliest root. Stays put when a resolver picks a different copy. */
  loadOrderWinner: boolean;
  findings: unknown[];
  digest: unknown;
  verdict: string;
  decision: string;
  /** Set only on the winner, and only after resolver or environment has selected one copy. */
  overallVerdict?: string;
}

export interface NameAssembly {
  copies: Record<string, NamedCopyRecord>;
  candidates: NamedCopyRecord[];
  winner: string | null;
  loadOrderWinner: string | null;
  precedenceKnown: boolean;
}

/**
 * Key every copy by its resolved absolute path. An overall verdict is attached
 * only to the winner, and only once a selector has chosen that copy. When any
 * copy has no precedence, nothing is a winner and nothing carries an overall verdict.
 */
export function assembleNameCopies(
  described: DescribedCopy[],
  selectedResolvedPath: string | null,
): NameAssembly {
  const precedenceKnown = described.length > 0 && described.every((c) => c.precedence !== null);
  let loadOrderWinner: string | null = null;
  if (precedenceKnown) {
    const ranked = [...described].sort(
      (a, b) => (a.precedence as number) - (b.precedence as number),
    );
    loadOrderWinner = ranked[0]?.resolvedPath ?? null;
  }
  const selected =
    precedenceKnown &&
    selectedResolvedPath !== null &&
    described.some((c) => c.resolvedPath === selectedResolvedPath)
      ? selectedResolvedPath
      : null;
  const winner = selected ?? (selectedResolvedPath === null ? loadOrderWinner : null);
  const copies: Record<string, NamedCopyRecord> = {};
  const candidates: NamedCopyRecord[] = [];
  for (const copy of described) {
    const record: NamedCopyRecord = {
      path: copy.path,
      resolvedPath: copy.resolvedPath,
      loadOrder: copy.loadOrder,
      precedence: copy.precedence,
      winner: winner !== null && copy.resolvedPath === winner,
      loadOrderWinner: loadOrderWinner !== null && copy.resolvedPath === loadOrderWinner,
      findings: copy.findings,
      digest: copy.digest,
      verdict: copy.verdict,
      decision: copy.decision,
    };
    if (selected !== null && copy.resolvedPath === selected) record.overallVerdict = copy.verdict;
    copies[copy.resolvedPath] = record;
    candidates.push(record);
  }
  return { copies, candidates, winner, loadOrderWinner, precedenceKnown };
}

export const PRECEDENCE_UNKNOWN = 'loader precedence cannot be computed; refusing an overall allow';

export interface Selector {
  resolver?: string;
  environment?: string;
}

export type Selection =
  | { status: 'chosen'; copy: NameCopy }
  | { status: 'ambiguous'; matches: NameCopy[]; reason: string }
  | { status: 'none'; reason: string };

/**
 * Select one copy. Without a resolver and an environment, more than one copy is
 * ambiguous. A selector that matches zero or several copies stays ambiguous and
 * must not allow.
 */
export function selectCopy(copies: NameCopy[], selector: Selector): Selection {
  if (!copies.length) return { status: 'none', reason: 'no copy of this name on the given roots' };
  const resolver = selector.resolver?.trim() || undefined;
  const environment = selector.environment?.trim() || undefined;
  if (!resolver && !environment) {
    if (copies.length === 1) return { status: 'chosen', copy: copies[0] as NameCopy };
    return {
      status: 'ambiguous',
      matches: copies,
      reason: `bare name matches ${copies.length} copies; pass resolver or environment before any allow`,
    };
  }
  const matches = copies.filter((c) => matchesSelector(c, resolver, environment));
  if (matches.length === 1) return { status: 'chosen', copy: matches[0] as NameCopy };
  if (!matches.length)
    return {
      status: 'ambiguous',
      matches: copies,
      reason: 'resolver and environment matched no copy; refusing to guess',
    };
  return {
    status: 'ambiguous',
    matches,
    reason: `resolver and environment matched ${matches.length} copies; refusing to guess`,
  };
}

function matchesSelector(copy: NameCopy, resolver?: string, environment?: string): boolean {
  if (resolver && !resolverMatches(copy, resolver)) return false;
  if (environment && !environmentMatches(copy, environment)) return false;
  return true;
}

function resolverMatches(copy: NameCopy, resolver: string): boolean {
  const want = resolve(resolver);
  return want === resolve(copy.path) || want === resolve(copy.root);
}

function environmentMatches(copy: NameCopy, environment: string): boolean {
  const segments = resolve(copy.path).split(sep).filter(Boolean);
  const rootSegments = resolve(copy.root).split(sep).filter(Boolean);
  return segments.includes(environment) || rootSegments.includes(environment);
}
