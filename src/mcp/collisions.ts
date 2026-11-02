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
  /** 1-based position on the search path (roots in the order given). */
  loadOrder: number;
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
    const real = await realpath(dir).catch(() => dir);
    if (seen.has(real)) continue;
    seen.add(real);
    out.push({ path: dir, loadOrder: order, root: resolve(root) });
  }
  return out;
}

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
