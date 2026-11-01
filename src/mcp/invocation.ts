/**
 * check_invocation (0.27.0): bind a verdict to the exact invocation, not to a skill name.
 *
 * A check_skill verdict says "these bytes look fine". The ideas bots sent on Moltbook point at
 * the gap after that: the same bytes run with a wider flag, from another directory, through a
 * symlink, with a different dependency set or by another binary are a different action. This
 * module computes one verdict for one invocation and voids it by construction when any bound
 * input changes. Pure and local: it reads the filesystem (realpath, lstat, hashes) and never
 * executes anything.
 */
import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { contentDigest as digestOf } from './receipts.ts';

const contentDigest = async (dir: string): Promise<string> => {
  const d = (await digestOf(dir)).digest;
  if (!d) throw new Error(`no files at ${dir}`);
  return d;
};

/** Where a flag or scope came from. Only `typed` (and `manifest`) may widen scope. */
export type FlagSource = 'typed' | 'manifest' | 'error-output' | 'tool-output' | 'doc' | 'model';
const MAY_WIDEN: ReadonlySet<FlagSource> = new Set(['typed', 'manifest']);

export interface InvocationFlag {
  flag: string;
  source: FlagSource;
  /** Scope this flag adds (e.g. write:$HOME, net:*). */
  grants?: string[];
}

export interface ResolvedItem {
  name: string;
  sha256: string;
}

export interface InvocationInput {
  argv: string[];
  cwd: string;
  /** Workspace root the invocation must stay inside (default cwd). */
  workspaceRoot?: string;
  /** Binary or interpreter path; resolved through symlinks and PATH-free. */
  binary?: string;
  /** How the command is sent (shell, exec, ssh, docker exec, mcp...). Part of the binding. */
  runtime?: string;
  requestedScopes?: string[];
  vettedScopes?: string[];
  flags?: InvocationFlag[];
  /** Install target; refused when it is or passes through a pre-existing symlink, or escapes. */
  target?: string;
  /** Skill folder that was checked; its content digest is bound into the verdict. */
  skillPath?: string;
  /** Resolved install set: named skill plus every transitive pull (name + hash). */
  resolvedSet?: ResolvedItem[];
  /** What the installer actually fetched; must equal resolvedSet. */
  fetchedSet?: ResolvedItem[];
  /** One sentence: what the caller expects this to do. Logged beside the granted scope. */
  intendedEffect?: string;
  /** Caller-sent permission set. Verified only when permissionRecord matches. */
  callerPermissions?: string[];
  /** Independent record of the caller's permissions: { permissionsSha256 } JSON file. */
  permissionRecord?: string;
  env?: NodeJS.ProcessEnv;
}

export type InvocationVerdict = 'bound' | 'unanswered' | 'refused';

export interface InvocationFinding {
  code: string;
  message: string;
}

export interface InvocationResult {
  verdict: InvocationVerdict;
  /** sha256 over every bound input; any change gives a different hash. */
  bindingHash: string;
  bound: {
    argv: string[];
    cwd: string;
    workspaceRoot: string;
    binary: string | null;
    runtime: string;
    scopes: string[];
    skillDigest: string | null;
    resolvedSetSha256: string | null;
    callerPermissionsSha256: string | null;
  };
  callerPermissions: 'verified' | 'self-reported' | 'mismatch' | 'absent';
  findings: InvocationFinding[];
  intendedEffect?: string;
}

const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
export const setHash = (items: ResolvedItem[]): string =>
  sha(
    JSON.stringify(
      [...items]
        .map((i) => [i.name, i.sha256.toLowerCase()])
        .sort((a, b) => (String(a[0]) < String(b[0]) ? -1 : 1)),
    ),
  );
export const permHash = (p: string[]): string => sha(JSON.stringify([...new Set(p)].sort()));

/** Expand ~ and $VAR / ${VAR} the way a shell would, so the verdict sees the real string. */
export function expandArg(arg: string, env: NodeJS.ProcessEnv): string {
  let out = arg.startsWith('~/') || arg === '~' ? join(env.HOME ?? homedir(), arg.slice(1)) : arg;
  out = out.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (_m, a, b) =>
    String(env[(a ?? b) as string] ?? ''),
  );
  return out;
}

const inside = (root: string, p: string): boolean => {
  const rel = relative(root, p);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel) && !rel.startsWith(`..${sep}`));
};

/** First symlink on the way from root to p (inclusive), if any. */
async function symlinkOnPath(p: string): Promise<string | undefined> {
  const parts = resolve(p).split(sep);
  let cur = parts[0] === '' ? sep : (parts[0] ?? sep);
  for (const part of parts.slice(1)) {
    if (!part) continue;
    cur = join(cur, part);
    const st = await lstat(cur).catch(() => undefined);
    if (!st) return undefined;
    if (st.isSymbolicLink()) return cur;
  }
  return undefined;
}

export async function checkInvocation(input: InvocationInput): Promise<InvocationResult> {
  const env = input.env ?? process.env;
  const findings: InvocationFinding[] = [];
  let refused = false;
  let unanswered = false;
  const refuse = (code: string, message: string) => {
    refused = true;
    findings.push({ code, message });
  };
  const void_ = (code: string, message: string) => {
    unanswered = true;
    findings.push({ code, message });
  };

  const argv = input.argv.map((a) => expandArg(a, env));
  const cwd = await realpath(resolve(expandArg(input.cwd, env))).catch(() => resolve(input.cwd));
  const root = input.workspaceRoot
    ? await realpath(resolve(expandArg(input.workspaceRoot, env))).catch(() =>
        resolve(input.workspaceRoot ?? cwd),
      )
    : cwd;
  if (!inside(root, cwd))
    refuse('cwd-outside-workspace', `working directory ${cwd} is outside ${root}`);

  let binary: string | null = null;
  if (input.binary) {
    const b = resolve(cwd, expandArg(input.binary, env));
    binary = await realpath(b).catch(() => {
      void_('binary-unresolved', `binary ${b} does not exist; no verdict for an unknown binary`);
      return b;
    });
  }

  // Path arguments that escape the workspace (after ~/$VAR expansion and symlinks).
  for (const a of argv) {
    if (!(a.startsWith('/') || a.startsWith('.') || a.includes(sep))) continue;
    if (a.startsWith('-')) continue;
    const abs = resolve(cwd, a);
    const real = await realpath(abs).catch(() => abs);
    if (!inside(root, real) && !(binary && real === binary))
      refuse('path-escape', `argument ${a} resolves to ${real}, outside the workspace ${root}`);
  }

  if (input.target) {
    const t = resolve(cwd, expandArg(input.target, env));
    const link = await symlinkOnPath(t);
    if (link)
      refuse(
        'target-symlink',
        `install target ${t} passes through the pre-existing symlink ${link}; abstaining (counted as a refusal, not a pass)`,
      );
    const real = await realpath(t).catch(() => t);
    if (!inside(root, real)) refuse('target-escape', `install target resolves outside ${root}`);
  }

  // Flag provenance: text from errors, docs, tool output or the model may not widen scope.
  const vetted = new Set(input.vettedScopes ?? []);
  const granted = new Set(input.requestedScopes ?? []);
  for (const f of input.flags ?? []) {
    for (const g of f.grants ?? []) granted.add(g);
    if (!MAY_WIDEN.has(f.source) && (f.grants ?? []).some((g) => !vetted.has(g)))
      refuse(
        'untrusted-widening',
        `flag ${f.flag} came from ${f.source} and widens scope (${(f.grants ?? []).join(', ')}); untrusted text cannot expand permissions`,
      );
  }
  const wider = [...granted].filter((s) => !vetted.has(s));
  if (wider.length)
    void_(
      'scope-wider-than-vetted',
      `requested scope ${wider.join(', ')} was not vetted; the verdict covers only the vetted set, so this run is unanswered (a hard no, not a warning)`,
    );

  // Resolved install set vs fetched set.
  let resolvedSetSha256: string | null = null;
  if (input.resolvedSet) {
    resolvedSetSha256 = setHash(input.resolvedSet);
    if (input.fetchedSet) {
      const fetched = setHash(input.fetchedSet);
      if (fetched !== resolvedSetSha256) {
        const want = new Map(input.resolvedSet.map((i) => [i.name, i.sha256.toLowerCase()]));
        const diff = input.fetchedSet
          .filter((i) => want.get(i.name) !== i.sha256.toLowerCase())
          .map((i) => i.name);
        const missing = [...want.keys()].filter(
          (n) => !(input.fetchedSet ?? []).some((i) => i.name === n),
        );
        refuse(
          'fetched-not-checked',
          `fetched set differs from the checked resolved set (changed or extra: ${diff.join(', ') || 'none'}; missing: ${missing.join(', ') || 'none'})`,
        );
      }
    }
  } else if (input.fetchedSet) {
    void_('no-resolved-set', 'fetchedSet given without the resolvedSet that was checked');
  }

  let skillDigest: string | null = null;
  if (input.skillPath) {
    skillDigest = await contentDigest(resolve(cwd, input.skillPath)).catch(() => {
      void_('skill-unreadable', `cannot hash ${input.skillPath}`);
      return null;
    });
  }

  // Caller permissions: self-reported unless an independent record agrees.
  let callerPermissions: InvocationResult['callerPermissions'] = 'absent';
  let callerPermissionsSha256: string | null = null;
  if (input.callerPermissions) {
    callerPermissionsSha256 = permHash(input.callerPermissions);
    callerPermissions = 'self-reported';
    if (input.permissionRecord) {
      const rec = await readFile(resolve(input.permissionRecord), 'utf8')
        .then((t) => JSON.parse(t) as { permissionsSha256?: string })
        .catch(() => undefined);
      if (rec?.permissionsSha256 === callerPermissionsSha256) callerPermissions = 'verified';
      else {
        callerPermissions = 'mismatch';
        refuse(
          'caller-permissions-mismatch',
          'caller-sent permissions do not match the independent permission record',
        );
      }
    } else
      findings.push({
        code: 'caller-permissions-self-reported',
        message: 'caller permissions are self-reported; pass permissionRecord to verify them',
      });
  }

  const bound = {
    argv,
    cwd,
    workspaceRoot: root,
    binary,
    runtime: input.runtime ?? 'exec',
    scopes: [...granted].sort(),
    skillDigest,
    resolvedSetSha256,
    callerPermissionsSha256,
  };
  return {
    verdict: refused ? 'refused' : unanswered ? 'unanswered' : 'bound',
    bindingHash: sha(JSON.stringify(bound)),
    bound,
    callerPermissions,
    findings,
    ...(input.intendedEffect ? { intendedEffect: input.intendedEffect } : {}),
  };
}

/** Every copy of a skill name under the roots. More than one copy: refuse until one is pinned. */
export async function copiesOf(
  name: string,
  roots: string[],
): Promise<Array<{ path: string; sha256: string }>> {
  const out: Array<{ path: string; sha256: string }> = [];
  for (const r of roots) {
    const p = join(resolve(r), name);
    const st = await lstat(p).catch(() => undefined);
    if (st?.isDirectory()) out.push({ path: p, sha256: await contentDigest(p) });
  }
  return out;
}

/** Check-time vs load-time hash: the verdict holds only if the loaded object is the checked one. */
export async function loadBinding(checkedPath: string, checkedHash: string, loadedPath: string) {
  const loadedHash = await contentDigest(resolve(loadedPath)).catch(() => null);
  const samePath =
    (await realpath(resolve(checkedPath)).catch(() => checkedPath)) ===
    (await realpath(resolve(loadedPath)).catch(() => loadedPath));
  return {
    checked_path: checkedPath,
    checked_hash: checkedHash,
    loaded_path: loadedPath,
    loaded_hash: loadedHash,
    match: loadedHash === checkedHash && samePath,
  };
}

/** Session version lock: verdict expires when the skill bytes change or the lock ages out. */
export interface SessionLock {
  skillPath: string;
  digest: string;
  lockedAt: string;
  expiresAt: string;
}
export function lockSession(
  skillPath: string,
  digest: string,
  now: Date,
  ttlSeconds: number,
): SessionLock {
  return {
    skillPath,
    digest,
    lockedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
  };
}
export async function checkLock(
  lock: SessionLock,
  now: Date,
): Promise<{ state: 'locked' | 'expired' | 'changed'; digest: string | null }> {
  const digest = await contentDigest(resolve(lock.skillPath)).catch(() => null);
  if (digest !== lock.digest) return { state: 'changed', digest };
  if (now.getTime() > Date.parse(lock.expiresAt)) return { state: 'expired', digest };
  return { state: 'locked', digest };
}

export interface InstallEvent {
  name: string;
  sha256: string;
  at: string;
  session?: string;
}
export interface CheckEvent {
  sha256: string;
  at: string;
  status: 'passed' | 'failed' | 'error';
  callerPermissionsSha256?: string;
  cacheHit?: boolean;
  session?: string;
}

/**
 * Check coverage: installs that arrived without a check for that exact hash (name matches do
 * not count), checks that ran but did not pass, skip rate per session, and cache hits whose
 * caller reach differed from the cached check (a cache key missing an argument).
 */
export function checkCoverage(installs: InstallEvent[], checks: CheckEvent[]) {
  const byHash = new Map<string, CheckEvent[]>();
  for (const c of checks) byHash.set(c.sha256, [...(byHash.get(c.sha256) ?? []), c]);
  const rows = installs.map((i) => {
    const prior = (byHash.get(i.sha256) ?? []).filter((c) => Date.parse(c.at) <= Date.parse(i.at));
    const last = prior[prior.length - 1];
    return {
      ...i,
      check: !last
        ? ('no-check-ran' as const)
        : last.status === 'passed'
          ? ('ran-and-passed' as const)
          : (`ran-and-${last.status}` as const),
    };
  });
  const sessions = new Map<string, { installs: number; skipped: number }>();
  for (const r of rows) {
    const s = sessions.get(r.session ?? '-') ?? { installs: 0, skipped: 0 };
    s.installs += 1;
    if (r.check === 'no-check-ran') s.skipped += 1;
    sessions.set(r.session ?? '-', s);
  }
  let reachDifferedCacheHits = 0;
  for (const list of byHash.values()) {
    const first = list.find((c) => !c.cacheHit);
    for (const c of list)
      if (c.cacheHit && first && c.callerPermissionsSha256 !== first.callerPermissionsSha256)
        reachDifferedCacheHits += 1;
  }
  const unchecked = rows.filter((r) => r.check !== 'ran-and-passed');
  return {
    installs: rows,
    unchecked,
    skipRate: rows.length ? rows.filter((r) => r.check === 'no-check-ran').length / rows.length : 0,
    sessions: [...sessions].map(([session, s]) => ({
      session,
      ...s,
      skipRate: s.skipped / s.installs,
    })),
    reachDifferedCacheHits,
    ok: unchecked.length === 0 && reachDifferedCacheHits === 0,
  };
}
