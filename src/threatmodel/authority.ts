/**
 * Runner ambient authority and removal leftovers (0.27.0).
 *
 * The review unit is the runner, not the skill: every step inherits the runner's secrets,
 * tokens and permissions. Growth fails the PR (not a warning). Approval binds the skill bytes
 * to a runner; a new runner is a new install even with identical bytes.
 */
export interface RunnerAuthority {
  runner: string;
  secrets: string[];
  tokens: string[];
  permissions: string[];
  /** Per step, the effective set it can see (job secrets plus inherited ones). */
  steps?: Record<string, string[]>;
}

export interface AuthorityFinding {
  code: string;
  severity: 'fail' | 'warn';
  message: string;
}

const grown = (a: string[] = [], b: string[] = []) => b.filter((x) => !a.includes(x));

export function diffAuthority(base: RunnerAuthority[], cur: RunnerAuthority[]): AuthorityFinding[] {
  const out: AuthorityFinding[] = [];
  const byName = new Map(base.map((r) => [r.runner, r]));
  for (const c of cur) {
    const b = byName.get(c.runner);
    if (!b) {
      out.push({
        code: 'new-runner',
        severity: 'fail',
        message: `new runner ${c.runner}: treat as a new install and list its ambient authority before any skill runs there`,
      });
      continue;
    }
    for (const k of ['secrets', 'tokens', 'permissions'] as const) {
      const g = grown(b[k], c[k]);
      if (g.length)
        out.push({
          code: 'ambient-authority-grew',
          severity: 'fail',
          message: `runner ${c.runner}: ${k} grew (${g.join(', ')})`,
        });
    }
    for (const [step, set] of Object.entries(c.steps ?? {})) {
      const g = grown(b.steps?.[step] ?? [], set);
      if (g.length)
        out.push({
          code: 'step-reach-grew',
          severity: 'fail',
          message: `runner ${c.runner} step ${step}: effective set grew (${g.join(', ')}); a new secret and a newly visible one are the same event`,
        });
    }
  }
  return out;
}

/** Approval of a skill on a runner: bound to (skill hash, runner, authority hash). */
export interface SkillMachineApproval {
  skill: string;
  sha256: string;
  runner: string;
  authoritySha256: string;
}
export function approvalCovers(
  a: SkillMachineApproval[],
  skill: string,
  sha256: string,
  runner: string,
  authoritySha256: string,
): boolean {
  return a.some(
    (x) =>
      x.skill === skill &&
      x.sha256 === sha256 &&
      x.runner === runner &&
      x.authoritySha256 === authoritySha256,
  );
}

/** Every new flag or env var needs its own reach line before the PR passes. */
export function unreachedKnobs(
  before: string[],
  after: string[],
  reachLines: Record<string, string>,
): AuthorityFinding[] {
  return grown(before, after)
    .filter((k) => !reachLines[k])
    .map((k) => ({
      code: 'knob-without-reach',
      severity: 'fail' as const,
      message: `new flag or env var ${k} has no reach line in the threat model`,
    }));
}

/** A removal PR must prove each leftover gone: cron entries, tokens, DNS records, files. */
export interface Leftover {
  kind: 'cron' | 'token' | 'dns' | 'file' | 'webhook' | 'service';
  id: string;
}
export function removalLeftovers(
  declared: Leftover[],
  provenGone: Array<Pick<Leftover, 'kind' | 'id'>>,
): AuthorityFinding[] {
  return declared
    .filter((l) => !provenGone.some((p) => p.kind === l.kind && p.id === l.id))
    .map((l) => ({
      code: 'removal-leftover',
      severity: 'fail' as const,
      message:
        l.kind === 'dns'
          ? `DNS record ${l.id} outlives the skill (re-registration takeover risk); prove it removed`
          : `${l.kind} ${l.id} left behind by the removed skill; prove it removed`,
    }));
}

/** A new reader on a path a private-data writer uses fails, whatever reach the reader declares. */
export function sharedPathReaders(
  writers: Array<{ skill: string; path: string; private: boolean }>,
  newReaders: Array<{ skill: string; path: string }>,
  overrides: Array<{ skill: string; path: string; by: string; reason: string }> = [],
): AuthorityFinding[] {
  return newReaders
    .filter((r) => writers.some((w) => w.private && w.path === r.path && w.skill !== r.skill))
    .filter(
      (r) => !overrides.some((o) => o.skill === r.skill && o.path === r.path && o.by && o.reason),
    )
    .map((r) => ({
      code: 'shared-path-reader',
      severity: 'fail' as const,
      message: `${r.skill} newly reads ${r.path}, which a private-data writer uses; treat the shared path as a publication`,
    }));
}
