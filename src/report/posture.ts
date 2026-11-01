/**
 * Agent security posture report (`ironheights report`).
 *
 * One report for a repository or a whole organisation checkout: every installed skill with its
 * grade and verdict, drift since approval, threat-model coverage, findings mapped to the OWASP
 * Top 10 for LLM Applications 2025, and a trend from earlier runs (`--history`). JSON and a
 * self-contained HTML page for audits. Local only: no network, no telemetry.
 */
import { createHash } from 'node:crypto';
import { appendFile, readFile, stat } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';

import { gradeFromSkills } from '../core/grade.ts';
import { discoverSkillRoots, scanSkill } from '../core/scanner.ts';
import type { Finding, ResolvedConfig, Severity, Verdict } from '../core/types.ts';
import { collectConfigKeys, fingerprintConfig } from '../drift/config-keys.ts';
import { diffSkill, readLedger, snapshotSkill, type DriftChange } from '../drift/drift.ts';
import { isCredentialPath } from '../guard/signals.ts';
import { redactSecrets } from '../guard/redact.ts';
import { escapeHtml } from '../cli/output/html.ts';
import { referencesFor, rulePageUrl } from '../rules/references.ts';
import {
  MODEL_FILE,
  evaluate,
  hostAllowed,
  loadModel,
  profileSkill,
  readMcpServers,
  toPosix,
  type McpServerDef,
  type SkillEntryT,
  type SkillProfile,
  type Violation,
} from '../threatmodel/threatmodel.ts';
import { TOOL_NAME, TOOL_VERSION } from '../version.ts';
import {
  environmentStamp,
  gradeStamp,
  leftovers as findLeftovers,
  lifecycleOf,
  refusalRow,
  reversalStats,
  type ArtifactRecord,
  type EnvironmentStamp,
  type GradeStamp,
  type LeftoverRow,
  type Lifecycle,
  type RefusalEvent,
  type RefusalRow,
  type ReversalStats,
} from './extras.ts';

export const OWASP_LLM_2025: Record<string, string> = {
  'LLM01:2025': 'Prompt Injection',
  'LLM02:2025': 'Sensitive Information Disclosure',
  'LLM03:2025': 'Supply Chain',
  'LLM04:2025': 'Data and Model Poisoning',
  'LLM05:2025': 'Improper Output Handling',
  'LLM06:2025': 'Excessive Agency',
  'LLM07:2025': 'System Prompt Leakage',
  'LLM08:2025': 'Vector and Embedding Weaknesses',
  'LLM09:2025': 'Misinformation',
  'LLM10:2025': 'Unbounded Consumption',
};

const SKILL_DIR_GUESSES = ['skills', '.claude/skills', '.cursor/skills', '.agents/skills', 'skill'];

export type ReachLevel =
  | 'exec'
  | 'secrets'
  | 'undeclared-network'
  | 'outside-write'
  | 'declared-network'
  | 'read-only';

export interface WorstReach {
  level: ReachLevel;
  label: string;
  rule?: string;
  evidence?: string;
}

const REACH_ORDER: Record<ReachLevel, number> = {
  exec: 0,
  secrets: 1,
  'undeclared-network': 2,
  'outside-write': 3,
  'declared-network': 4,
  'read-only': 5,
};

const REACH_LABEL: Record<ReachLevel, string> = {
  exec: 'exec or credential read',
  secrets: 'secrets in env',
  'undeclared-network': 'network egress to undeclared host',
  'outside-write': 'writes outside workspace',
  'declared-network': 'network to declared hosts',
  'read-only': 'read-only',
};

const GRADE_ORDER: Record<string, number> = {
  F: 0,
  D: 1,
  C: 2,
  B: 3,
  A: 4,
  incomplete: 5,
  'nothing-scanned': 6,
};

export interface SkillRow {
  repo: string;
  skill: string;
  path: string;
  /** Highest-reach capability. The inventory is sorted by this, then grade. */
  worstReach: WorstReach;
  grade: string;
  /** sha256 of config inputs. Secret values are not part of the hash. */
  configHash: string;
  /** True when `--history` shows a different configHash for this skill. */
  regraded?: true;
  score?: number;
  verdict: Verdict;
  findings: number;
  bySeverity: Partial<Record<Severity, number>>;
  topRules: string[];
  inThreatModel: boolean | null;
  drift: { approved: boolean; changes: number; high: number } | null;
  /**
   * What the grade is about. `complete` is false when files were skipped or the skill fetches
   * instructions at runtime; the grade then covers only the inspected files (0.23.0).
   */
  coverage: {
    complete: boolean;
    filesRead: number;
    filesSkipped: number;
    /** URLs the skill fetches and follows at runtime; the scan did not read those bytes. */
    runtimeFetched: string[];
    /** Why the skill is not fully inspected. Empty when complete. */
    reasons: string[];
  };
  /** 0.24.0: what was graded, when, against which version, and until when it holds. */
  stamp?: GradeStamp;
  /** 0.24.0: fix lifecycle, derived at read time. Shown as a gap column; it does not move the grade. */
  lifecycle?: { state: Lifecycle; installedVersion: string | null; gap: string };
}

export interface LossPath {
  repo: string;
  skill: string;
  path: string;
  asset: string;
  precondition: string;
  exploitable: 'confirmed' | 'unresolved';
  checkNeeded?: string;
  firstSeen?: string;
  status?: 'open' | 'contained-pending-check';
}

export interface RepoRow {
  repo: string;
  path: string;
  skills: number;
  configHash: string;
  threatModel: { present: boolean; covered: number; violations: number; high: number } | null;
}

export interface PostureReport {
  tool: string;
  version: string;
  title: string;
  generatedAt: string;
  totals: {
    repos: number;
    skills: number;
    grades: Record<string, number>;
    verdicts: Record<string, number>;
    findings: number;
    reposWithThreatModel: number;
    threatModelCoverage: number | null;
    driftChanged: number;
    driftApproved: number;
    /** Skills fully inspected vs skills loaded (0.23.0). */
    coverage: { inspected: number; loaded: number; complete: boolean };
    /**
     * Worst grade among fully inspected skills, or `incomplete` when any loaded skill was not
     * fully inspected. A letter is only issued when coverage is total.
     */
    overall: string;
    /** One line that always carries its denominator. */
    result: string;
  };
  /** Report fingerprint: sha256 over every skill config hash and coverage state. */
  fingerprint: string;
  /** After this time the HTML page marks itself expired. */
  validUntil: string;
  owaspLlm: Array<{ id: string; name: string; findings: number; skills: number; rules: string[] }>;
  repos: RepoRow[];
  skills: SkillRow[];
  violations: Array<Violation & { repo: string }>;
  driftChanges: Array<DriftChange & { repo: string }>;
  history: HistoryPoint[];
  /** 0.24.0: where this report ran. Trends are drawn only across the same environment. */
  environment?: EnvironmentStamp;
  /** 0.24.0: weakest skill and its widest reach, as one unit. */
  lead?: string;
  /** 0.24.0: a critical finding flips the verdict regardless of the average. */
  killSwitch?: { skill: string; rule: string } | null;
  /** 0.24.0: confirmed paths first (containment), then unresolved high-impact paths (verification). */
  lanes?: { containment: LossPath[]; verification: LossPath[] };
  /** 0.24.0: average score; a cleanup-effort measure, not a safety measure. */
  cleanupEffort?: number | null;
  refusals?: RefusalRow;
  leftovers?: LeftoverRow[];
  reversal?: ReversalStats;
  /** 0.24.0: skills whose config changed between runs, from --history. */
  changeLog?: Array<{ at: string; changed: string[] }>;
  /** 0.24.0: earlier runs from other environments, shown side by side, never in the trend. */
  otherEnvironments?: Array<{
    id: string;
    at: string;
    skills: number;
    findings: number;
    inspectedDigest?: string;
  }>;
  checkIntervalHours?: number;
}

export interface HistoryPoint {
  at: string;
  skills: number;
  findings: number;
  block: number;
  review: number;
  threatModelCoverage: number | null;
  driftChanged: number;
  /** Per-skill config hashes from this run, keyed by `repo/path`. */
  configHashes?: Record<string, string>;
  /** 0.24.0 */
  envId?: string;
  inspectedDigest?: string;
  changed?: string[];
  /** Skills that had findings in this run. */
  findingSkills?: string[];
  /** Unresolved loss paths and when they were first seen. */
  unresolved?: Record<string, string>;
}

async function isDir(p: string): Promise<boolean> {
  try {
    return (await stat(p)).isDirectory();
  } catch {
    return false;
  }
}

async function exists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

function previousConfigHashes(history: HistoryPoint[]): Record<string, string> | undefined {
  for (let i = history.length - 1; i >= 0; i -= 1) {
    const hashes = history[i]?.configHashes;
    if (hashes && typeof hashes === 'object') return hashes;
  }
  return undefined;
}

function clipEvidence(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const clean = redactSecrets(value).replace(/\s+/g, ' ').trim();
  return clean.length > 160 ? `${clean.slice(0, 157)}...` : clean;
}

function worstReach(
  findings: readonly Finding[],
  profile: SkillProfile,
  entry: SkillEntryT | undefined,
  hasModel: boolean,
): WorstReach {
  const hits: Array<{ level: ReachLevel; rule?: string; evidence?: string }> = [];
  const add = (level: ReachLevel, rule?: string, evidence?: string): void => {
    hits.push({
      level,
      ...(rule ? { rule } : {}),
      ...(clipEvidence(evidence) ? { evidence: clipEvidence(evidence) } : {}),
    });
  };
  if (profile.shell) add('exec', undefined, 'shell or child process');
  for (const f of findings) {
    if (/^IH-EXEC|^IH-PRIV/.test(f.ruleId) || f.ruleId === 'IH-CRED-001')
      add('exec', f.ruleId, f.evidence);
  }
  for (const path of profile.paths) if (isCredentialPath(path)) add('exec', undefined, path);
  if (profile.tokens.length) add('secrets', undefined, profile.tokens.join(', '));
  for (const f of findings) {
    if (/^IH-CRED-(?!001\b)/.test(f.ruleId)) add('secrets', f.ruleId, f.evidence);
  }
  for (const f of findings) {
    if (f.ruleId === 'IH-NET-001' || f.ruleId === 'IH-NET-002')
      add('undeclared-network', f.ruleId, f.evidence);
  }
  if (hasModel) {
    for (const host of profile.hosts) {
      if (!entry || !hostAllowed(host, entry.network)) add('undeclared-network', undefined, host);
    }
  }
  for (const f of findings) {
    if (f.ruleId === 'IH-FS-001') add('outside-write', f.ruleId, f.evidence);
  }
  for (const path of profile.paths)
    if (!isCredentialPath(path)) add('outside-write', undefined, path);
  if (profile.hosts.length) add('declared-network', undefined, profile.hosts.join(', '));
  add('read-only');
  hits.sort((a, b) => REACH_ORDER[a.level] - REACH_ORDER[b.level]);
  const best = hits[0] as { level: ReachLevel; rule?: string; evidence?: string };
  return {
    level: best.level,
    label: REACH_LABEL[best.level],
    ...(best.rule ? { rule: best.rule } : {}),
    ...(best.evidence ? { evidence: best.evidence } : {}),
  };
}

function modelEntry(
  skills: Record<string, SkillEntryT> | undefined,
  key: string,
): SkillEntryT | undefined {
  if (!skills) return undefined;
  return Object.values(skills).find(
    (entry) => toPosix(entry.path).replace(/^\.\//, '').replace(/\/+$/, '') === key,
  );
}

/** A target is a repository when it has a threat model or one of the usual skill folders. */
async function repoSkillDirs(dir: string): Promise<string[] | null> {
  const found: string[] = [];
  for (const d of SKILL_DIR_GUESSES) if (await isDir(join(dir, d))) found.push(d);
  if (found.length || (await exists(join(dir, MODEL_FILE)))) return found;
  return null;
}

/** Expand an org folder (one level of repositories) or take the target as a single repo. */
export async function resolveRepos(targets: string[]): Promise<string[]> {
  const repos: string[] = [];
  for (const t of targets) {
    const abs = resolve(t);
    if (await repoSkillDirs(abs)) {
      repos.push(abs);
      continue;
    }
    const { readdir } = await import('node:fs/promises');
    let children: string[] = [];
    try {
      children = (await readdir(abs, { withFileTypes: true }))
        .filter((e) => e.isDirectory() && !e.name.startsWith('.') && e.name !== 'node_modules')
        .map((e) => join(abs, e.name));
    } catch {
      children = [];
    }
    const sub: string[] = [];
    for (const c of children) if (await repoSkillDirs(c)) sub.push(c);
    repos.push(...(sub.length ? sub : [abs]));
  }
  return [...new Set(repos)].sort();
}

const URL_RE = /https?:\/\/[^\s)`'"<>\]]+/g;

function runtimeFetchUrls(findings: readonly Finding[]): { urls: string[]; unnamed: number } {
  const urls = new Set<string>();
  let unnamed = 0;
  for (const f of findings) {
    if (f.ruleId !== 'IH-INJ-004') continue;
    const found = (f.evidence ?? '').match(URL_RE) ?? [];
    if (!found.length) unnamed += 1;
    for (const u of found) urls.add(u.replace(/[.,;:]+$/, ''));
  }
  return { urls: [...urls].sort(), unnamed };
}

export interface BuildOptions {
  targets: string[];
  /** Days until the HTML page marks itself expired (default 7). */
  validDays?: number;
  config: ResolvedConfig;
  title?: string;
  ledger?: string;
  history?: HistoryPoint[];
  now?: Date;
  /** 0.24.0 */
  checkIntervalHours?: number;
  refusals?: RefusalEvent[];
  artifacts?: ArtifactRecord[];
  /** Runtime attestation: `repo/path` -> content digest the running agent loaded. */
  loaded?: Record<string, string>;
  /** `repo/path` -> version that fixes the open findings. */
  fixes?: Record<string, string>;
  envId?: string;
  imageDigest?: string;
  receipts?: Array<Record<string, unknown>>;
  reversalWindow?: number;
  verifySlaDays?: number;
  env?: NodeJS.ProcessEnv;
}

export async function buildReport(opts: BuildOptions): Promise<PostureReport> {
  const repos = await resolveRepos(opts.targets);
  const ledger = opts.ledger ? await readLedger(resolve(opts.ledger)) : null;
  const skills: SkillRow[] = [];
  const repoRows: RepoRow[] = [];
  const violations: PostureReport['violations'] = [];
  const driftChanges: PostureReport['driftChanges'] = [];
  const owasp = new Map<string, { findings: number; skills: Set<string>; rules: Set<string> }>();
  const multi = repos.length > 1;
  const base = multi ? resolve(repos[0] as string, '..') : (repos[0] ?? resolve('.'));
  const prevHashes = previousConfigHashes(opts.history ?? []);

  for (const repo of repos) {
    const name = multi ? toPosix(relative(base, repo)) || basename(repo) : basename(repo);
    const modelPath = join(repo, MODEL_FILE);
    const model = (await exists(modelPath)) ? await loadModel(modelPath) : null;
    const dirs = model?.skillDirs ?? (await repoSkillDirs(repo)) ?? [];
    const roots = new Set<string>();
    for (const d of dirs.length ? dirs : ['.']) {
      const abs = resolve(repo, d);
      if (await isDir(abs)) for (const r of await discoverSkillRoots(abs)) roots.add(r);
    }
    const profiles = [];
    const mcp: McpServerDef[] = [];
    for (const f of model?.mcpConfigs ?? []) {
      const abs = resolve(repo, f);
      if (await exists(abs)) mcp.push(...(await readMcpServers(abs, repo)));
    }
    const modelPaths = new Set(
      Object.values(model?.skills ?? {}).map((e) =>
        toPosix(e.path).replace(/^\.\//, '').replace(/\/+$/, ''),
      ),
    );
    for (const root of [...roots].sort()) {
      const report = await scanSkill(root, opts.config);
      const grade = gradeFromSkills([report]);
      // discoverSkillRoots falls back to the folder itself; an empty folder is not a skill.
      if (grade.letter === 'nothing-scanned') continue;
      const profile = await profileSkill(root, repo);
      profile.grade = grade.letter;
      profiles.push(profile);
      const bySeverity: Partial<Record<Severity, number>> = {};
      const ruleCount = new Map<string, number>();
      for (const f of report.findings) {
        bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
        ruleCount.set(f.ruleId, (ruleCount.get(f.ruleId) ?? 0) + 1);
        for (const id of referencesFor(f.ruleId).owaspLlm) {
          const o = owasp.get(id) ?? {
            findings: 0,
            skills: new Set<string>(),
            rules: new Set<string>(),
          };
          o.findings += 1;
          o.skills.add(`${name}/${profile.key}`);
          o.rules.add(f.ruleId);
          owasp.set(id, o);
        }
      }
      const entry = modelEntry(model?.skills, profile.key);
      const keys = await collectConfigKeys(root);
      const mcpExtra = mcp
        .filter(
          (s) =>
            s.name === profile.name ||
            profile.hosts.some((h) => (s.url ?? '').toLowerCase().includes(h.toLowerCase())),
        )
        .map((s) => `mcp:${s.name}:${s.command ?? ''}:${s.url ?? ''}:env=${s.env.join(',')}`);
      const configHash = fingerprintConfig(keys, [...profile.env, ...profile.tokens], mcpExtra);
      const hashId = `${name}/${profile.key}`;
      const regraded = Boolean(
        prevHashes && hashId in prevHashes && prevHashes[hashId] !== configHash,
      );
      let drift: SkillRow['drift'] = null;
      if (ledger) {
        const now = await snapshotSkill(root);
        const before = ledger.skills[now.root];
        const changes = before ? diffSkill(before, now) : [];
        for (const c of changes) driftChanges.push({ ...c, repo: name });
        drift = {
          approved: Boolean(before),
          changes: changes.length,
          high: changes.filter((c) => c.severity === 'high').length,
        };
      }
      const fetched = runtimeFetchUrls(report.findings);
      const reasons: string[] = [];
      const nSkipped = report.filesSkipped.length;
      if (nSkipped)
        reasons.push(
          `${nSkipped} file(s) not read: ${report.filesSkipped
            .slice(0, 3)
            .map((x) => `${x.file} (${x.reason})`)
            .join(', ')}${nSkipped > 3 ? ', ...' : ''}`,
        );
      if (fetched.urls.length)
        reasons.push(`fetches instructions at runtime: ${fetched.urls.join(', ')}`);
      if (fetched.unnamed)
        reasons.push('fetches instructions at runtime from a URL the scan could not read');
      skills.push({
        repo: name,
        skill: report.skillName,
        path: profile.key,
        worstReach: worstReach(report.findings, profile, entry, Boolean(model)),
        grade: grade.letter,
        configHash,
        ...(regraded ? { regraded: true as const } : {}),
        ...(grade.score !== undefined ? { score: grade.score } : {}),
        verdict: report.verdict,
        findings: report.findings.length,
        bySeverity,
        topRules: [...ruleCount.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 3)
          .map(([r]) => r),
        inThreatModel: model ? modelPaths.has(profile.key) : null,
        drift,
        coverage: {
          complete: reasons.length === 0,
          filesRead: report.filesScanned,
          filesSkipped: nSkipped,
          runtimeFetched: fetched.urls,
          reasons,
        },
      });
    }
    let tm: RepoRow['threatModel'] = null;
    if (model) {
      const v = evaluate({ model, base: repo, profiles, mcp, modelFile: MODEL_FILE });
      for (const x of v) violations.push({ ...x, repo: name });
      tm = {
        present: true,
        covered: profiles.filter((p) => modelPaths.has(p.key)).length,
        violations: v.filter((x) => x.severity !== 'info').length,
        high: v.filter((x) => x.severity === 'high').length,
      };
    }
    const mine = skills.filter((s) => s.repo === name);
    repoRows.push({
      repo: name,
      path: repo,
      skills: profiles.length,
      configHash: fingerprintConfig(
        {},
        [],
        [
          ...mine.map((s) => `${s.path}:${s.configHash}`),
          ...mcp.map((s) => `mcp:${s.name}:${s.command ?? ''}:${s.url ?? ''}`),
        ],
      ),
      threatModel: tm,
    });
  }
  const now0 = opts.now ?? new Date();
  const hist = opts.history ?? [];
  const lastPoint = hist[hist.length - 1];
  const hadFindings = new Set(lastPoint?.findingSkills ?? []);
  const rootOf = new Map<string, string>();
  for (const r of repoRows)
    for (const s0 of skills.filter((x) => x.repo === r.repo))
      rootOf.set(`${s0.repo}/${s0.path}`, resolve(r.path, s0.path));
  for (const s0 of skills) {
    const id = `${s0.repo}/${s0.path}`;
    const root = rootOf.get(id) as string;
    s0.stamp = await gradeStamp(
      root,
      s0.grade,
      s0.worstReach.level,
      TOOL_VERSION,
      now0,
      opts.validDays ?? 7,
    );
    const lc = await lifecycleOf(
      root,
      s0.findings,
      hadFindings.has(id),
      s0.stamp.contentHash,
      opts.fixes?.[id],
      opts.loaded?.[id],
    );
    if (lc.state)
      s0.lifecycle = { state: lc.state, installedVersion: lc.installedVersion, gap: lc.gap };
  }
  skills.sort((a, b) => {
    const byReach = REACH_ORDER[a.worstReach.level] - REACH_ORDER[b.worstReach.level];
    if (byReach !== 0) return byReach;
    const byGrade = (GRADE_ORDER[a.grade] ?? 9) - (GRADE_ORDER[b.grade] ?? 9);
    if (byGrade !== 0) return byGrade;
    return a.path.localeCompare(b.path) || a.repo.localeCompare(b.repo);
  });

  const count = <T extends string>(vals: T[]): Record<string, number> =>
    vals.reduce<Record<string, number>>((acc, v) => ({ ...acc, [v]: (acc[v] ?? 0) + 1 }), {});
  const modelled = skills.filter((s) => s.inThreatModel !== null);
  const coverage = modelled.length
    ? Math.round((modelled.filter((s) => s.inThreatModel).length / skills.length) * 1000) / 10
    : null;
  const totals: PostureReport['totals'] = {
    repos: repoRows.length,
    skills: skills.length,
    grades: count(skills.map((s) => s.grade)),
    verdicts: count(skills.map((s) => s.verdict)),
    findings: skills.reduce((a, s) => a + s.findings, 0),
    reposWithThreatModel: repoRows.filter((r) => r.threatModel).length,
    threatModelCoverage: skills.length ? coverage : null,
    driftChanged: skills.filter((s) => s.drift && s.drift.changes > 0).length,
    driftApproved: skills.filter((s) => s.drift?.approved).length,
    coverage: { inspected: 0, loaded: skills.length, complete: true },
    overall: 'nothing-scanned',
    result: '',
  };
  const inspected = skills.filter((s) => s.coverage.complete && s.grade !== 'incomplete');
  totals.coverage = {
    inspected: inspected.length,
    loaded: skills.length,
    complete: inspected.length === skills.length,
  };
  const worst = inspected
    .map((s) => s.grade)
    .sort((a, b) => (GRADE_ORDER[a] ?? 9) - (GRADE_ORDER[b] ?? 9))[0];
  totals.overall = !skills.length
    ? 'nothing-scanned'
    : totals.coverage.complete
      ? (worst ?? 'incomplete')
      : 'incomplete';
  const missing = skills.filter((s) => !inspected.includes(s));
  totals.result = !skills.length
    ? 'nothing scanned: 0 skills found'
    : totals.coverage.complete
      ? `grade ${totals.overall}: ${inspected.length} of ${skills.length} loaded skill(s) fully inspected`
      : `incomplete: ${inspected.length} of ${skills.length} loaded skill(s) fully inspected; not inspected: ${missing
          .map((s) => `${s.repo}/${s.path} (${s.worstReach.label})`)
          .join(', ')}`;
  const now = opts.now ?? new Date();
  const generatedAt = now.toISOString();
  const validUntil = new Date(
    now.getTime() + Math.max(0, opts.validDays ?? 7) * 86_400_000,
  ).toISOString();
  const fingerprint = createHash('sha256')
    .update(
      skills
        .map((s) => `${s.repo}/${s.path}:${s.configHash}:${s.grade}:${s.coverage.complete ? 1 : 0}`)
        .sort()
        .join('\n'),
    )
    .digest('hex');
  const environment = environmentStamp(
    {
      ...(opts.envId ? { envId: opts.envId } : {}),
      ...(opts.imageDigest ? { imageDigest: opts.imageDigest } : {}),
      ...(opts.env ? { env: opts.env } : {}),
    },
    skills.map((s0) => `${s0.repo}/${s0.path}`),
    skills.map((s0) => s0.stamp?.contentHash ?? ''),
  );
  /* lead line, kill switch, lanes */
  const weakest = [...skills].sort(
    (a, b) =>
      (GRADE_ORDER[a.grade] ?? 9) - (GRADE_ORDER[b.grade] ?? 9) ||
      REACH_ORDER[a.worstReach.level] - REACH_ORDER[b.worstReach.level],
  )[0];
  const lead = weakest
    ? `weakest: ${weakest.repo}/${weakest.skill} grade ${weakest.grade}, widest reach ${weakest.worstReach.label}${weakest.worstReach.evidence ? ` (${weakest.worstReach.evidence})` : ''}`
    : 'nothing scanned';
  const crit = skills.find((s0) => (s0.bySeverity.critical ?? 0) > 0);
  const killSwitch = crit
    ? { skill: `${crit.repo}/${crit.skill}`, rule: crit.topRules[0] ?? 'critical finding' }
    : null;
  const prevUnresolved = lastPoint?.unresolved ?? {};
  const containment: LossPath[] = [];
  const verification: LossPath[] = [];
  const sla = opts.verifySlaDays;
  for (const s0 of skills) {
    if (!['exec', 'secrets', 'undeclared-network', 'outside-write'].includes(s0.worstReach.level))
      continue;
    const confirmed =
      s0.verdict === 'block' || (s0.bySeverity.critical ?? 0) + (s0.bySeverity.high ?? 0) > 0;
    const base0: LossPath = {
      repo: s0.repo,
      skill: s0.skill,
      path: s0.path,
      asset: s0.worstReach.label,
      precondition: s0.worstReach.rule ?? s0.worstReach.evidence ?? 'named in the skill files',
      exploitable: confirmed ? 'confirmed' : 'unresolved',
    };
    if (confirmed) containment.push(base0);
    else {
      const id = `${s0.repo}/${s0.path}`;
      const firstSeen = prevUnresolved[id] ?? now0.toISOString();
      const lapsed = sla !== undefined && now0.getTime() - Date.parse(firstSeen) > sla * 86_400_000;
      verification.push({
        ...base0,
        checkNeeded: s0.coverage.complete
          ? `confirm whether ${base0.precondition} is reachable at run time (read the matched lines)`
          : `read what the scan skipped: ${s0.coverage.reasons.join('; ')}`,
        firstSeen,
        status: lapsed ? 'contained-pending-check' : 'open',
      });
    }
  }
  verification.sort(
    (a, b) =>
      REACH_ORDER[
        (skills.find((x) => x.path === a.path && x.repo === a.repo) as SkillRow).worstReach.level
      ] -
      REACH_ORDER[
        (skills.find((x) => x.path === b.path && x.repo === b.repo) as SkillRow).worstReach.level
      ],
  );
  const scored = skills.filter((s0) => typeof s0.score === 'number');
  const cleanupEffort = scored.length
    ? Math.round((scored.reduce((a, s0) => a + (s0.score as number), 0) / scored.length) * 10) / 10
    : null;
  const leftoverRows = await findLeftovers(
    opts.artifacts ?? [],
    new Set(
      skills.flatMap((s0) => [
        s0.skill,
        s0.path,
        `${s0.repo}/${s0.path}`,
        s0.path.split('/').pop() as string,
      ]),
    ),
    repoRows.map((r) => r.path),
    now0,
  );
  if (leftoverRows.some((l) => l.capsGrade) && totals.overall !== 'nothing-scanned') {
    totals.overall = 'F';
    totals.result = `grade F (capped: ${leftoverRows.filter((l) => l.capsGrade).length} live leftover(s) of removed skills); ${totals.result}`;
  }
  if (killSwitch)
    totals.result = `kill switch: ${killSwitch.rule} in ${killSwitch.skill}; ${totals.result}`;
  totals.result = `${totals.result} · checked ${generatedAt.slice(0, 16)}Z on ${environment.id}`;
  const sameEnv = hist.filter((h) => !h.envId || h.envId === environment.id);
  const otherEnv = hist.filter((h) => h.envId && h.envId !== environment.id);
  const changed = lastPoint?.configHashes
    ? skills
        .filter((s0) => {
          const k = `${s0.repo}/${s0.path}`;
          return (
            lastPoint.configHashes &&
            k in lastPoint.configHashes &&
            lastPoint.configHashes[k] !== s0.configHash
          );
        })
        .map((s0) => `${s0.repo}/${s0.path}`)
    : [];
  const point: HistoryPoint = {
    at: generatedAt,
    skills: totals.skills,
    findings: totals.findings,
    block: totals.verdicts.block ?? 0,
    review: totals.verdicts.review ?? 0,
    threatModelCoverage: totals.threatModelCoverage,
    driftChanged: totals.driftChanged,
    configHashes: Object.fromEntries(skills.map((s) => [`${s.repo}/${s.path}`, s.configHash])),
    envId: environment.id,
    inspectedDigest: environment.inspectedDigest,
    changed,
    findingSkills: skills.filter((s0) => s0.findings > 0).map((s0) => `${s0.repo}/${s0.path}`),
    unresolved: Object.fromEntries(
      verification.map((v0) => [`${v0.repo}/${v0.path}`, v0.firstSeen as string]),
    ),
  };
  return {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    title: opts.title ?? 'Agent security posture',
    generatedAt,
    totals,
    fingerprint,
    validUntil,
    owaspLlm: Object.entries(OWASP_LLM_2025).map(([id, name]) => {
      const o = owasp.get(id);
      return {
        id,
        name,
        findings: o?.findings ?? 0,
        skills: o?.skills.size ?? 0,
        rules: [...(o?.rules ?? [])].sort(),
      };
    }),
    repos: repoRows,
    skills,
    violations,
    driftChanges,
    history: [...sameEnv, point],
    environment,
    lead,
    killSwitch,
    lanes: { containment, verification },
    cleanupEffort,
    ...(opts.refusals ? { refusals: refusalRow(opts.refusals) } : {}),
    leftovers: leftoverRows,
    ...(opts.receipts ? { reversal: reversalStats(opts.receipts, opts.reversalWindow ?? 20) } : {}),
    changeLog: [...sameEnv, point]
      .filter((h) => h.changed && h.changed.length)
      .map((h) => ({ at: h.at, changed: h.changed as string[] })),
    otherEnvironments: otherEnv.map((h) => ({
      id: h.envId as string,
      at: h.at,
      skills: h.skills,
      findings: h.findings,
      ...(h.inspectedDigest ? { inspectedDigest: h.inspectedDigest } : {}),
    })),
    ...(opts.checkIntervalHours ? { checkIntervalHours: opts.checkIntervalHours } : {}),
  };
}

export async function readHistory(path: string): Promise<HistoryPoint[]> {
  let raw = '';
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    return [];
  }
  const out: HistoryPoint[] = [];
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      const p = JSON.parse(line) as HistoryPoint;
      if (typeof p.at === 'string' && typeof p.skills === 'number') out.push(p);
    } catch {
      /* skip a bad line */
    }
  }
  return out;
}

export async function appendHistory(path: string, report: PostureReport): Promise<void> {
  const last = report.history[report.history.length - 1];
  if (last) await appendFile(path, JSON.stringify(last) + '\n');
}

/* ---------------- HTML ---------------- */

const e = (v: unknown): string => escapeHtml(String(v ?? ''));

function sparkline(values: number[], w = 220, h = 40): string {
  if (values.length < 2) return '';
  const max = Math.max(...values, 1);
  const step = w / (values.length - 1);
  const pts = values
    .map((v, i) => `${(i * step).toFixed(1)},${(h - (v / max) * (h - 4) - 2).toFixed(1)}`)
    .join(' ');
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="trend"><polyline fill="none" stroke="currentColor" stroke-width="2" points="${pts}"/></svg>`;
}

export function renderPostureHtml(r: PostureReport): string {
  const t = r.totals;
  const gradeOrder = ['A', 'B', 'C', 'D', 'F', 'incomplete', 'nothing-scanned'];
  const card = (label: string, value: string, sub = '') =>
    `<div class="card"><div class="v">${e(value)}</div><div class="l">${e(label)}</div>${sub ? `<div class="s">${sub}</div>` : ''}</div>`;
  const hist = r.history;
  const rows = r.skills
    .map(
      (s) =>
        `<tr class="ih-row" data-graded="${e(s.stamp?.gradedAt ?? r.generatedAt)}" data-until="${e(s.stamp?.validUntil ?? r.validUntil)}"><td>${e(s.worstReach.label)}${s.worstReach.rule ? `<div class="p">${e(s.worstReach.rule)}</div>` : ''}</td><td class="g g-${e(s.grade)}">${e(s.grade)} @ cfg ${e(s.configHash.slice(0, 8))}${s.regraded ? '<div class="p">config changed since last report; grade recomputed</div>' : ''}</td><td>${e(s.repo)}</td><td>${e(s.skill)}<div class="p">${e(s.path)}</div></td><td>${e(s.verdict)}${s.lifecycle ? `<div class="p">${e(s.lifecycle.state)}${s.lifecycle.gap ? `: ${e(s.lifecycle.gap)}` : ''}</div>` : ''}${s.stamp ? `<div class="p">${e(s.stamp.validity)}</div>${s.stamp.evidence.length ? `<div class="p">from: ${e(s.stamp.evidence.join('; '))}</div>` : ''}` : ''}</td><td>${s.findings}</td><td>${s.topRules.map((x) => `<a href="${e(rulePageUrl(x))}">${e(x)}</a>`).join(' ')}</td><td>${s.inThreatModel === null ? '—' : s.inThreatModel ? 'yes' : '<b>no</b>'}</td><td>${s.drift ? (s.drift.approved ? (s.drift.changes ? `<b>${s.drift.changes} change(s)</b>` : 'unchanged') : 'not approved') : '—'}</td></tr>`,
    )
    .join('\n');
  const owasp = r.owaspLlm
    .map(
      (o) =>
        `<tr><td>${e(o.id)}</td><td>${e(o.name)}</td><td>${o.findings}</td><td>${o.skills}</td><td>${o.rules.map((x) => `<a href="${e(rulePageUrl(x))}">${e(x)}</a>`).join(' ') || '—'}</td></tr>`,
    )
    .join('\n');
  const repos = r.repos
    .map(
      (x) =>
        `<tr><td>${e(x.repo)}</td><td>${x.skills}</td><td>${x.threatModel ? `${x.threatModel.covered}/${x.skills}` : 'none'}</td><td>${x.threatModel ? x.threatModel.violations : '—'}</td></tr>`,
    )
    .join('\n');
  const viol = r.violations.length
    ? `<table><thead><tr><th>Repo</th><th>Severity</th><th>Check</th><th>Target</th><th>Detail</th></tr></thead><tbody>${r.violations
        .map(
          (v) =>
            `<tr><td>${e(v.repo)}</td><td>${e(v.severity)}</td><td><code>${e(v.kind)}</code></td><td>${e(v.target)}</td><td>${e(v.detail)}</td></tr>`,
        )
        .join('')}</tbody></table>`
    : '<p>No threat model violations.</p>';
  const missing = r.skills.filter((s) => !s.coverage.complete);
  const notInspected = missing.length
    ? `<p>These skills are not part of the grade. Read them before an agent auto-installs or auto-runs them.</p><table><thead><tr><th>Skill</th><th>Worst reach</th><th>Read</th><th>Why</th></tr></thead><tbody>${missing
        .map(
          (s) =>
            `<tr><td>${e(s.repo)}/${e(s.skill)}<div class="p">${e(s.path)}</div></td><td>${e(s.worstReach.label)}</td><td>${s.coverage.filesRead} of ${s.coverage.filesRead + s.coverage.filesSkipped} file(s), ${s.coverage.runtimeFetched.length ? `0 of ${s.coverage.runtimeFetched.length} fetched at runtime` : 'nothing fetched at runtime'}</td><td>${s.coverage.reasons.map((x) => e(x)).join('<br>')}</td></tr>`,
        )
        .join('')}</tbody></table>`
    : `<p>All ${r.skills.length} loaded skill(s) were fully inspected.</p>`;
  const drift = r.driftChanges.length
    ? `<table><thead><tr><th>Repo</th><th>Severity</th><th>Change</th><th>Skill</th><th>Detail</th></tr></thead><tbody>${r.driftChanges
        .map(
          (d) =>
            `<tr><td>${e(d.repo)}</td><td>${e(d.severity)}</td><td><code>${e(d.kind)}</code></td><td>${e(d.target)}</td><td>${e(d.detail)}</td></tr>`,
        )
        .join('')}</tbody></table>`
    : '<p>No drift since approval (or no ledger given).</p>';
  const lane = (rows0: LossPath[], unresolved: boolean): string =>
    rows0.length
      ? `<table><thead><tr><th>Skill</th><th>Reachable asset</th><th>Precondition</th>${unresolved ? '<th>Check needed</th><th>Status</th>' : ''}</tr></thead><tbody>${rows0
          .map(
            (x) =>
              `<tr><td>${e(x.repo)}/${e(x.skill)}</td><td>${e(x.asset)}</td><td>${e(x.precondition)}</td>${unresolved ? `<td>${e(x.checkNeeded)}</td><td>${e(x.status)}${x.firstSeen ? `<div class="p">since ${e(x.firstSeen)}</div>` : ''}</td>` : ''}</tr>`,
          )
          .join('')}</tbody></table>`
      : '<p>None.</p>';
  const lanesHtml = r.lanes
    ? `<h2>Loss paths</h2><h3>Containment: confirmed exploitable</h3>${lane(r.lanes.containment, false)}<h3>Verification: high impact, preconditions unresolved</h3><p class="p">Unknowns are a verification task, never counted as safe or proven.</p>${lane(r.lanes.verification, true)}`
    : '';
  const refusalHtml = r.refusals
    ? `<h2>Refusals</h2><p>${r.refusals.denials} denial(s) beside ${r.refusals.successes} success(es) · route-around rate ${r.refusals.routeAroundRate ?? '—'} · escalating mutated retries ${r.refusals.escalatingMutations} · after denial: ${
        Object.entries(r.refusals.after)
          .filter(([, n]) => n)
          .map(([k, n]) => `${e(k)} ${n}`)
          .join(', ') || '—'
      }</p>${r.refusals.rows.length ? `<table><thead><tr><th>At</th><th>Skill / tool</th><th>Denial</th><th>Next</th><th>Intent</th><th>Gap</th></tr></thead><tbody>${r.refusals.rows.map((x) => `<tr><td>${e(x.at)}</td><td>${e(x.skill ?? '—')} / ${e(x.tool ?? '—')}</td><td>${e(x.denial)}</td><td>${e(x.next)}</td><td>${e(x.intent ?? '—')}</td><td>${e(x.gap)}</td></tr>`).join('')}</tbody></table>` : ''}`
    : '';
  const leftHtml = r.leftovers?.length
    ? `<h2>Leftovers of removed skills</h2><table><thead><tr><th>Left by</th><th>Kind</th><th>Severity</th><th>Where</th><th>Detail</th></tr></thead><tbody>${r.leftovers.map((x) => `<tr><td>${e(x.skill)}</td><td>${e(x.kind)}</td><td>${e(x.severity)}${x.capsGrade ? ' (caps grade)' : ''}</td><td>${e(x.path ?? '—')}</td><td>${e(x.detail)}<div class="p">${e(x.provenance)}</div></td></tr>`).join('')}</tbody></table>`
    : '';
  const revHtml = r.reversal
    ? `<h2>Reversal rate</h2><p>${e(r.reversal.label)} · shortlist sizes ${e(r.reversal.shortlistSizes.join(', ') || '—')} · late checks ${r.reversal.lateChecks} · median check minus decision ${r.reversal.medianCheckMinusDecisionMs ?? '—'} ms${r.reversal.failedControl ? ' · <b>failed control: checks consistently land after the decision</b>' : ''}</p>`
    : '';
  const changeHtml = r.changeLog?.length
    ? `<h2>Changes between runs</h2><table><thead><tr><th>Run</th><th>Changed skills</th></tr></thead><tbody>${r.changeLog.map((c) => `<tr><td>${e(c.at)}</td><td>${c.changed.map((x) => e(x)).join(', ')}</td></tr>`).join('')}</tbody></table>`
    : '';
  const envHtml = r.environment
    ? `<div class="meta">Environment <code>${e(r.environment.id)}</code>${r.environment.imageDigest ? ` · image <code>${e(r.environment.imageDigest.slice(0, 19))}</code>` : ''} · inspected digest <code>${e(r.environment.inspectedDigest.slice(0, 16))}</code></div>${r.otherEnvironments?.length ? `<h2>Other environments (not in the trend)</h2><div class="banner">These runs came from a different environment; they are shown side by side, never as one trend.</div><table><thead><tr><th>Environment</th><th>Run</th><th>Skills</th><th>Findings</th><th>Inspected digest</th></tr></thead><tbody>${r.otherEnvironments.map((o) => `<tr><td>${e(o.id)}</td><td>${e(o.at)}</td><td>${o.skills}</td><td>${o.findings}</td><td><code>${e((o.inspectedDigest ?? '').slice(0, 16))}</code></td></tr>`).join('')}</tbody></table>` : ''}`
    : '';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${e(r.title)} — Ironheights</title>
<style>
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;color:#111;background:#fafafa}
main{max-width:1100px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px}h2{margin-top:36px}
.meta{color:#555}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:20px 0}
.card{background:#fff;border:1px solid #e5e5e5;border-radius:12px;padding:14px}.v{font-size:26px;font-weight:650}.l{color:#555}.s{color:#777;font-size:13px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e5e5;border-radius:8px;font-size:14px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #eee;vertical-align:top}th{background:#f3f3f3}
.p{color:#777;font-size:12px}.g{font-weight:700}.g-A{color:#15803d}.g-B{color:#4d7c0f}.g-C{color:#a16207}.g-D{color:#c2410c}.g-F{color:#b91c1c}
code{font-size:13px}a{color:#1d4ed8}footer{margin-top:40px;color:#666;font-size:13px}
tr.ih-degraded td{opacity:.7}tr.ih-grey td{opacity:.4;filter:grayscale(1)}tr.ih-hidden td.g{color:transparent!important;text-shadow:none}tr.ih-hidden td.g::after{content:attr(data-ts);color:#777}.banner{background:#fde68a;border:1px solid #d97706;padding:10px 12px;border-radius:8px;margin:8px 0}.result{font-size:18px;font-weight:650;margin:6px 0}.result.inc{color:#b45309}body.expired main>*:not(#ih-expired){opacity:.45}
@media print{body{background:#fff}.card,table{break-inside:avoid}}
</style></head><body><main>
<h1>${e(r.title)}</h1>
<div id="ih-expired" class="banner" hidden>This report expired on ${e(r.validUntil)}. It describes the skills as they were on ${e(r.generatedAt)}. Run <code>ironheights report</code> again and compare the fingerprint.</div>
${r.lead ? `<div class="result lead">${e(r.lead)}</div>` : ''}
<div class="result ${t.coverage.complete ? '' : 'inc'}">${e(t.result)}</div>
<div class="meta">Generated ${e(r.generatedAt)} by ${e(r.tool)} ${e(r.version)} · ${t.repos} repo(s) · local scan, no telemetry · valid until ${e(r.validUntil)} · fingerprint <code>${e(r.fingerprint.slice(0, 16))}</code></div>
${envHtml}
<div class="cards">
${card('Overall', t.overall, `${t.coverage.inspected} of ${t.coverage.loaded} fully inspected`)}
${card('Skills installed', String(t.skills))}
${card('Blocked', String(t.verdicts.block ?? 0), hist.length > 1 ? sparkline(hist.map((h) => h.block)) : '')}
${card('Need review', String(t.verdicts.review ?? 0), hist.length > 1 ? sparkline(hist.map((h) => h.review)) : '')}
${card('Findings', String(t.findings), hist.length > 1 ? sparkline(hist.map((h) => h.findings)) : '')}
${card('Threat model coverage', t.threatModelCoverage === null ? 'no model' : `${t.threatModelCoverage}%`, `${t.reposWithThreatModel}/${t.repos} repo(s) with a model`)}
${card('Changed since approval', String(t.driftChanged), `${t.driftApproved} skill(s) approved`)}
</div>
<h2>Grades</h2>
<p>${
    gradeOrder
      .filter((g) => t.grades[g])
      .map((g) => `<span class="g g-${e(g)}">${e(g)}</span>: ${t.grades[g]}`)
      .join(' · ') || 'No skills found.'
  }</p>
<h2>OWASP Top 10 for LLM Applications 2025</h2>
<table><thead><tr><th>Id</th><th>Risk</th><th>Findings</th><th>Skills</th><th>Ironheights rules</th></tr></thead><tbody>${owasp}</tbody></table>
<h2>Repositories</h2>
<table><thead><tr><th>Repo</th><th>Skills</th><th>In threat model</th><th>Violations</th></tr></thead><tbody>${repos}</tbody></table>
<h2>Skill inventory</h2>
<table><thead><tr><th>Worst reach</th><th>Grade</th><th>Repo</th><th>Skill</th><th>Verdict</th><th>Findings</th><th>Top rules</th><th>In model</th><th>Drift</th></tr></thead><tbody>${rows}</tbody></table>
${lanesHtml}
<h2>Not fully inspected</h2>${notInspected}
${refusalHtml}
${leftHtml}
${revHtml}
${changeHtml}
<h2>Threat model violations</h2>${viol}
<h2>Drift since approval</h2>${drift}
${hist.length > 1 ? `<h2>Trend</h2><table><thead><tr><th>Run</th><th>Skills</th><th>Findings</th><th>Block</th><th>Review</th><th>Coverage</th><th>Drifted</th></tr></thead><tbody>${hist.map((h) => `<tr><td>${e(h.at)}</td><td>${h.skills}</td><td>${h.findings}</td><td>${h.block}</td><td>${h.review}</td><td>${h.threatModelCoverage ?? '—'}</td><td>${h.driftChanged}</td></tr>`).join('')}</tbody></table>` : ''}
${r.cleanupEffort !== null && r.cleanupEffort !== undefined ? `<p class="p">Average score ${r.cleanupEffort}: a cleanup-effort measure, not a safety measure.</p>` : ''}
<footer>Ironheights protects any AI bot that installs it. A grade reports what the rules matched in the files scanned; no findings is not proof of safety. OWASP mapping from each rule's references. https://www.ironheights.dev</footer>
</main><script>(function(){var u=Date.parse(${JSON.stringify(r.validUntil)});if(Date.now()>u){document.body.className+=' expired';var b=document.getElementById('ih-expired');if(b)b.hidden=false;}var iv=${JSON.stringify((r.checkIntervalHours ?? 0) * 3600000)};var rows=document.querySelectorAll('tr.ih-row');for(var i=0;i<rows.length;i++){var tr=rows[i];var g=Date.parse(tr.getAttribute('data-graded'));var until=Date.parse(tr.getAttribute('data-until'));var age=Date.now()-g;var lvl=iv?Math.floor(age/iv):0;if(Date.now()>until&&lvl<2)lvl=2;var c=tr.querySelector('td.g');if(c)c.setAttribute('data-ts','graded '+tr.getAttribute('data-graded'));if(lvl>=3)tr.className+=' ih-grey ih-hidden';else if(lvl>=2)tr.className+=' ih-grey';else if(lvl>=1)tr.className+=' ih-degraded';}})();</script></body></html>
`;
}
