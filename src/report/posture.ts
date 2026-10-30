/**
 * Agent security posture report (`ironheights report`).
 *
 * One report for a repository or a whole organisation checkout: every installed skill with its
 * grade and verdict, drift since approval, threat-model coverage, findings mapped to the OWASP
 * Top 10 for LLM Applications 2025, and a trend from earlier runs (`--history`). JSON and a
 * self-contained HTML page for audits. Local only: no network, no telemetry.
 */
import { appendFile, readFile, stat } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';

import { gradeFromSkills } from '../core/grade.ts';
import { discoverSkillRoots, scanSkill } from '../core/scanner.ts';
import type { ResolvedConfig, Severity, Verdict } from '../core/types.ts';
import { diffSkill, readLedger, snapshotSkill, type DriftChange } from '../drift/drift.ts';
import { escapeHtml } from '../cli/output/html.ts';
import { referencesFor, rulePageUrl } from '../rules/references.ts';
import {
  MODEL_FILE,
  evaluate,
  loadModel,
  profileSkill,
  readMcpServers,
  toPosix,
  type Violation,
} from '../threatmodel/threatmodel.ts';
import { TOOL_NAME, TOOL_VERSION } from '../version.ts';

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

export interface SkillRow {
  repo: string;
  skill: string;
  path: string;
  grade: string;
  score?: number;
  verdict: Verdict;
  findings: number;
  bySeverity: Partial<Record<Severity, number>>;
  topRules: string[];
  inThreatModel: boolean | null;
  drift: { approved: boolean; changes: number; high: number } | null;
}

export interface RepoRow {
  repo: string;
  path: string;
  skills: number;
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
  };
  owaspLlm: Array<{ id: string; name: string; findings: number; skills: number; rules: string[] }>;
  repos: RepoRow[];
  skills: SkillRow[];
  violations: Array<Violation & { repo: string }>;
  driftChanges: Array<DriftChange & { repo: string }>;
  history: HistoryPoint[];
}

export interface HistoryPoint {
  at: string;
  skills: number;
  findings: number;
  block: number;
  review: number;
  threatModelCoverage: number | null;
  driftChanged: number;
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

export interface BuildOptions {
  targets: string[];
  config: ResolvedConfig;
  title?: string;
  ledger?: string;
  history?: HistoryPoint[];
  now?: Date;
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
    const modelPaths = new Set(
      Object.values(model?.skills ?? {}).map((e) =>
        toPosix(e.path).replace(/^\.\//, '').replace(/\/+$/, ''),
      ),
    );
    for (const root of [...roots].sort()) {
      const report = await scanSkill(root, opts.config);
      const grade = gradeFromSkills([report]);
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
      skills.push({
        repo: name,
        skill: report.skillName,
        path: profile.key,
        grade: grade.letter,
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
      });
    }
    let tm: RepoRow['threatModel'] = null;
    if (model) {
      const mcp = [];
      for (const f of model.mcpConfigs) {
        const abs = resolve(repo, f);
        if (await exists(abs)) mcp.push(...(await readMcpServers(abs, repo)));
      }
      const v = evaluate({ model, base: repo, profiles, mcp, modelFile: MODEL_FILE });
      for (const x of v) violations.push({ ...x, repo: name });
      tm = {
        present: true,
        covered: profiles.filter((p) => modelPaths.has(p.key)).length,
        violations: v.filter((x) => x.severity !== 'info').length,
        high: v.filter((x) => x.severity === 'high').length,
      };
    }
    repoRows.push({ repo: name, path: repo, skills: profiles.length, threatModel: tm });
  }

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
  };
  const generatedAt = (opts.now ?? new Date()).toISOString();
  const point: HistoryPoint = {
    at: generatedAt,
    skills: totals.skills,
    findings: totals.findings,
    block: totals.verdicts.block ?? 0,
    review: totals.verdicts.review ?? 0,
    threatModelCoverage: totals.threatModelCoverage,
    driftChanged: totals.driftChanged,
  };
  return {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    title: opts.title ?? 'Agent security posture',
    generatedAt,
    totals,
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
    history: [...(opts.history ?? []), point],
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
        `<tr><td>${e(s.repo)}</td><td>${e(s.skill)}<div class="p">${e(s.path)}</div></td><td class="g g-${e(s.grade)}">${e(s.grade)}</td><td>${e(s.verdict)}</td><td>${s.findings}</td><td>${s.topRules.map((x) => `<a href="${e(rulePageUrl(x))}">${e(x)}</a>`).join(' ')}</td><td>${s.inThreatModel === null ? '—' : s.inThreatModel ? 'yes' : '<b>no</b>'}</td><td>${s.drift ? (s.drift.approved ? (s.drift.changes ? `<b>${s.drift.changes} change(s)</b>` : 'unchanged') : 'not approved') : '—'}</td></tr>`,
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
  const drift = r.driftChanges.length
    ? `<table><thead><tr><th>Repo</th><th>Severity</th><th>Change</th><th>Skill</th><th>Detail</th></tr></thead><tbody>${r.driftChanges
        .map(
          (d) =>
            `<tr><td>${e(d.repo)}</td><td>${e(d.severity)}</td><td><code>${e(d.kind)}</code></td><td>${e(d.target)}</td><td>${e(d.detail)}</td></tr>`,
        )
        .join('')}</tbody></table>`
    : '<p>No drift since approval (or no ledger given).</p>';
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
@media print{body{background:#fff}.card,table{break-inside:avoid}}
</style></head><body><main>
<h1>${e(r.title)}</h1>
<div class="meta">Generated ${e(r.generatedAt)} by ${e(r.tool)} ${e(r.version)} · ${t.repos} repo(s) · local scan, no telemetry</div>
<div class="cards">
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
<table><thead><tr><th>Repo</th><th>Skill</th><th>Grade</th><th>Verdict</th><th>Findings</th><th>Top rules</th><th>In model</th><th>Drift</th></tr></thead><tbody>${rows}</tbody></table>
<h2>Threat model violations</h2>${viol}
<h2>Drift since approval</h2>${drift}
${hist.length > 1 ? `<h2>Trend</h2><table><thead><tr><th>Run</th><th>Skills</th><th>Findings</th><th>Block</th><th>Review</th><th>Coverage</th><th>Drifted</th></tr></thead><tbody>${hist.map((h) => `<tr><td>${e(h.at)}</td><td>${h.skills}</td><td>${h.findings}</td><td>${h.block}</td><td>${h.review}</td><td>${h.threatModelCoverage ?? '—'}</td><td>${h.driftChanged}</td></tr>`).join('')}</tbody></table>` : ''}
<footer>Ironheights protects any AI bot that installs it. A grade reports what the rules matched in the files scanned; no findings is not proof of safety. OWASP mapping from each rule's references. https://www.ironheights.dev</footer>
</main></body></html>
`;
}
