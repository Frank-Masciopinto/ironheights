import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { promisify } from 'node:util';
import { loadConfig } from '../../core/config.ts';
import { UsageError } from '../../core/errors.ts';
import { gradeFromSkills } from '../../core/grade.ts';
import { discoverSkillRoots, scanSkill } from '../../core/scanner.ts';
import { diffSkill, readLedger, snapshotSkill } from '../../drift/drift.ts';
import {
  assessClaims,
  claimViolations,
  type ClaimResult,
  type UncoveredCapability,
} from '../../threatmodel/claims.ts';
import {
  MODEL_FILE,
  evaluate,
  exitCodeFor,
  loadModel,
  modelFromProfiles,
  parseModel,
  profileSkill,
  readMcpServers,
  renderModelYaml,
  toPosix,
  widened,
  type McpServerDef,
  type SkillProfile,
  type ThreatModel,
  type Violation,
} from '../../threatmodel/threatmodel.ts';
import {
  evaluateExtras,
  folderViolations,
  lockAndReasonChanges,
  profileExtras,
  readLock,
  reviewTier,
  triggerChanges,
  undeclaredSkillFolders,
  type ExtraProfile,
  type ExtrasResult,
  type ReviewResult,
} from '../../threatmodel/extras.ts';
import { REPOSITORY_URL, TOOL_NAME, TOOL_VERSION } from '../../version.ts';

const run = promisify(execFile);

export interface ThreatModelFlags {
  action: string | undefined;
  dir?: string;
  model?: string;
  skillDirs?: string[];
  mcp?: string[];
  base?: string;
  ledger?: string;
  noGrade?: boolean;
  /** Exit 2 when a capability is not mentioned anywhere in the model. */
  failOnUncovered?: boolean;
  /** diff: fail when a capability passes only because the same change widened the model. */
  failOnWiden?: boolean;
  /** diff: review tier for widenings (reasons, non-author approval). Also on with modelChanges: review. */
  review?: boolean;
  /** diff: PR author login, and whether an agent authored the change. */
  author?: string;
  authorKind?: 'human' | 'agent';
  /** diff: logins that approved the change. */
  approvers?: string[];
  force?: boolean;
  json?: boolean;
  markdown?: string;
  sarif?: string;
  config?: string;
  env?: NodeJS.ProcessEnv;
  out?: (line: string) => void;
}

export interface ThreatModelReport {
  tool: string;
  version: string;
  modelFile: string;
  checkedAt: string;
  base?: string;
  /** Commits this result covers (git). Anything after `head` was not checked. */
  covered?: { base?: string; head?: string; dirty?: boolean };
  /** Model skill folders that do not exist, so nothing in them was checked. */
  notChecked?: string[];
  skills: number;
  mcpServers: number;
  violations: Violation[];
  /** Only for diff: violations that exist at head but not at base. */
  introduced?: Violation[];
  /** Per-claim results. Untested claims do not change the exit code. */
  claims?: ClaimResult[];
  /** Capabilities no claim mentions. Informational unless failing is opted in. */
  uncovered?: UncoveredCapability[];
  /** 0.24.0: writes seen but not declared, for a human to accept (persistence never auto-added). */
  proposedWrites?: ExtrasResult['proposedWrites'];
  /** 0.24.0 diff: changed files counted against the declared scope, so outside is never zero by construction. */
  scope?: { changedFiles: number; inScope: number; outsideScope: string[] };
  /** 0.24.0 diff: self-approved marks waiting for a different reader. */
  selfApproved?: ReviewResult['selfApproved'];
  /** 0.24.0 diff: how many model changes the extractor could classify. */
  extractorHealth?: ReviewResult['extractorHealth'];
  exitCode: number;
}

async function gitSha(dir: string, ref: string): Promise<string | undefined> {
  try {
    const { stdout } = await run('git', ['-C', dir, 'rev-parse', '--verify', `${ref}^{commit}`]);
    return stdout.trim() || undefined;
  } catch {
    return undefined;
  }
}

async function coveredRange(dir: string, base?: string): Promise<ThreatModelReport['covered']> {
  const head = await gitSha(dir, 'HEAD');
  if (!head) return undefined;
  let dirty = false;
  try {
    const { stdout } = await run('git', ['-C', dir, 'status', '--porcelain']);
    dirty = stdout.trim().length > 0;
  } catch {
    dirty = false;
  }
  const b = base ? await gitSha(dir, base) : undefined;
  return { ...(b ? { base: b } : {}), head, ...(dirty ? { dirty } : {}) };
}

async function missingDirs(dir: string, dirs: string[]): Promise<string[]> {
  const out: string[] = [];
  for (const d of dirs) if (!(await exists(resolve(dir, d)))) out.push(d);
  return out;
}

async function exists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

async function collect(
  base: string,
  skillDirs: string[],
  mcpFiles: string[],
  grade: boolean,
  flags: ThreatModelFlags,
): Promise<{ profiles: SkillProfile[]; mcp: McpServerDef[] }> {
  const roots = new Set<string>();
  for (const d of skillDirs) {
    const abs = resolve(base, d);
    if (await exists(abs)) for (const r of await discoverSkillRoots(abs)) roots.add(r);
  }
  const profiles: SkillProfile[] = [];
  const config = await loadConfig({
    ...(flags.config ? { explicitPath: flags.config } : {}),
    env: flags.env ?? process.env,
  });
  for (const r of [...roots].sort()) {
    const p = await profileSkill(r, base);
    const report = await scanSkill(r, config);
    if (grade) p.grade = gradeFromSkills([report]).letter;
    p.remoteInstructionsHit = report.findings.some((f) => f.ruleId === 'IH-INJ-004');
    profiles.push(p);
  }
  const mcp: McpServerDef[] = [];
  for (const f of mcpFiles) {
    const abs = resolve(base, f);
    if (await exists(abs)) mcp.push(...(await readMcpServers(abs, base)));
  }
  return { profiles, mcp };
}

async function checkAt(
  base: string,
  model: ThreatModel,
  modelFile: string,
  flags: ThreatModelFlags,
): Promise<{
  violations: Violation[];
  skills: number;
  mcp: number;
  profiles: SkillProfile[];
  mcpServers: McpServerDef[];
  extras: ExtraProfile[];
  proposedWrites: ExtrasResult['proposedWrites'];
}> {
  const { profiles, mcp } = await collect(
    base,
    flags.skillDirs?.length ? flags.skillDirs : model.skillDirs,
    [...model.mcpConfigs, ...(flags.mcp ?? [])],
    !flags.noGrade,
    flags,
  );
  const violations = evaluate({ model, base, profiles, mcp, modelFile });
  const extras: ExtraProfile[] = [];
  for (const p of profiles) extras.push(await profileExtras(p));
  const ex = evaluateExtras(model, profiles, extras);
  // A fallback host is reported once, as the named code branch.
  const fb = new Set(
    ex.violations
      .filter((x) => x.kind === 'fallback-host' && x.severity === 'high')
      .map((x) => `${x.target}|${/sends to (\S+)/.exec(x.detail)?.[1] ?? ''}`),
  );
  const kept = violations.filter(
    (x) => !(x.kind === 'host-not-allowed' && fb.has(`${x.target}|${x.detail}`)),
  );
  violations.length = 0;
  violations.push(...kept, ...ex.violations);
  const outside = await undeclaredSkillFolders(
    base,
    flags.skillDirs?.length ? flags.skillDirs : model.skillDirs,
  );
  if (outside.length) {
    const fp: SkillProfile[] = [];
    for (const k of outside) fp.push(await profileSkill(resolve(base, k), base));
    violations.push(...folderViolations(model, fp));
  }
  if (flags.ledger) {
    const ledger = await readLedger(resolve(flags.ledger));
    for (const p of profiles) {
      const before = ledger.skills[p.root];
      if (!before) continue;
      for (const c of diffSkill(before, await snapshotSkill(p.root)))
        violations.push({
          kind: 'drift',
          severity: c.severity,
          target: p.key,
          detail: `${c.kind}: ${c.detail}`,
          file: `${p.key}/SKILL.md`,
        });
    }
  }
  return {
    violations,
    skills: profiles.length,
    mcp: mcp.length,
    profiles,
    mcpServers: mcp,
    extras,
    proposedWrites: ex.proposedWrites,
  };
}

function withClaims(
  model: ThreatModel,
  flags: ThreatModelFlags,
  head: { violations: Violation[]; profiles: SkillProfile[]; mcpServers: McpServerDef[] },
  base: { profiles: SkillProfile[]; mcpServers: McpServerDef[] } | undefined,
  diff: boolean,
): { violations: Violation[]; claims: ClaimResult[]; uncovered: UncoveredCapability[] } {
  const assessed = assessClaims({
    model,
    profiles: head.profiles,
    mcp: head.mcpServers,
    ...(base ? { baseProfiles: base.profiles, baseMcp: base.mcpServers } : {}),
    diff,
  });
  const extra = claimViolations({
    model,
    claims: assessed.claims,
    uncovered: assessed.uncovered,
    existing: head.violations,
    failOnUncovered: Boolean(flags.failOnUncovered),
  });
  return {
    violations: [...head.violations, ...extra],
    claims: assessed.claims,
    uncovered: assessed.uncovered,
  };
}

export async function runThreatModel(flags: ThreatModelFlags): Promise<number> {
  const out = flags.out ?? ((l: string) => process.stdout.write(l + '\n'));
  const action = flags.action ?? 'check';
  const dir = resolve(flags.dir ?? '.');
  const modelPath = resolve(dir, flags.model ?? MODEL_FILE);
  const modelFile = toPosix(relative(dir, modelPath));
  if (action === 'init') return init(flags, dir, modelPath, out);
  if (action === 'check') {
    const model = await loadModel(modelPath);
    const r = await checkAt(dir, model, modelFile, flags);
    const assessed = withClaims(model, flags, r, undefined, false);
    const covered = await coveredRange(dir);
    const notChecked = await missingDirs(
      dir,
      flags.skillDirs?.length ? flags.skillDirs : model.skillDirs,
    );
    return emit(flags, out, {
      tool: TOOL_NAME,
      version: TOOL_VERSION,
      modelFile,
      checkedAt: new Date().toISOString(),
      ...(covered ? { covered } : {}),
      ...(notChecked.length ? { notChecked } : {}),
      skills: r.skills,
      mcpServers: r.mcp,
      violations: assessed.violations,
      claims: assessed.claims,
      uncovered: assessed.uncovered,
      ...(r.proposedWrites.length ? { proposedWrites: r.proposedWrites } : {}),
      exitCode: exitCodeFor(assessed.violations),
    });
  }
  if (action === 'diff') return diff(flags, dir, modelPath, modelFile, out);
  throw new UsageError('threatmodel action must be init, check, or diff');
}

async function init(
  flags: ThreatModelFlags,
  dir: string,
  modelPath: string,
  out: (l: string) => void,
): Promise<number> {
  if ((await exists(modelPath)) && !flags.force)
    throw new UsageError(`${modelPath} already exists (use --force to overwrite)`);
  const skillDirs = flags.skillDirs?.length
    ? flags.skillDirs
    : (
        await Promise.all(
          ['skills', '.claude/skills', '.cursor/skills', '.agents/skills', 'skill'].map(
            async (d) => ((await exists(join(dir, d))) ? d : null),
          ),
        )
      ).filter((d): d is string => d !== null);
  const mcpConfigs = flags.mcp?.length
    ? flags.mcp
    : (
        await Promise.all(
          ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json', 'mcp.json'].map(async (f) =>
            (await exists(join(dir, f))) ? f : null,
          ),
        )
      ).filter((d): d is string => d !== null);
  const dirs = skillDirs.length ? skillDirs : ['skills'];
  const { profiles, mcp } = await collect(dir, dirs, mcpConfigs, !flags.noGrade, flags);
  const model = modelFromProfiles(profiles, mcp, { skillDirs: dirs, mcpConfigs });
  const yaml = renderModelYaml(model);
  parseModel(yaml);
  await writeFile(modelPath, yaml);
  out(
    `wrote ${toPosix(relative(dir, modelPath))}: ${profiles.length} skill(s), ${mcp.length} MCP server(s). Review every allowed host, path, token and shell flag before you commit it.`,
  );
  return 0;
}

async function diff(
  flags: ThreatModelFlags,
  dir: string,
  modelPath: string,
  modelFile: string,
  out: (l: string) => void,
): Promise<number> {
  if (!flags.base) throw new UsageError('threatmodel diff needs --base <git ref>');
  if (!/^[\w./@~^-]+$/.test(flags.base) || flags.base.startsWith('-'))
    throw new UsageError('--base must be a git ref');
  const headModel = await loadModel(modelPath);
  const head = await checkAt(dir, headModel, modelFile, flags);
  const tmp = await mkdtemp(join(tmpdir(), 'ih-tm-base-'));
  let baseSnapshot:
    | { violations: Violation[]; profiles: SkillProfile[]; mcpServers: McpServerDef[] }
    | undefined;
  let modelChanges: Violation[] = [];
  let sameChange: Violation[] = [];
  let extra: Violation[] = [];
  let review: ReviewResult | undefined;
  let scope: ThreatModelReport['scope'];
  const lockPairs: Parameters<typeof lockAndReasonChanges>[1] = [];
  try {
    // --show-prefix avoids comparing long and short (8.3) temp paths on Windows.
    const { stdout: prefix } = await run('git', ['-C', dir, 'rev-parse', '--show-prefix']);
    const { stdout: cdup } = await run('git', ['-C', dir, 'rev-parse', '--show-cdup']);
    const sub = prefix.trim().replace(/\/+$/, '');
    const treeish = sub ? `${flags.base}:${sub}` : flags.base;
    // Run from the top level (relative --show-cdup avoids long vs 8.3 paths on Windows):
    // git archive inside a subdirectory only archives that subdirectory.
    await run('git', ['archive', '--format=tar', '-o', join(tmp, 'base.tar'), treeish], {
      cwd: resolve(dir, cdup.trim() || '.'),
    });
    await run('tar', ['-xf', 'base.tar'], { cwd: tmp });
    const baseDir = tmp;
    const baseModelPath = join(baseDir, modelFile);
    if (await exists(baseModelPath)) {
      const baseModel = parseModel(
        await readFile(baseModelPath, 'utf8'),
        `${flags.base}:${modelFile}`,
      );
      // Base skills measured against the head model, so a widened model does not hide anything.
      const base = await checkAt(baseDir, headModel, modelFile, { ...flags, ledger: undefined });
      const baseAssessed = withClaims(headModel, flags, base, undefined, false);
      baseSnapshot = {
        violations: baseAssessed.violations,
        profiles: base.profiles,
        mcpServers: base.mcpServers,
      };
      modelChanges = widened(baseModel, headModel, modelFile);
      const strictTriggers =
        baseModel.defaults.triggers === 'require' || baseModel.defaults.modelChanges !== 'note';
      extra.push(...triggerChanges(headModel, base.extras, head.extras, strictTriggers));
      for (const [id, e] of Object.entries(headModel.skills)) {
        const key = toPosix(e.path).replace(/^\.\//, '').replace(/\/+$/, '');
        lockPairs.push({
          id,
          key,
          base: await readLock(join(baseDir, key)),
          head: await readLock(join(dir, key)),
        });
      }
      const modelFileChanged =
        (await readFile(baseModelPath, 'utf8')) !== (await readFile(modelPath, 'utf8'));
      if (flags.review || baseModel.defaults.modelChanges === 'review') {
        review = await reviewTier({
          baseModel,
          headModel,
          widenings: modelChanges,
          modelFileChanged,
          ...(flags.author ? { author: flags.author } : {}),
          ...(flags.authorKind ? { authorKind: flags.authorKind } : {}),
          approvers: flags.approvers ?? [],
          baseHas: (rel) => exists(join(baseDir, rel)),
        });
        extra.push(...review.violations);
      }
      if (flags.failOnWiden || baseModel.defaults.modelChanges === 'fail') {
        // Head skills against the base model, minus what the base already violated there.
        const headVsBase = await checkAt(dir, baseModel, modelFile, {
          ...flags,
          ledger: undefined,
        });
        const baseVsBase = await checkAt(baseDir, baseModel, modelFile, {
          ...flags,
          ledger: undefined,
        });
        const k = (v: Violation): string => `${v.kind}|${v.target}|${v.detail}`;
        const known = new Set(baseVsBase.violations.map(k));
        const headKeys = new Set(head.violations.map(k));
        sameChange = headVsBase.violations
          .filter((v) => v.severity !== 'info' && !known.has(k(v)) && !headKeys.has(k(v)))
          .map((v) => ({
            kind: 'widened-in-same-change' as const,
            severity: 'high' as const,
            target: v.target,
            detail: `${v.kind}: ${v.detail} (allowed only by a model change in this same PR; land the model change on its own first)`,
            file: v.file ?? modelFile,
          }));
      }
    } else {
      modelChanges = [
        {
          kind: 'model-widened',
          severity: 'info',
          target: modelFile,
          detail: 'threat model added in this change',
          file: modelFile,
        },
      ];
    }
  } catch (error) {
    if (error instanceof UsageError) throw error;
    throw new UsageError(
      `cannot read base ref ${flags.base}: ${(error as Error).message.split('\n')[0]}`,
    );
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
  try {
    const { stdout } = await run('git', ['-C', dir, 'diff', '--name-only', flags.base, '--', '.']);
    const { stdout: prefix } = await run('git', ['-C', dir, 'rev-parse', '--show-prefix']);
    const sub = prefix.trim();
    const changed = stdout
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => (sub && l.startsWith(sub) ? l.slice(sub.length) : l));
    const dirs = (flags.skillDirs?.length ? flags.skillDirs : headModel.skillDirs).map((d) =>
      d.replace(/^\.\//, '').replace(/\/+$/, ''),
    );
    const inScope = (f: string): boolean =>
      f === modelFile ||
      headModel.mcpConfigs.includes(f) ||
      dirs.some((d) => f === d || f.startsWith(d + '/'));
    const out = changed.filter((f) => !inScope(f));
    scope = {
      changedFiles: changed.length,
      inScope: changed.length - out.length,
      outsideScope: out,
    };
    for (const f of out) {
      if (
        !/\.(?:m?[jt]s|py|sh|bash|zsh|rb|go|json|ya?ml|toml)$|(?:^|\/)SKILL\.md$|(?:^|\/)Dockerfile$/.test(
          f,
        )
      )
        continue;
      const body = await readFile(join(dir, f), 'utf8').catch(() => '');
      const authority =
        /https?:\/\/|child_process|subprocess|process\.env|os\.environ|\bcurl\b|\bexec\(/.test(
          body,
        );
      if (authority)
        extra.push({
          kind: 'changed-outside-scope',
          severity: headModel.defaults.undeclaredFolders === 'fail' ? 'high' : 'medium',
          target: f,
          detail:
            'changed file outside every declared skill dir names hosts, env or processes; the model never searched it',
          file: f,
        });
    }
  } catch {
    scope = undefined;
  }
  const headAssessed = withClaims(headModel, flags, head, baseSnapshot, true);
  const key = (v: Violation): string => `${v.kind}|${v.target}|${v.detail}`;
  const before = new Set((baseSnapshot?.violations ?? []).map(key));
  const introduced0 = [
    ...headAssessed.violations.filter((v) => !before.has(key(v))),
    ...sameChange,
  ];
  extra.push(
    ...lockAndReasonChanges(
      headModel,
      lockPairs,
      introduced0.some((v) => v.severity !== 'info'),
    ),
  );
  extra = extra.filter((v, i, a) => a.findIndex((x) => key(x) === key(v)) === i);
  const introduced = [...introduced0, ...extra];
  const violations = [...headAssessed.violations, ...sameChange, ...extra, ...modelChanges];
  const covered = await coveredRange(dir, flags.base);
  const notChecked = await missingDirs(
    dir,
    flags.skillDirs?.length ? flags.skillDirs : headModel.skillDirs,
  );
  return emit(flags, out, {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    modelFile,
    checkedAt: new Date().toISOString(),
    base: flags.base,
    ...(covered ? { covered } : {}),
    ...(notChecked.length ? { notChecked } : {}),
    skills: head.skills,
    mcpServers: head.mcp,
    violations,
    introduced: [...introduced, ...modelChanges],
    claims: headAssessed.claims,
    uncovered: headAssessed.uncovered,
    ...(head.proposedWrites.length ? { proposedWrites: head.proposedWrites } : {}),
    ...(scope ? { scope } : {}),
    ...(review
      ? { selfApproved: review.selfApproved, extractorHealth: review.extractorHealth }
      : {}),
    exitCode: exitCodeFor(introduced),
  });
}

async function emit(
  flags: ThreatModelFlags,
  out: (l: string) => void,
  r: ThreatModelReport,
): Promise<number> {
  if (flags.markdown) await writeFile(resolve(flags.markdown), renderMarkdown(r));
  if (flags.sarif) await writeFile(resolve(flags.sarif), renderTmSarif(r));
  if (flags.json) out(JSON.stringify(r, null, 2));
  else {
    const list = r.introduced ?? r.violations;
    if (list.length === 0)
      out(
        `threat model ok: ${r.skills} skill(s), ${r.mcpServers} MCP server(s) inside ${r.modelFile}`,
      );
    for (const v of list)
      out(`${v.severity.toUpperCase().padEnd(6)} ${v.kind}  ${v.target}  ${v.detail}`);
    if (r.covered?.head)
      out(
        `covers ${r.covered.base ? `${r.covered.base.slice(0, 12)}..` : ''}${r.covered.head.slice(0, 12)}${r.covered.dirty ? ' + uncommitted' : ''}; not checked since`,
      );
    if (r.notChecked?.length) out(`not checked (folder missing): ${r.notChecked.join(', ')}`);
    outClaims(out, r);
  }
  return r.exitCode;
}

function outClaims(out: (l: string) => void, r: ThreatModelReport): void {
  const claims = r.claims ?? [];
  if (claims.length) {
    const count = (status: ClaimResult['status']): number =>
      claims.filter((c) => c.status === status).length;
    out(
      `Claims: ${count('passed')} passed, ${count('violated')} violated, ${count('untested')} untested`,
    );
    for (const c of claims) {
      const flag = c.unenforced ? ' unenforced' : '';
      out(`  ${c.status.padEnd(9)} ${c.claim}  ${c.target}  ${c.detail}${flag}`);
    }
  }
  const uncovered = r.uncovered ?? [];
  if (!uncovered.length) return;
  out('Uncovered capabilities');
  for (const u of uncovered) out(`  ${u.kind}  ${u.target}  ${u.value}`);
  out('Suggested claims');
  for (const u of uncovered) out(`  ${u.suggestedClaim}`);
}

export const COMMENT_MARKER = '<!-- ironheights-threatmodel -->';

export function renderMarkdown(r: ThreatModelReport): string {
  const list = r.introduced ?? r.violations;
  const blocking = list.filter((v) => v.severity !== 'info');
  const info = list.filter((v) => v.severity === 'info');
  const status =
    r.exitCode === 2
      ? '❌ Out-of-model change'
      : r.exitCode === 1
        ? '⚠️ Review needed'
        : '✅ Inside the threat model';
  const lines = [
    COMMENT_MARKER,
    `### Ironheights threat model: ${status}`,
    '',
    `Checked ${r.skills} skill(s) and ${r.mcpServers} MCP server(s) against \`${r.modelFile}\`${r.base ? ` (base \`${r.base}\`)` : ''}.`,
    '',
    ...(r.covered?.head
      ? [
          `Covers ${r.covered.base ? `\`${r.covered.base.slice(0, 12)}\`..` : ''}\`${r.covered.head.slice(0, 12)}\`${r.covered.dirty ? ' plus uncommitted changes' : ''}. Not checked since \`${r.covered.head.slice(0, 12)}\`.`,
          '',
        ]
      : []),
    ...(r.notChecked?.length
      ? [
          `Not checked (folder missing): ${r.notChecked.map((d) => `\`${esc(d)}\``).join(', ')}.`,
          '',
        ]
      : []),
  ];
  const table = (rows: Violation[]): string[] => [
    '| Severity | Check | Target | Detail |',
    '| --- | --- | --- | --- |',
    ...rows.map((v) => `| ${v.severity} | \`${v.kind}\` | ${esc(v.target)} | ${esc(v.detail)} |`),
    '',
  ];
  if (blocking.length)
    lines.push(r.base ? '**New in this PR**' : '**Violations**', '', ...table(blocking));
  if (info.length)
    lines.push('**Model changes and notes** (a reviewer should approve these)', '', ...table(info));
  if (!list.length) lines.push('No skill or MCP server reaches outside the model.', '');
  if (r.claims?.length) {
    const count = (status: ClaimResult['status']): number =>
      r.claims?.filter((c) => c.status === status).length ?? 0;
    lines.push(
      '**Claims**',
      '',
      `${count('passed')} passed, ${count('violated')} violated, ${count('untested')} untested. Untested matched zero rows and does not change the exit code.`,
      '',
      '| Target | Claim | Status | Distribution |',
      '| --- | --- | --- | --- |',
      ...r.claims.map(
        (c) =>
          `| ${esc(c.target)} | \`${c.claim}\` | ${c.status}${c.unenforced ? ' (unenforced)' : ''} | ${esc(c.detail)} |`,
      ),
      '',
    );
  }
  if (r.uncovered?.length) {
    lines.push(
      '**Uncovered capabilities**',
      '',
      '| Target | Kind | Value | Suggested claim |',
      '| --- | --- | --- | --- |',
      ...r.uncovered.map(
        (u) => `| ${esc(u.target)} | ${u.kind} | ${esc(u.value)} | \`${esc(u.suggestedClaim)}\` |`,
      ),
      '',
      '**Suggested claims**',
      '',
      ...r.uncovered.map((u) => `- \`${u.suggestedClaim}\``),
      '',
    );
  }
  if (r.selfApproved?.length)
    lines.push(
      '**Self-approved marks waiting for a different reader**',
      '',
      ...r.selfApproved.map((x) => `- ${esc(x.target)}: ${esc(x.detail)}`),
      '',
    );
  if (r.proposedWrites?.length)
    lines.push(
      "**Proposed writes** (accept each one by adding it to `writes`; startup files and other tools' config are never proposed as accepted)",
      '',
      ...r.proposedWrites.map(
        (w) =>
          `- ${esc(w.target)}: \`${esc(w.path)}\` (${esc(w.why)})${w.denyByDefault ? ' deny by default' : ''}`,
      ),
      '',
    );
  if (r.scope)
    lines.push(
      `Scope: ${r.scope.changedFiles} changed file(s), ${r.scope.inScope} inside the declared skill dirs, ${r.scope.outsideScope.length} outside.`,
      '',
    );
  if (r.extractorHealth && r.extractorHealth.unclassified)
    lines.push(
      `Extractor health: ${r.extractorHealth.unclassified} of ${r.extractorHealth.classified + r.extractorHealth.unclassified} model change(s) could not be classified.`,
      '',
    );
  lines.push(
    `Fix: remove the access, or widen \`${r.modelFile}\` in this PR so a reviewer approves it. Docs: https://www.ironheights.dev/docs/threatmodel/`,
    '',
    `<sub>${r.tool} ${r.version} · local check, no network, no telemetry · Ironheights protects any AI bot that installs it</sub>`,
    '',
  );
  return lines.join('\n');
}

const esc = (s: string): string => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function renderTmSarif(r: ThreatModelReport): string {
  const list = r.introduced ?? r.violations;
  const kinds = [...new Set(list.map((v) => v.kind))];
  const level = (s: Violation['severity']): string =>
    s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'note';
  return (
    JSON.stringify(
      {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: `${r.tool}-threatmodel`,
                version: r.version,
                informationUri: REPOSITORY_URL,
                rules: kinds.map((k) => ({
                  id: `IH-TM-${k}`,
                  shortDescription: { text: `Threat model: ${k}` },
                  helpUri: 'https://www.ironheights.dev/docs/threatmodel/',
                })),
              },
            },
            results: list.map((v) => ({
              ruleId: `IH-TM-${v.kind}`,
              level: level(v.severity),
              message: { text: `${v.target}: ${v.detail}` },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: v.file ?? r.modelFile, uriBaseId: '%SRCROOT%' },
                    region: { startLine: 1 },
                  },
                },
              ],
            })),
          },
        ],
      },
      null,
      2,
    ) + '\n'
  );
}
