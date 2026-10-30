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
  skills: number;
  mcpServers: number;
  violations: Violation[];
  /** Only for diff: violations that exist at head but not at base. */
  introduced?: Violation[];
  exitCode: number;
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
  const config = grade
    ? await loadConfig({
        ...(flags.config ? { explicitPath: flags.config } : {}),
        env: flags.env ?? process.env,
      })
    : undefined;
  for (const r of [...roots].sort()) {
    const p = await profileSkill(r, base);
    if (config) {
      const report = await scanSkill(r, config);
      p.grade = gradeFromSkills([report]).letter;
    }
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
): Promise<{ violations: Violation[]; skills: number; mcp: number }> {
  const { profiles, mcp } = await collect(
    base,
    flags.skillDirs?.length ? flags.skillDirs : model.skillDirs,
    [...model.mcpConfigs, ...(flags.mcp ?? [])],
    !flags.noGrade,
    flags,
  );
  const violations = evaluate({ model, base, profiles, mcp, modelFile });
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
  return { violations, skills: profiles.length, mcp: mcp.length };
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
    return emit(flags, out, {
      tool: TOOL_NAME,
      version: TOOL_VERSION,
      modelFile,
      checkedAt: new Date().toISOString(),
      skills: r.skills,
      mcpServers: r.mcp,
      violations: r.violations,
      exitCode: exitCodeFor(r.violations),
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
  let baseViolations: Violation[] = [];
  let modelChanges: Violation[] = [];
  try {
    const { stdout: top } = await run('git', ['-C', dir, 'rev-parse', '--show-toplevel']);
    const repo = top.trim();
    const sub = toPosix(relative(repo, dir));
    const archive = join(tmp, 'base.tar');
    await run('git', [
      '-C',
      repo,
      'archive',
      '--format=tar',
      '-o',
      archive,
      flags.base,
      '--',
      sub || '.',
    ]);
    await run('tar', ['-xf', archive, '-C', tmp]);
    const baseDir = join(tmp, sub);
    const baseModelPath = join(baseDir, modelFile);
    if (await exists(baseModelPath)) {
      const baseModel = parseModel(
        await readFile(baseModelPath, 'utf8'),
        `${flags.base}:${modelFile}`,
      );
      // Base skills measured against the head model, so a widened model does not hide anything.
      baseViolations = (
        await checkAt(baseDir, headModel, modelFile, { ...flags, ledger: undefined })
      ).violations;
      modelChanges = widened(baseModel, headModel, modelFile);
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
  const key = (v: Violation): string => `${v.kind}|${v.target}|${v.detail}`;
  const before = new Set(baseViolations.map(key));
  const introduced = head.violations.filter((v) => !before.has(key(v)));
  const violations = [...head.violations, ...modelChanges];
  return emit(flags, out, {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    modelFile,
    checkedAt: new Date().toISOString(),
    base: flags.base,
    skills: head.skills,
    mcpServers: head.mcp,
    violations,
    introduced: [...introduced, ...modelChanges],
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
  }
  return r.exitCode;
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
