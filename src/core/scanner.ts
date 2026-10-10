import { readdir, readFile, stat } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { parseSkillMarkdown, type SkillFrontmatter } from '../openclaw/skill.ts';
import { allContentRules } from '../rules/index.ts';
import type { Finding, ResolvedConfig, ScanContext, ScannedFile, SkillReport } from './types.ts';
import { applySuppressions } from './suppress.ts';
import { blockingSkipCount, scoreFindings, verdictFor, worstVerdict } from './verdict.ts';
import { walkSkill } from './walker.ts';
import type { Verdict } from './types.ts';

export interface ScanPathResult {
  skills: SkillReport[];
  verdict: Verdict;
}

export async function scanPath(
  root: string,
  config: ResolvedConfig,
  options: { now?: Date; allowSkipped?: boolean } = {},
): Promise<ScanPathResult & { scannedAt: string }> {
  const abs = resolve(root);
  const skillRoots = await discoverSkillRoots(abs);
  const skills: SkillReport[] = [];
  for (const skillRoot of skillRoots) {
    skills.push(await scanSkill(skillRoot, config, options));
  }
  return {
    skills,
    verdict: worstVerdict(skills.map((skill) => skill.verdict)),
    scannedAt: (options.now ?? new Date()).toISOString(),
  };
}

export async function discoverSkillRoots(root: string): Promise<string[]> {
  let info;
  try {
    info = await stat(root);
  } catch {
    return [];
  }
  if (!info.isDirectory()) return [];
  if (await hasSkillFile(root)) return [root];
  const nested = await findSkillDirs(root, 0);
  if (nested.length > 0) return nested;
  return [root];
}

async function findSkillDirs(dir: string, depth: number): Promise<string[]> {
  if (depth > 6) return [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const found: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name === '.git' || entry.name === 'node_modules') continue;
    const child = join(dir, entry.name);
    if (await hasSkillFile(child)) {
      found.push(child);
      continue;
    }
    found.push(...(await findSkillDirs(child, depth + 1)));
  }
  return found;
}

async function hasSkillFile(dir: string): Promise<boolean> {
  try {
    const info = await stat(join(dir, 'SKILL.md'));
    return info.isFile();
  } catch {
    return false;
  }
}

export async function scanSkill(
  root: string,
  config: ResolvedConfig,
  options: { allowSkipped?: boolean } = {},
): Promise<SkillReport> {
  const walked = await walkSkill(root, config.limits, config.ignoreGlobs, config.ignoreDirs);
  const frontmatter = await readSkillFrontmatter(root, walked.files);
  const skillName = frontmatter?.name ?? basename(root);
  const ctx: ScanContext = {
    config,
    root,
    skillDirName: basename(root),
    skillAllowDomains: frontmatter?.allowDomains ?? [],
  };
  const raw: Finding[] = [];
  for (const file of walked.files) {
    raw.push(...scanFile(file, ctx));
  }
  return finishSkill(
    skillName,
    root,
    walked.files.length,
    walked.skipped,
    walked.skippedDirectories,
    raw,
    walked.files,
    config,
    options.allowSkipped === true,
  );
}

export async function scanText(
  text: string,
  config: ResolvedConfig,
  options: { label?: 'stdin' | 'text'; now?: Date; allowSkipped?: boolean } = {},
): Promise<ScanPathResult & { scannedAt: string }> {
  const scannedAt = (options.now ?? new Date()).toISOString();
  const label = options.label ?? 'text';
  const relativePath = label;
  const root = `(${label})`;
  const bytes = Buffer.byteLength(text);
  if (bytes > config.limits.maxFileBytes) {
    const skill = finishSkill(
      label,
      root,
      0,
      [{ file: relativePath, reason: `text exceeds ${config.limits.maxFileBytes} bytes` }],
      [],
      [],
      [],
      config,
      options.allowSkipped === true,
    );
    return { skills: [skill], verdict: skill.verdict, scannedAt };
  }
  const encoded = new TextEncoder().encode(text);
  const file: ScannedFile = {
    relativePath,
    kind: 'text',
    archive: false,
    size: bytes,
    mode: 0o644,
    text,
    head: encoded.subarray(0, Math.min(encoded.length, 64)),
    symlinkOutside: false,
    symlinkLoop: false,
    hidden: false,
  };
  const ctx: ScanContext = {
    config,
    root,
    skillDirName: label,
    skillAllowDomains: [],
  };
  const skill = finishSkill(
    label,
    root,
    1,
    [],
    [],
    scanFile(file, ctx, { textMode: true }),
    [file],
    config,
    options.allowSkipped === true,
  );
  return { skills: [skill], verdict: skill.verdict, scannedAt };
}

export function scanFile(
  file: ScannedFile,
  ctx: ScanContext,
  options: { textMode?: boolean } = {},
): Finding[] {
  const findings: Finding[] = [];
  for (const rule of allContentRules()) {
    const override = ctx.config.ruleOverrides[rule.id];
    if (override?.enabled === false) continue;
    if (!ruleApplies(rule, file, options.textMode === true)) continue;
    for (const finding of rule.check(file, ctx)) {
      const severity = override?.severity ?? finding.severity;
      findings.push(severity === finding.severity ? finding : { ...finding, severity });
    }
  }
  return findings;
}

function finishSkill(
  skillName: string,
  root: string,
  filesScanned: number,
  filesSkipped: SkillReport['filesSkipped'],
  skippedDirectories: SkillReport['skippedDirectories'],
  raw: Finding[],
  files: ScannedFile[],
  config: ResolvedConfig,
  allowSkipped: boolean,
): SkillReport {
  raw.sort(compareFindings);
  const outcome = applySuppressions(raw, files, config);
  const score = scoreFindings(outcome.active);
  const report: SkillReport = {
    skillName,
    root,
    filesScanned,
    filesSkipped,
    ...(skippedDirectories && skippedDirectories.length > 0 ? { skippedDirectories } : {}),
    findings: outcome.active,
    suppressed: outcome.suppressed,
    suppressionRefused: outcome.refused,
    suppressionWarnings: outcome.warnings,
    score,
    gradeRisk: score,
    verdict: 'no-findings',
  };
  report.verdict = verdictFor(outcome.active, config.thresholds, {
    filesSkipped: blockingSkipCount(report),
    allowSkipped,
  });
  return report;
}

function ruleApplies(
  rule: { id: string; appliesTo: string[] },
  file: ScannedFile,
  textMode: boolean,
): boolean {
  if (textMode) {
    if (rule.id === 'IH-BIN-001') return false;
    return rule.appliesTo.some(
      (item) =>
        item === 'any' ||
        item === 'markdown' ||
        item === 'script' ||
        item === 'config' ||
        item === 'text',
    );
  }
  if (rule.id === 'IH-BIN-001' && (file.kind === 'binary' || file.archive)) return true;
  if (rule.appliesTo.includes('any')) return true;
  return rule.appliesTo.includes(file.kind);
}

async function readSkillFrontmatter(
  root: string,
  files: ScannedFile[],
): Promise<SkillFrontmatter | undefined> {
  const skill = files.find(
    (file) => file.relativePath === 'SKILL.md' || file.relativePath.endsWith('/SKILL.md'),
  );
  if (skill && skill.relativePath === 'SKILL.md') return parseSkillMarkdown(skill.text);
  try {
    return parseSkillMarkdown(await readFile(join(root, 'SKILL.md'), 'utf8'));
  } catch {
    return undefined;
  }
}

function compareFindings(a: Finding, b: Finding): number {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const bySeverity = rank[a.severity] - rank[b.severity];
  if (bySeverity !== 0) return bySeverity;
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  return (a.line ?? 0) - (b.line ?? 0);
}
