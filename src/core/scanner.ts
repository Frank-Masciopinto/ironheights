import { readdir, readFile, stat } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { parseSkillMarkdown, type SkillFrontmatter } from '../openclaw/skill.ts';
import { allContentRules } from '../rules/index.ts';
import type { Finding, ResolvedConfig, ScanContext, ScannedFile, SkillReport } from './types.ts';
import { scoreFindings, verdictFor, worstVerdict } from './verdict.ts';
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
  const walked = await walkSkill(root, config.limits, config.ignoreGlobs);
  const frontmatter = await readSkillFrontmatter(root, walked.files);
  const skillName = frontmatter?.name ?? basename(root);
  const ctx: ScanContext = {
    config,
    root,
    skillDirName: basename(root),
    skillAllowDomains: frontmatter?.allowDomains ?? [],
  };
  const findings: Finding[] = [];
  for (const file of walked.files) {
    findings.push(...scanFile(file, ctx));
  }
  findings.sort(compareFindings);
  const score = scoreFindings(findings);
  return {
    skillName,
    root,
    filesScanned: walked.files.length,
    filesSkipped: walked.skipped,
    findings,
    score,
    verdict: verdictFor(findings, config.thresholds, {
      filesSkipped: walked.skipped.length,
      allowSkipped: options.allowSkipped === true,
    }),
  };
}

export function scanFile(file: ScannedFile, ctx: ScanContext): Finding[] {
  const findings: Finding[] = [];
  for (const rule of allContentRules()) {
    const override = ctx.config.ruleOverrides[rule.id];
    if (override?.enabled === false) continue;
    if (!ruleApplies(rule.appliesTo, file, rule.id)) continue;
    for (const finding of rule.check(file, ctx)) {
      const severity = override?.severity ?? finding.severity;
      findings.push(severity === finding.severity ? finding : { ...finding, severity });
    }
  }
  return findings;
}

function ruleApplies(appliesTo: string[], file: ScannedFile, ruleId: string): boolean {
  if (ruleId === 'IH-BIN-001' && (file.kind === 'binary' || file.archive)) return true;
  if (appliesTo.includes('any')) return true;
  return appliesTo.includes(file.kind);
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
