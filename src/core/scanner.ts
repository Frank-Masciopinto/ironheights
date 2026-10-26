import { findSkillFile, isSkillFileName } from './skill-file.ts';
import { readdir, readFile, stat } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { parseSkillMarkdown, type SkillFrontmatter } from '../openclaw/skill.ts';
import { skillHoldsAmbientSecret } from '../rules/ambient-env.ts';
import { allContentRules } from '../rules/index.ts';
import type { Finding, ResolvedConfig, ScanContext, ScannedFile, SkillReport } from './types.ts';
import { applySuppressions, reconcileEvidenceDrift } from './suppress.ts';
import {
  blockingSkipCount,
  gradeRiskFor,
  scoreFindings,
  verdictFor,
  worstVerdict,
} from './verdict.ts';
import { walkSkill } from './walker.ts';
import { clip, fencedLineNumbers } from '../util/text.ts';
import {
  dependenciesFromInstructions,
  describeDependency,
  type UnscannedDependency,
} from './dependencies.ts';
import { checkRegistry } from '../net/registry.ts';
import { dep001 } from '../rules/dependency.ts';
import type { Verdict } from './types.ts';

export interface ScanPathResult {
  skills: SkillReport[];
  verdict: Verdict;
}

export async function scanPath(
  root: string,
  config: ResolvedConfig,
  options: { now?: Date; allowSkipped?: boolean } & RegistryOptions = {},
): Promise<ScanPathResult & { scannedAt: string }> {
  const abs = resolve(root);
  const skillRoots = await discoverSkillRoots(abs);
  const skills: SkillReport[] = [];
  for (const skillRoot of skillRoots) {
    skills.push(await scanSkill(skillRoot, config, options));
  }
  const reconciled = reconcileEvidenceDrift(skills, config.suppressions);
  return {
    skills: reconciled,
    verdict: worstVerdict(reconciled.map((skill) => skill.verdict)),
    scannedAt: (options.now ?? new Date()).toISOString(),
  };
}

export interface RegistryOptions {
  /** Ask npm and PyPI whether install names exist. Off by default: scans are local. */
  checkRegistry?: boolean;
  fetchImpl?: typeof fetch;
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
  return (await findSkillFile(dir)) !== undefined;
}

export async function scanSkill(
  root: string,
  config: ResolvedConfig,
  options: { allowSkipped?: boolean } & RegistryOptions = {},
): Promise<SkillReport> {
  const walked = await walkSkill(root, config.limits, config.ignoreGlobs, config.ignoreDirs);
  const frontmatter = await readSkillFrontmatter(root, walked.files);
  const skillName = frontmatter?.name ?? basename(root);
  const ctx: ScanContext = {
    config,
    root,
    skillDirName: basename(root),
    skillAllowDomains: frontmatter?.allowDomains ?? [],
    skillDeclaredHosts: frontmatter?.declaredHosts ?? [],
    skillHoldsSecret: skillHoldsAmbientSecret(
      walked.files.filter((file) => !isInstallToolMetadata(file.relativePath)),
    ),
  };
  const raw: Finding[] = [];
  for (const file of walked.files) {
    raw.push(...scanFile(file, ctx));
  }
  const deps = skillDependencies(walked.files, frontmatter);
  let registryCheck: SkillReport['registryCheck'];
  if (options.checkRegistry && deps.length > 0) {
    const results = await checkRegistry(deps, options.fetchImpl);
    const notes: string[] = [];
    let missing = 0;
    let notChecked = 0;
    for (const result of results) {
      if (result.status === 'missing') {
        missing += 1;
        raw.push(missingPackageFinding(result.dependency));
      } else if (result.status === 'unknown') {
        notChecked += 1;
        notes.push(
          `${result.dependency.manager} ${result.dependency.name}: not checked (${result.detail ?? 'unknown'})`,
        );
      }
    }
    registryCheck = { checked: results.length - notChecked, missing, notChecked, notes };
  }
  const report = finishSkill(
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
  if (deps.length > 0) report.unscannedDependencies = deps;
  if (registryCheck) report.registryCheck = registryCheck;
  return report;
}

function skillDependencies(
  files: ScannedFile[],
  frontmatter: SkillFrontmatter | undefined,
): UnscannedDependency[] {
  const top = files.filter((file) => isSkillFileName(file.relativePath));
  const skill = top.find((file) => file.relativePath === 'SKILL.md') ?? top[0];
  const fileName = skill?.relativePath ?? 'SKILL.md';
  const out: UnscannedDependency[] = [];
  const add = (dep: UnscannedDependency): void => {
    if (out.some((item) => item.manager === dep.manager && item.name === dep.name)) return;
    out.push(dep);
  };
  for (const dep of frontmatter?.installDependencies ?? []) add({ ...dep, file: fileName });
  if (skill) for (const dep of dependenciesFromInstructions(skill.text, fileName)) add(dep);
  return out.slice(0, 50);
}

function missingPackageFinding(dep: UnscannedDependency): Finding {
  const registry = dep.manager === 'npm' ? 'npm' : 'PyPI';
  return {
    ruleId: dep001.id,
    severity: dep001.severity,
    confidence: 'high',
    file: clip(dep.file, 300),
    ...(dep.line !== undefined ? { line: dep.line } : {}),
    evidence: clip(describeDependency(dep)),
    message: `${registry} has no package named ${clip(dep.name, 120)}. Anyone can register it.`,
    remediation: dep001.remediation,
  };
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
    const skills = reconcileEvidenceDrift([skill], config.suppressions);
    return { skills, verdict: skills[0]?.verdict ?? skill.verdict, scannedAt };
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
  const skills = reconcileEvidenceDrift([skill], config.suppressions);
  return { skills, verdict: skills[0]?.verdict ?? skill.verdict, scannedAt };
}

export function scanFile(
  file: ScannedFile,
  ctx: ScanContext,
  options: { textMode?: boolean } = {},
): Finding[] {
  // Install-tool metadata is hashed for tamper checks but not graded as author content.
  if (isInstallToolMetadata(file.relativePath)) return [];
  const findings: Finding[] = [];
  let fenced: Set<number> | undefined;
  for (const rule of allContentRules()) {
    const override = ctx.config.ruleOverrides[rule.id];
    if (override?.enabled === false) continue;
    if (!ruleApplies(rule, file, options.textMode === true)) continue;
    for (const raw of rule.check(file, ctx)) {
      let finding = raw;
      if (file.kind === 'markdown' && DOC_EXAMPLE_RULES.has(rule.id) && raw.line !== undefined) {
        fenced ??= fencedLineNumbers(file.text);
        if (fenced.has(raw.line)) finding = asDocExample(raw);
      }
      if (isRegistrySkillCard(file.relativePath)) finding = asRegistryCard(finding);
      else if (isChangelog(file.relativePath)) finding = asChangelogFix(finding, file.text);
      const severity = override?.severity ?? finding.severity;
      findings.push(severity === finding.severity ? finding : { ...finding, severity });
    }
  }
  return findings;
}

/**
 * Rules whose hit in a fenced Markdown example means "the docs tell a person to run this",
 * not "a shipped script runs this". Those hits are graded one step lower than the same line
 * in a script. Remote fetch, injection, exfiltration and credential rules are not listed:
 * malware hides in setup snippets, so they keep full severity everywhere.
 */
const DOC_EXAMPLE_RULES = new Set(['IH-PRIV-001', 'IH-FS-001', 'IH-CRED-004']);

const ONE_STEP_DOWN: Record<Finding['severity'], Finding['severity']> = {
  critical: 'critical',
  high: 'medium',
  medium: 'low',
  low: 'low',
  info: 'info',
};

function asDocExample(finding: Finding): Finding {
  const severity = ONE_STEP_DOWN[finding.severity];
  if (severity === finding.severity) return finding;
  const note =
    'Docs example: this line is in a fenced code block in Markdown, so the docs tell someone to run it. The same line in a shipped script is graded one step higher.';
  return { ...finding, severity, note: finding.note ? `${finding.note} ${note}` : note };
}

/**
 * ClawHub writes `skill-card.md` next to every published skill (2,760 of 2,819 in the registry,
 * including ours, which only shipped SKILL.md). It is the registry's summary and warnings, not the
 * author's code, so its hits are reported as notes. Critical hits stay visible at medium.
 */
export function isRegistrySkillCard(relativePath: string): boolean {
  return relativePath.toLowerCase() === 'skill-card.md';
}

/**
 * ClawHub / install-tool files written next to a skill at install time, not by the skill author.
 * Examples: `.clawhub/origin.json` (registry, slug, installedVersion) and root `_meta.json`
 * (ownerId, slug, version). Content rules would grade clawhub.ai URLs and similar metadata as
 * the author's undeclared hosts (billboardbug 1.2.3 with 0.13.0: B 85 from IH-NET-001 alone).
 * Still walked and hashed so integrity / tamper checks see them; only author-facing content
 * findings are skipped. Suggested by ccbillboardbug on Moltbook (2026-10-24 beta rescan).
 */
export function isInstallToolMetadata(relativePath: string): boolean {
  const portable = relativePath.replace(/\\/g, '/').replace(/^\.\//, '');
  const lower = portable.toLowerCase();
  if (lower === '_meta.json') return true;
  if (lower === '.clawhub' || lower.startsWith('.clawhub/')) return true;
  return false;
}

function asRegistryCard(finding: Finding): Finding {
  const severity: Finding['severity'] = finding.severity === 'critical' ? 'medium' : 'info';
  if (severity === finding.severity) return finding;
  const note =
    "Registry skill card: ClawHub generates skill-card.md, so this is read as notes, not as the author's code.";
  return { ...finding, severity, note: finding.note ? `${finding.note} ${note}` : note };
}

/** CHANGELOG.md, CHANGES, HISTORY.md, RELEASE_NOTES.md and the like, at any depth. */
export function isChangelog(relativePath: string): boolean {
  const name = relativePath.split('/').pop() ?? '';
  return /^(?:changelog|changes|history|release[-_ ]?notes|news)(?:\.(?:md|markdown|txt|rst))?$/i.test(
    name,
  );
}

const FIXED_BUG =
  /\b(?:fix(?:e[ds])?|fixing|resolved?|patch(?:ed)?|bug ?fix|no longer|regression|was (?:broken|wrong))\b/i;

/**
 * A changelog line that describes a fixed bug ("Fixed: rm -rf ran on the wrong folder") names the
 * old behaviour, not what the skill does now (0.12.0, IH-EXEC-003 false positive on
 * email-to-calendar). Those hits become info; other changelog lines keep their severity.
 */
function asChangelogFix(finding: Finding, text: string): Finding {
  if (finding.line === undefined || finding.severity === 'info' || finding.severity === 'critical')
    return finding;
  const line = text.split(/\r?\n/)[finding.line - 1] ?? '';
  if (!FIXED_BUG.test(line)) return finding;
  const note =
    'Changelog line about a fixed bug: it describes old behaviour, so it is reported as info.';
  return { ...finding, severity: 'info', note: finding.note ? `${finding.note} ${note}` : note };
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
    ...(outcome.stale.length > 0 ? { staleSuppressions: outcome.stale } : {}),
    ...(outcome.matches.length > 0 ? { evidenceMatches: outcome.matches } : {}),
    score,
    gradeRisk: gradeRiskFor(outcome.active),
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
  const top = files.filter((file) => isSkillFileName(file.relativePath));
  const skill = top.find((file) => file.relativePath === 'SKILL.md') ?? top[0];
  if (skill) return parseSkillMarkdown(skill.text);
  try {
    const path = await findSkillFile(root);
    if (!path) return undefined;
    return parseSkillMarkdown(await readFile(path, 'utf8'));
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
