import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { basename, join, relative, sep } from 'node:path';
import type { Finding, Limits, ResolvedConfig, SkillReport } from '../core/types.ts';
import { blockingSkipCount, gradeRiskFor, scoreFindings, verdictFor } from '../core/verdict.ts';
import { parseSkillMarkdown } from '../openclaw/skill.ts';
import { adv001 } from '../rules/advisory.ts';
import { clip } from '../util/text.ts';
import { normalizeContentHash, type AdvisoryDocument, type AdvisoryEntry } from './schema.ts';

export interface SkillMaterial {
  skillName: string;
  dirName: string;
  version?: string;
  files: Array<{ relativePath: string; sha256: string; text?: string }>;
}

export interface AnnotateOptions {
  allowSkipped: boolean;
  /** Set for fetch and safe-install, where the publisher handle is known. */
  owner?: string;
}

export async function annotateSkillReports(
  skills: SkillReport[],
  document: AdvisoryDocument,
  config: ResolvedConfig,
  options: AnnotateOptions,
): Promise<SkillReport[]> {
  const override = config.ruleOverrides[adv001.id];
  if (override?.enabled === false) return skills;
  const severity = override?.severity ?? adv001.severity;
  const next: SkillReport[] = [];
  for (const skill of skills) {
    const material = await collectSkillMaterial(skill.root, config.limits, skill.skillName);
    const extra = findingsForSkill(material, document, options.owner, severity);
    if (extra.length === 0) {
      next.push(skill);
      continue;
    }
    const findings = [...skill.findings, ...extra].sort(compareFindings);
    const score = scoreFindings(findings);
    next.push({
      ...skill,
      findings,
      score,
      gradeRisk: gradeRiskFor(findings),
      verdict: verdictFor(findings, config.thresholds, {
        filesSkipped: blockingSkipCount(skill),
        allowSkipped: options.allowSkipped,
      }),
    });
  }
  return next;
}

export async function collectSkillMaterial(
  root: string,
  limits: Limits,
  fallbackName: string,
): Promise<SkillMaterial> {
  const dirName = basename(root);
  const files: SkillMaterial['files'] = [];
  await walk(root, root, 0, limits, files);
  const skillFile =
    files.find((file) => file.relativePath === 'SKILL.md') ??
    files.find((file) => file.relativePath.toLowerCase() === 'skill.md');
  const frontmatter = skillFile?.text ? parseSkillMarkdown(skillFile.text) : undefined;
  return {
    skillName: frontmatter?.name ?? fallbackName,
    dirName,
    ...(frontmatter?.version ? { version: frontmatter.version } : {}),
    files,
  };
}

export function findingsForSkill(
  material: SkillMaterial,
  document: AdvisoryDocument,
  owner: string | undefined,
  severity: Finding['severity'],
): Finding[] {
  const findings: Finding[] = [];
  for (const advisory of document.advisories) {
    const nameHit = nameMatches(advisory, material, owner);
    const hashHit = hashMatch(advisory, material);
    const hostHit = hostMatch(advisory, material);
    if (!nameHit && !hashHit && !hostHit) continue;
    const reasons: string[] = [];
    if (nameHit) reasons.push(`name ${advisory.skill}`);
    if (hashHit) reasons.push(`content hash ${hashHit.sha256.slice(0, 12)}`);
    if (hostHit) reasons.push(`IOC host ${hostHit.host}`);
    const links = advisory.sources.slice(0, 3).join(' ');
    const file = hashHit?.relativePath ?? hostHit?.relativePath ?? 'SKILL.md';
    findings.push({
      ruleId: adv001.id,
      severity,
      confidence: 'high',
      file,
      evidence: clip(`${advisory.status} ${advisory.campaign}: ${reasons.join(', ')}`),
      message: `Advisory ${advisory.id} matches this skill (${reasons.join(', ')}). Sources: ${links}`,
      remediation: `${adv001.remediation} Sources: ${links}`,
    });
  }
  return findings;
}

function nameMatches(
  advisory: AdvisoryEntry,
  material: SkillMaterial,
  owner: string | undefined,
): boolean {
  const names = new Set([material.skillName.toLowerCase(), material.dirName.toLowerCase()]);
  if (!names.has(advisory.skill.toLowerCase())) return false;
  if (advisory.owner && owner && advisory.owner.toLowerCase() !== owner.toLowerCase()) return false;
  if (advisory.versions.length === 0 || advisory.versions.includes('*')) return true;
  if (!material.version) return false;
  return advisory.versions.includes(material.version);
}

function hashMatch(
  advisory: AdvisoryEntry,
  material: SkillMaterial,
): { relativePath: string; sha256: string } | undefined {
  const wanted = new Set(advisory.contentHashes.map(normalizeContentHash));
  for (const file of material.files) {
    if (wanted.has(file.sha256)) return { relativePath: file.relativePath, sha256: file.sha256 };
  }
  return undefined;
}

function hostMatch(
  advisory: AdvisoryEntry,
  material: SkillMaterial,
): { relativePath: string; host: string } | undefined {
  for (const file of material.files) {
    if (!file.text) continue;
    for (const host of advisory.iocHosts) {
      if (textContainsHost(file.text, host)) return { relativePath: file.relativePath, host };
    }
  }
  return undefined;
}

export function textContainsHost(text: string, host: string): boolean {
  const escaped = host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(?:^|[^A-Za-z0-9.-])${escaped}(?=$|[^A-Za-z0-9.-])`, 'i');
  return pattern.test(text);
}

async function walk(
  root: string,
  dir: string,
  depth: number,
  limits: Limits,
  files: SkillMaterial['files'],
): Promise<void> {
  if (depth > limits.maxDepth || files.length >= limits.maxFiles) return;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (files.length >= limits.maxFiles) return;
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const abs = join(dir, entry.name);
    const rel = relative(root, abs);
    if (rel.startsWith('..') || rel.split(sep).includes('..')) continue;
    let info;
    try {
      info = await lstat(abs);
    } catch {
      continue;
    }
    if (info.isSymbolicLink()) continue;
    if (info.isDirectory()) {
      await walk(root, abs, depth + 1, limits, files);
      continue;
    }
    if (!info.isFile() || info.size > limits.maxFileBytes) continue;
    const bytes = await readFile(abs);
    if (bytes.byteLength > limits.maxFileBytes) continue;
    const text = decodeUtf8(bytes);
    files.push({
      relativePath: rel.split(sep).join('/'),
      sha256: createHash('sha256').update(bytes).digest('hex'),
      ...(text !== undefined ? { text } : {}),
    });
  }
}

function decodeUtf8(bytes: Uint8Array): string | undefined {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

function compareFindings(a: Finding, b: Finding): number {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const bySeverity = rank[a.severity] - rank[b.severity];
  if (bySeverity !== 0) return bySeverity;
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
  return a.evidence < b.evidence ? -1 : a.evidence > b.evidence ? 1 : 0;
}
