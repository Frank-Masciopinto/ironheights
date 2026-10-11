import { basename } from 'node:path';
import type { Confidence, Finding, KnownSecurityToolNote, SkillReport } from '../core/types.ts';
import { toolForSkillName } from './registry.ts';

/**
 * A security tool's own files quote attacks, so Ironheights flags them. A
 * fake can use the same name. This adds a note and lowers `confidence` one
 * step on injection and credential findings in Markdown files, and does
 * nothing else: severity, score, grade, verdict and exit code are unchanged,
 * and no finding is hidden.
 */

const DOWNGRADE_PREFIXES = ['IH-INJ-', 'IH-CRED-'];
const MARKDOWN_FILE = /\.(md|markdown|mdx|txt)$/i;

const NOTE_FINDING =
  'Folder or SKILL.md name matches a listed security tool (name only, not verified). Security tools quote attack text and credential paths in their docs, so confidence was lowered one step. Severity and verdict are unchanged. Review it yourself.';

export function annotateKnownSecurityTools(skills: SkillReport[]): SkillReport[] {
  return skills.map((skill) => {
    const byFolder = toolForSkillName(basename(skill.root));
    const bySkill = byFolder ? undefined : toolForSkillName(skill.skillName);
    const tool = byFolder ?? bySkill;
    if (!tool) return skill;
    let downgraded = 0;
    const findings = skill.findings.map((finding) => {
      if (!qualifies(finding)) return finding;
      downgraded += 1;
      return {
        ...finding,
        confidence: lower(finding.confidence),
        note: NOTE_FINDING,
      };
    });
    const note: KnownSecurityToolNote = {
      id: tool.id,
      name: tool.name,
      matchedBy: byFolder ? 'folder-name' : 'skill-name',
      verified: false,
      downgradedFindings: downgraded,
      note: `This ${byFolder ? 'folder' : 'skill'} is named like ${tool.name}, a security tool Ironheights knows about. That is a name match only. A malicious skill can use the same name. Nothing is allowlisted: every finding is still reported and the verdict is unchanged.${downgraded > 0 ? ` ${downgraded} finding${downgraded === 1 ? '' : 's'} in Markdown files had confidence lowered one step.` : ''}`,
    };
    return { ...skill, findings, knownSecurityTool: note };
  });
}

function qualifies(finding: Finding): boolean {
  return (
    DOWNGRADE_PREFIXES.some((prefix) => finding.ruleId.startsWith(prefix)) &&
    MARKDOWN_FILE.test(finding.file)
  );
}

function lower(confidence: Confidence): Confidence {
  if (confidence === 'high') return 'medium';
  return 'low';
}
