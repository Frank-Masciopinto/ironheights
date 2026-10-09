import { parseSkillMarkdown } from '../openclaw/skill.ts';
import type { Finding, Rule } from '../core/types.ts';
import { createFinding } from './helpers.ts';

export const meta001: Rule = {
  id: 'IH-META-001',
  title: 'Skill metadata problem',
  category: 'meta',
  severity: 'low',
  priority: 'P1',
  description:
    'OpenClaw discovers a skill from SKILL.md frontmatter. Missing fields make the skill harder to identify and review.',
  remediation:
    'Add YAML frontmatter with name and description. The name should match the folder name.',
  appliesTo: ['markdown'],
  examples: {
    matches: ['# No frontmatter here'],
    nonMatches: ['---\nname: notes\ndescription: Take notes.\n---'],
  },
  check(file, ctx) {
    if (file.relativePath !== 'SKILL.md') return [];
    const parsed = parseSkillMarkdown(file.text);
    const findings: Finding[] = [];
    if (parsed.missing || parsed.malformed) {
      findings.push(
        createFinding(meta001, file, {
          line: 1,
          evidence: file.text.slice(0, 80) || '(empty)',
          message: parsed.malformed
            ? 'SKILL.md frontmatter is malformed.'
            : 'SKILL.md is missing frontmatter.',
          confidence: 'high',
        }),
      );
      return findings;
    }
    if (!parsed.name || !parsed.description) {
      findings.push(
        createFinding(meta001, file, {
          line: 1,
          evidence: 'frontmatter',
          message: 'SKILL.md frontmatter is missing name or description.',
          confidence: 'high',
        }),
      );
    }
    if (parsed.name && parsed.name !== ctx.skillDirName) {
      findings.push(
        createFinding(meta001, file, {
          line: 1,
          evidence: parsed.name,
          message: `Frontmatter name "${parsed.name}" does not match the folder "${ctx.skillDirName}".`,
          confidence: 'high',
        }),
      );
    }
    return findings;
  },
};
