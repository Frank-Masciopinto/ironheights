import type { Rule } from '../core/types.ts';

function integrityRule(rule: Omit<Rule, 'check'>): Rule {
  return { ...rule, check: () => [] };
}

export const int001: Rule = integrityRule({
  id: 'IH-INT-001',
  title: 'Skill file modified',
  category: 'integrity',
  severity: 'high',
  priority: 'P0',
  description: 'A file in an installed skill no longer matches the saved baseline.',
  remediation:
    'Review the diff. Restore the file or create a new baseline only after you accept the change.',
  appliesTo: ['any'],
  examples: {
    matches: ['SKILL.md hash changed since baseline'],
    nonMatches: ['SKILL.md hash matches baseline'],
  },
});

export const int002: Rule = integrityRule({
  id: 'IH-INT-002',
  title: 'New skill file',
  category: 'integrity',
  severity: 'medium',
  priority: 'P0',
  description: 'A file or skill directory appeared after the baseline was created.',
  remediation:
    'Inspect the new file before trusting the skill, then update the baseline if you accept it.',
  appliesTo: ['any'],
  examples: {
    matches: ['scripts/install.sh added'],
    nonMatches: ['no new paths since baseline'],
  },
});

export const int003: Rule = integrityRule({
  id: 'IH-INT-003',
  title: 'Skill file removed',
  category: 'integrity',
  severity: 'medium',
  priority: 'P0',
  description: 'A file that was in the baseline is gone.',
  remediation:
    'Confirm the deletion was intentional. A missing file can also mean the skill was replaced.',
  appliesTo: ['any'],
  examples: {
    matches: ['README.md removed'],
    nonMatches: ['every baseline path still exists'],
  },
});

export const int004: Rule = integrityRule({
  id: 'IH-INT-004',
  title: 'Watched agent file changed',
  category: 'integrity',
  severity: 'high',
  priority: 'P0',
  description:
    'An agent instruction, personality, memory, or config file changed since the baseline.',
  remediation: 'Compare the agent file with a copy you trust before starting the agent again.',
  appliesTo: ['any'],
  examples: {
    matches: ['AGENTS.md changed', 'openclaw.json changed'],
    nonMatches: ['AGENTS.md matches baseline'],
  },
});

export const integrityRules: Rule[] = [int001, int002, int003, int004];
