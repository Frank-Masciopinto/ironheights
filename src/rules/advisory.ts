import type { Rule } from '../core/types.ts';

function advisoryRule(rule: Omit<Rule, 'check'>): Rule {
  return { ...rule, check: () => [] };
}

/**
 * Applied from the cached advisory feed during scan and fetch.
 * It is not a content-pattern rule: `check` stays empty so a skill file
 * cannot trip it by mentioning the rule id.
 */
export const adv001: Rule = advisoryRule({
  id: 'IH-ADV-001',
  title: 'Advisory feed match',
  category: 'advisory',
  severity: 'critical',
  priority: 'P0',
  description:
    'The cached signed advisory feed lists this skill name, a file content hash, or an indicator host. The match is reported only when a local cache is present. Scan does not contact the network to refresh the feed.',
  remediation:
    'Do not install or enable this skill. Read the source links, then quarantine the copy if it is already on disk.',
  appliesTo: ['any'],
  examples: {
    matches: [
      'skill slug evil-skill is listed in the advisory feed',
      'file sha256 matches an advisory content hash',
      'skill text contains an advisory IOC host',
    ],
    nonMatches: [
      'skill slug is not in the feed',
      'no advisory cache is present',
      'a version-specific advisory does not list this version',
    ],
  },
});

export const advisoryRules: Rule[] = [adv001];
