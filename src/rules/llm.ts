import type { Rule } from '../core/types.ts';
import { LLM_REMEDIATION, LLM_RULE_ID } from '../llm/constants.ts';

/** Metadata only. The review never runs inside the rule loop. */
export const llm001: Rule = {
  id: LLM_RULE_ID,
  title: 'Advisory model review',
  category: 'llm-review',
  severity: 'info',
  priority: 'advisory',
  description:
    'An optional language-model review added a note. This is not a pattern rule and it does not scan files by itself. The model sees redacted skill text and the deterministic findings, and it can be wrong. The note never changes the verdict or the exit code. It appears only after `scan --llm` or `review`, and only when the model output matched the review schema.',
  remediation: LLM_REMEDIATION,
  appliesTo: ['any'],
  examples: {
    matches: ['Model note: the skill tells the agent to download a script before reading it.'],
    nonMatches: ['A skill file on its own, with scan --llm not set.'],
  },
  check: () => [],
};
