import type { RuleReferences } from '../core/types.ts';

/**
 * OWASP LLM ids are from the OWASP Top 10 for LLM Applications 2025.
 * OWASP Agentic ids are from the OWASP Top 10 for Agentic Applications 2026.
 * MITRE ATLAS ids are technique ids from ATLAS (AML.T0010.005 names MCP servers explicitly).
 * An empty list means no mapping was defensible enough to cite.
 */
export const RULE_REFERENCES: Record<string, RuleReferences> = {
  'IH-EXEC-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: ['AML.T0053'],
  },
  'IH-EXEC-002': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
  },
  'IH-EXEC-003': {
    owaspLlm: ['LLM05:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
  },
  'IH-EXEC-004': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI03:2026'],
    mitreAtlas: [],
  },
  'IH-EXEC-005': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: ['ASI03:2026'],
    mitreAtlas: ['AML.T0055'],
  },
  'IH-NET-001': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
  },
  'IH-NET-002': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: ['ASI02:2026'],
    mitreAtlas: ['AML.T0025'],
  },
  'IH-CRED-001': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
  },
  'IH-CRED-002': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0055'],
  },
  'IH-CRED-003': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
  },
  'IH-CRED-004': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
  },
  'IH-CRED-005': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
  },
  'IH-CRED-006': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0055'],
  },
  'IH-INJ-001': {
    owaspLlm: ['LLM01:2025'],
    owaspAgentic: ['ASI01:2026'],
    mitreAtlas: ['AML.T0051', 'AML.T0051.001'],
  },
  'IH-INJ-002': {
    owaspLlm: ['LLM01:2025'],
    owaspAgentic: ['ASI01:2026'],
    mitreAtlas: ['AML.T0051.001', 'AML.T0068'],
  },
  'IH-INJ-003': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI03:2026', 'ASI06:2026'],
    mitreAtlas: [],
  },
  'IH-INJ-004': {
    owaspLlm: ['LLM01:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: [],
  },
  'IH-OBF-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [] },
  'IH-PERSIST-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [] },
  'IH-PRIV-001': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI03:2026'],
    mitreAtlas: [],
  },
  'IH-BIN-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
  },
  'IH-BIN-002': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: [],
  },
  'IH-FS-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [] },
  'IH-META-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [] },
  'IH-REF-001': { owaspLlm: ['LLM03:2025'], owaspAgentic: ['ASI04:2026'], mitreAtlas: [] },
  'IH-INT-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
  },
  'IH-INT-002': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
  },
  'IH-INT-003': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
  },
  'IH-INT-004': {
    owaspLlm: [],
    owaspAgentic: ['ASI06:2026'],
    mitreAtlas: [],
  },
  'IH-MCP-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010.005'],
  },
  'IH-MCP-002': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
  },
  'IH-MCP-003': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI02:2026'],
    mitreAtlas: [],
  },
  'IH-ADV-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
  },
  'IH-CFG-001': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
  },
  'IH-CFG-002': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
  },
  'IH-CFG-003': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
  },
  'IH-CFG-004': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
  },
  'IH-CFG-005': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
  },
  'IH-CFG-006': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
  },
  'IH-CFG-007': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
  },
  'IH-CFG-008': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: [],
  },
  'IH-CFG-009': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
  },
  'IH-DEP-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
  },
  // Advisory notes are not a detection technique, so no framework id is cited.
  'IH-LLM-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [] },
};

export function referencesFor(ruleId: string): RuleReferences {
  return RULE_REFERENCES[ruleId] ?? { owaspLlm: [], owaspAgentic: [], mitreAtlas: [] };
}

export function referenceTags(ruleId: string): string[] {
  const refs = referencesFor(ruleId);
  return [...refs.owaspLlm, ...refs.owaspAgentic, ...refs.mitreAtlas];
}
