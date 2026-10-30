import type { RuleReferences } from '../core/types.ts';

/**
 * OWASP LLM ids are from the OWASP Top 10 for LLM Applications 2025.
 * OWASP Agentic ids are from the OWASP Top 10 for Agentic Applications 2026.
 * MITRE ATLAS ids are technique ids from ATLAS (AML.T0010.005 names MCP servers explicitly).
 * OpenCRE ids (opencre.org, CC0) were checked against the OpenCRE REST API on 2026-10-30.
 * LLM01 direct injection is CRE 686-110; text inside a skill is indirect injection, CRE 012-625.
 * An empty list means no mapping was defensible enough to cite.
 */
export const RULE_REFERENCES: Record<string, RuleReferences> = {
  'IH-EXEC-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: ['AML.T0053'],
    openCre: ['307-507', '715-223'],
  },
  'IH-EXEC-002': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
    openCre: ['307-507', '715-223'],
  },
  'IH-EXEC-003': {
    owaspLlm: ['LLM05:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
    openCre: ['317-743'],
  },
  'IH-EXEC-004': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI03:2026'],
    mitreAtlas: [],
    openCre: ['202-604', '333-480'],
  },
  'IH-EXEC-005': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: ['ASI03:2026'],
    mitreAtlas: ['AML.T0055'],
    openCre: ['123-124', '368-633'],
  },
  'IH-NET-001': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
    openCre: ['814-322'],
  },
  'IH-NET-002': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: ['ASI02:2026'],
    mitreAtlas: ['AML.T0025'],
    openCre: ['814-322'],
  },
  'IH-CRED-001': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
    openCre: ['368-633', '881-321'],
  },
  'IH-CRED-002': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0055'],
    openCre: ['774-888'],
  },
  'IH-CRED-003': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
    openCre: ['340-375'],
  },
  'IH-CRED-004': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
    openCre: ['881-321', '123-124'],
  },
  'IH-CRED-005': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
    openCre: ['333-888'],
  },
  'IH-CRED-006': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0055'],
    openCre: ['774-888', '813-610'],
  },
  'IH-INJ-001': {
    owaspLlm: ['LLM01:2025'],
    owaspAgentic: ['ASI01:2026'],
    mitreAtlas: ['AML.T0051', 'AML.T0051.001'],
    openCre: ['012-625'],
  },
  'IH-INJ-002': {
    owaspLlm: ['LLM01:2025'],
    owaspAgentic: ['ASI01:2026'],
    mitreAtlas: ['AML.T0051.001', 'AML.T0068'],
    openCre: ['012-625'],
  },
  'IH-INJ-003': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI03:2026', 'ASI06:2026'],
    mitreAtlas: [],
    openCre: ['012-625', '202-604'],
  },
  'IH-INJ-004': {
    owaspLlm: ['LLM01:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: [],
    openCre: ['012-625', '307-507'],
  },
  'IH-OBF-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [], openCre: ['265-800', '611-158'] },
  'IH-PERSIST-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [], openCre: ['838-636'] },
  'IH-PRIV-001': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI03:2026'],
    mitreAtlas: [],
    openCre: ['368-633', '330-281'],
  },
  'IH-BIN-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
    openCre: ['171-222', '265-800'],
  },
  'IH-BIN-002': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: [],
    openCre: ['265-800', '611-158'],
  },
  'IH-FS-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [], openCre: [] },
  'IH-META-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [], openCre: [] },
  'IH-REF-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: [],
    openCre: [],
  },
  'IH-INT-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
    openCre: ['307-507'],
  },
  'IH-INT-002': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
    openCre: ['307-507'],
  },
  'IH-INT-003': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
    openCre: ['307-507'],
  },
  'IH-INT-004': {
    owaspLlm: [],
    owaspAgentic: ['ASI06:2026'],
    mitreAtlas: [],
    openCre: ['418-853'],
  },
  'IH-MCP-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010.005'],
    openCre: ['307-507', '613-287'],
  },
  'IH-MCP-002': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
    openCre: ['774-888'],
  },
  'IH-MCP-003': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI02:2026'],
    mitreAtlas: [],
    openCre: ['123-124'],
  },
  'IH-ADV-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
    openCre: ['265-800'],
  },
  'IH-CFG-001': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
    openCre: ['515-021', '233-748'],
  },
  'IH-CFG-002': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: [],
    mitreAtlas: [],
    openCre: ['065-183', '233-748'],
  },
  'IH-CFG-003': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
    openCre: ['746-705'],
  },
  'IH-CFG-004': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
    openCre: ['746-705'],
  },
  'IH-CFG-005': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
    openCre: ['881-321', '340-375'],
  },
  'IH-CFG-006': {
    owaspLlm: ['LLM02:2025'],
    owaspAgentic: [],
    mitreAtlas: ['AML.T0055'],
    openCre: ['123-124', '233-748'],
  },
  'IH-CFG-007': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
    openCre: ['202-604', '368-633'],
  },
  'IH-CFG-008': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: [],
    openCre: ['307-507'],
  },
  'IH-CFG-009': {
    owaspLlm: ['LLM06:2025'],
    owaspAgentic: ['ASI05:2026'],
    mitreAtlas: [],
    openCre: ['333-480', '515-021'],
  },
  'IH-DEP-001': {
    owaspLlm: ['LLM03:2025'],
    owaspAgentic: ['ASI04:2026'],
    mitreAtlas: ['AML.T0010'],
    openCre: ['613-287', '613-286'],
  },
  // Advisory notes are not a detection technique, so no framework id is cited.
  'IH-LLM-001': { owaspLlm: [], owaspAgentic: [], mitreAtlas: [], openCre: [] },
};

export function referencesFor(ruleId: string): RuleReferences {
  return RULE_REFERENCES[ruleId] ?? { owaspLlm: [], owaspAgentic: [], mitreAtlas: [], openCre: [] };
}

export function referenceTags(ruleId: string): string[] {
  const refs = referencesFor(ruleId);
  return [...refs.owaspLlm, ...refs.owaspAgentic, ...refs.mitreAtlas];
}

/** Names of every OpenCRE id cited above, as returned by https://www.opencre.org/rest/v1/id/<id>. */
export const OPENCRE_NAMES: Record<string, string> = {
  '012-625': 'Indirect prompt injection',
  '065-183': 'Disallow default credentials',
  '123-124': 'Minimize permissions',
  '171-222': 'Check binary integrity before deployment',
  '202-604': 'Human AI oversight',
  '233-748': 'Configuration hardening',
  '265-800': 'Check source code and third party libraries to not contain malicious code',
  '307-507':
    'Allow only trusted sources both build time and runtime; therefore perform integrity checks on all resources and code',
  '317-743': 'Do not use eval or dynamic code execution functions',
  '330-281': 'Use least privilege OS accounts for system (components)',
  '333-480': 'Impact limitation of unwanted model behaviour',
  '333-888': 'Do not expose data through API URLs',
  '340-375': 'Use a dedicated secrets management solution',
  '368-633': 'Enforce least privilege',
  '418-853': 'Monitor unusual activities on system',
  '515-021': 'Sandbox, containerize and/or isolate applications at the network level',
  '611-158': 'Use static analysis tooling to detect potentially malicious actions',
  '613-286': 'Dependency management',
  '613-287': 'Dependency integrity',
  '715-223': 'Ensure trusted origin of third party resources',
  '746-705': "Limit/authorize user's access to functionality",
  '774-888': 'Do not store secrets in the code',
  '813-610': 'Do not use static secrets',
  '814-322': 'Whitelist data sources and sinks',
  '838-636': 'Check source code and third party libraries to not contain backdoors',
  '881-321': 'Store credentials securely',
};

export const OWASP_LLM_NAMES: Record<string, string> = {
  'LLM01:2025': 'Prompt Injection',
  'LLM02:2025': 'Sensitive Information Disclosure',
  'LLM03:2025': 'Supply Chain',
  'LLM04:2025': 'Data and Model Poisoning',
  'LLM05:2025': 'Improper Output Handling',
  'LLM06:2025': 'Excessive Agency',
  'LLM07:2025': 'System Prompt Leakage',
  'LLM08:2025': 'Vector and Embedding Weaknesses',
  'LLM09:2025': 'Misinformation',
  'LLM10:2025': 'Unbounded Consumption',
};

const OWASP_LLM_SLUGS: Record<string, string> = {
  'LLM01:2025': 'llm01-prompt-injection',
  'LLM02:2025': 'llm022025-sensitive-information-disclosure',
  'LLM03:2025': 'llm032025-supply-chain',
  'LLM04:2025': 'llm042025-data-and-model-poisoning',
  'LLM05:2025': 'llm052025-improper-output-handling',
  'LLM06:2025': 'llm062025-excessive-agency',
  'LLM07:2025': 'llm072025-system-prompt-leakage',
  'LLM08:2025': 'llm082025-vector-and-embedding-weaknesses',
  'LLM09:2025': 'llm092025-misinformation',
  'LLM10:2025': 'llm102025-unbounded-consumption',
};

export interface ReferenceLink {
  label: string;
  url: string;
}

/** Static links only. Building them makes no network call. */
export function openCreUrl(id: string): string {
  return `https://www.opencre.org/cre/${id}`;
}

export function rulePageUrl(ruleId: string): string {
  return `https://www.ironheights.dev/rules/${ruleId.toLowerCase()}`;
}

export function referenceLinks(ruleId: string): ReferenceLink[] {
  const refs = referencesFor(ruleId);
  const links: ReferenceLink[] = [];
  for (const id of refs.owaspLlm) {
    const slug = OWASP_LLM_SLUGS[id];
    if (slug) {
      links.push({
        label: `OWASP ${id} ${OWASP_LLM_NAMES[id] ?? ''}`.trim(),
        url: `https://genai.owasp.org/llmrisk/${slug}/`,
      });
    }
  }
  for (const id of refs.openCre) {
    links.push({ label: `OpenCRE ${id} ${OPENCRE_NAMES[id] ?? ''}`.trim(), url: openCreUrl(id) });
  }
  return links;
}

/** One short line for terminal output, for example "OWASP LLM01:2025 · CRE 012-625". */
export function standardsLine(ruleId: string): string | undefined {
  const refs = referencesFor(ruleId);
  const parts = [
    ...refs.owaspLlm.map((id) => `OWASP ${id}`),
    ...refs.openCre.map((id) => `CRE ${id}`),
  ];
  return parts.length > 0 ? parts.join(' · ') : undefined;
}
