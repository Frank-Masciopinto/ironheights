import type { UnscannedDependency } from './dependencies.ts';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';
export type Category =
  | 'exec'
  | 'network'
  | 'credentials'
  | 'injection'
  | 'obfuscation'
  | 'persistence'
  | 'privilege'
  | 'binary'
  | 'filesystem'
  | 'meta'
  | 'integrity'
  | 'mcp'
  | 'advisory'
  | 'config'
  | 'llm-review';

export type FileKind = 'markdown' | 'script' | 'config' | 'binary' | 'text';
export type AppliesTo = 'markdown' | 'script' | 'config' | 'binary' | 'any';
export type Verdict = 'no-findings' | 'review' | 'block' | 'incomplete';

export interface ScannedFile {
  relativePath: string;
  kind: FileKind;
  archive: boolean;
  size: number;
  mode: number;
  text: string;
  head: Uint8Array;
  symlinkOutside: boolean;
  symlinkLoop: boolean;
  symlinkTarget?: string;
  hidden: boolean;
}

export interface ScanContext {
  config: ResolvedConfig;
  root: string;
  skillDirName: string;
  /** Hosts from this skill's `metadata.ironheights.allowDomains`. */
  skillAllowDomains: string[];
  /** Hosts the skill declares as its own (frontmatter `homepage`, metadata api_base/homepage/network). */
  skillDeclaredHosts?: string[];
  /**
   * True when a non-test file in this skill names a secret-shaped variable.
   * The scanner sets it. IH-EXEC-005 uses it so an explicit full-environment
   * copy is flagged even when the key lives in a different file. Omitted means
   * the rule looks at this file only.
   */
  skillHoldsSecret?: boolean;
}

export interface RuleExamples {
  matches: string[];
  nonMatches: string[];
}

export interface Rule {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  priority: 'P0' | 'P1' | 'advisory';
  description: string;
  remediation: string;
  appliesTo: AppliesTo[];
  examples: RuleExamples;
  check(file: ScannedFile, ctx: ScanContext): Finding[];
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  file: string;
  line?: number;
  column?: number;
  evidence: string;
  message: string;
  remediation: string;
  /** Extra context for the reader. It never changes severity, score or verdict. */
  note?: string;
  /**
   * Set when an evidence-bound suppression covers this rule and path but not this
   * finding. It does not change severity, score, or verdict.
   * `accepted finding changed` — every named acceptance for this rule and path missed.
   * `not accepted` — a named acceptance still matches a different finding here.
   */
  acceptance?: 'accepted finding changed' | 'not accepted';
  /**
   * Set when every URL in the finding points at a host the skill declares as its own
   * (frontmatter homepage, metadata api_base). The finding keeps its severity and the
   * verdict is unchanged; only the letter grade weighs it as a review item.
   */
  firstParty?: boolean;
}

export interface SkippedFile {
  file: string;
  reason: string;
}

/**
 * A directory the scan did not enter.
 * `explicit` means `ignoreDirs` named it, so it does not make the scan incomplete.
 */
export interface SkippedDirectory {
  path: string;
  reason: string;
  explicit?: boolean;
}

/** Config entry that acknowledges a `.git` or `node_modules` directory. */
export interface IgnoreDir {
  path: string;
  reason: string;
}

/** Framework ids cited on a rule. Empty arrays mean no defensible mapping. */
export interface RuleReferences {
  owaspLlm: string[];
  owaspAgentic: string[];
  mitreAtlas: string[];
  /** OpenCRE common requirement ids, linked as https://www.opencre.org/cre/<id>. */
  openCre: string[];
}

export interface SuppressedFinding {
  ruleId: string;
  severity: Severity;
  file: string;
  line?: number;
  evidence: string;
  reason: string;
}

export interface RefusedSuppression {
  ruleId: string;
  severity: Severity;
  file: string;
  line?: number;
  /** Set when an evidence-bound entry matched this finding and was refused. */
  evidence?: string;
  detail: string;
}

/** An evidence-bound suppression that matched no finding in a file it covers. */
export interface StaleSuppression {
  ruleId: string;
  path?: string;
  evidence: string;
  reason: string;
}

/** An evidence-bound suppression that matched a finding. Omitted from JSON. */
export interface EvidenceMatch {
  ruleId: string;
  path?: string;
  evidence: string;
}

/**
 * Letter grades use the trust score 100 minus the risk score, capped at 0.
 * `incomplete` has no numeric score: a skipped file must not look like a pass.
 */
export interface Grade {
  letter: 'A' | 'B' | 'C' | 'D' | 'F' | 'incomplete' | 'nothing-scanned';
  score?: number;
  /** Registry packages the skills install whose code was not scanned. */
  unscannedDependencies?: number;
  disclaimer: string;
}

export interface SinceBaselineOmitted {
  ruleId: string;
  severity: Severity;
  file: string;
  line?: number;
  evidence: string;
}

export interface SinceBaselineNote {
  comparedWith: string;
  kind: 'integrity' | 'scan-result';
  omittedCount?: number;
  omitted: SinceBaselineOmitted[];
}

export interface SkillReport {
  skillName: string;
  root: string;
  filesScanned: number;
  filesSkipped: SkippedFile[];
  /** `.git` and `node_modules` directories that were not entered. */
  skippedDirectories?: SkippedDirectory[];
  findings: Finding[];
  score: number;
  verdict: Verdict;
  /** Risk points after suppression and before `--since-baseline`. The grade uses this. */
  gradeRisk?: number;
  suppressed?: SuppressedFinding[];
  suppressionRefused?: RefusedSuppression[];
  suppressionWarnings?: string[];
  /** Evidence-bound entries that covered a scanned file and matched nothing. */
  staleSuppressions?: StaleSuppression[];
  /** Matched evidence-bound entries. Renderers omit this. */
  evidenceMatches?: EvidenceMatch[];
  sinceBaseline?: SinceBaselineNote;
  /** Set when the folder or SKILL.md name equals a listed security tool. Not verified. */
  knownSecurityTool?: KnownSecurityToolNote;
  /**
   * Packages the skill installs from a registry (frontmatter install entries and install commands
   * in SKILL.md). Their code was not scanned, so a clean grade covers the skill's files only.
   */
  unscannedDependencies?: UnscannedDependency[];
  /** Set by `scan --check-registry`. */
  registryCheck?: { checked: number; missing: number; notChecked: number; notes: string[] };
}

export interface KnownSecurityToolNote {
  id: string;
  name: string;
  matchedBy: 'folder-name' | 'skill-name';
  /** Always false. A name match proves nothing about the files. */
  verified: false;
  /** How many findings had their confidence lowered one step. */
  downgradedFindings: number;
  note: string;
}

export interface JsonSkillReport extends SkillReport {
  skippedFileCount: number;
  suppressedCount: number;
  suppressionRefusedCount: number;
  findings: Array<
    Finding & { references?: RuleReferences; links?: Array<{ label: string; url: string }> }
  >;
}

export interface AdvisoryFeedNote {
  entries: number;
  generatedAt: string;
}

export interface ScanOutput {
  schemaVersion: number;
  tool: { name: string; version: string };
  scannedAt: string;
  verdict: Verdict;
  skippedFileCount: number;
  /** Present when a `.git` or `node_modules` directory was not entered. */
  skippedDirectories?: SkippedDirectory[];
  grade: Grade;
  scanMode: 'directory' | 'text';
  summary: string;
  badge: string;
  scanLimit?: string;
  sinceBaseline?: { path: string; kind: 'integrity' | 'scan-result'; omittedCount: number };
  skills: JsonSkillReport[];
  /** Present only when a cached advisory feed was checked during this scan. */
  advisoryFeed?: AdvisoryFeedNote;
}

export interface Limits {
  maxFileBytes: number;
  maxFiles: number;
  maxDepth: number;
}

export interface Thresholds {
  block: number;
  review: number;
}

/** Connection defaults for an opt-in model review. Presence does not enable it. */
export interface ResolvedLlmConfig {
  url: string;
  model: string;
  api?: 'ollama' | 'openai';
  timeoutMs: number;
  maxInputChars: number;
}

export interface RuleOverride {
  enabled?: boolean;
  severity?: Severity;
}

export interface SuppressionEntry {
  ruleId: string;
  path?: string;
  line?: number;
  /**
   * When set, the entry suppresses only a finding with this exact evidence.
   * Line numbers are ignored, matching `scan --since-baseline` on a previous
   * JSON result (rule id, file, evidence).
   */
  evidence?: string;
  reason: string;
}

export interface ResolvedConfig {
  skillDirs: string[];
  agentFiles: string[];
  allowDomains: string[];
  ignoreGlobs: string[];
  ignoreDirs: IgnoreDir[];
  ruleOverrides: Record<string, RuleOverride>;
  suppressions: SuppressionEntry[];
  /** When false, a suppression never hides a critical finding. */
  suppressCritical: boolean;
  /** When false, a suppression never hides an IH-INT finding. */
  suppressIntegrity: boolean;
  failOn?: Severity;
  limits: Limits;
  thresholds: Thresholds;
  llm: ResolvedLlmConfig;
  configPath?: string;
}

export interface FileRecord {
  sha256: string;
  size: number;
  mode: number;
}

export interface Baseline {
  version: 1;
  createdAt: string;
  toolVersion: string;
  roots: string[];
  files: Record<string, FileRecord>;
  treeHash: string;
}
