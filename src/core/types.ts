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
  detail: string;
}

/**
 * Letter grades use the trust score 100 minus the risk score, capped at 0.
 * `incomplete` has no numeric score: a skipped file must not look like a pass.
 */
export interface Grade {
  letter: 'A' | 'B' | 'C' | 'D' | 'F' | 'incomplete';
  score?: number;
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
  sinceBaseline?: SinceBaselineNote;
}

export interface JsonSkillReport extends SkillReport {
  skippedFileCount: number;
  suppressedCount: number;
  suppressionRefusedCount: number;
  findings: Array<Finding & { references?: RuleReferences }>;
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
