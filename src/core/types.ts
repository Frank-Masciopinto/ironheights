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
  | 'integrity';

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
  priority: 'P0' | 'P1';
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

export interface SkillReport {
  skillName: string;
  root: string;
  filesScanned: number;
  filesSkipped: SkippedFile[];
  findings: Finding[];
  score: number;
  verdict: Verdict;
}

export interface ScanOutput {
  schemaVersion: number;
  tool: { name: string; version: string };
  scannedAt: string;
  verdict: Verdict;
  skippedFileCount: number;
  skills: Array<SkillReport & { skippedFileCount: number }>;
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

export interface RuleOverride {
  enabled?: boolean;
  severity?: Severity;
}

export interface ResolvedConfig {
  skillDirs: string[];
  agentFiles: string[];
  allowDomains: string[];
  ignoreGlobs: string[];
  ruleOverrides: Record<string, RuleOverride>;
  failOn?: Severity;
  limits: Limits;
  thresholds: Thresholds;
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
