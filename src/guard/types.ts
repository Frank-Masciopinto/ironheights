/** Runtime guard decisions. These are not content-scan findings. */

export const GUARD_RULE_IDS = [
  'IH-GUARD-CRED',
  'IH-GUARD-EXEC',
  'IH-GUARD-NET',
  'IH-GUARD-WRITE',
] as const;

export type GuardRuleId = (typeof GUARD_RULE_IDS)[number];

export type DecisionRuleId = GuardRuleId | 'IH-GUARD-ERROR';

export type GuardMode = 'monitor' | 'enforce';

export type GuardSeverity = 'medium' | 'high' | 'critical';

export interface ToolCall {
  toolName: string;
  params: Record<string, unknown>;
  derivedPaths: string[];
  /** Set when the caller can attribute the call to one skill. Unattributed calls do not inherit a skill allowlist. */
  skill?: string;
  toolKind?: string;
  toolInputKind?: string;
}

export interface GuardAllow {
  id: string;
  reason: string;
  rule?: GuardRuleId;
  tool?: string;
  skill?: string;
  path?: string;
  host?: string;
}

export interface ResolvedGuardPolicy {
  mode: GuardMode;
  /** Built-in hosts, ironheights.config.json allowDomains, and policy allowDomains. */
  globalAllowDomains: string[];
  /** Hosts from the policy file, keyed by skill name. */
  skills: Record<string, { allowDomains: string[] }>;
  /** Hosts from that skill's metadata.ironheights.allowDomains. */
  skillDeclaredDomains: Record<string, string[]>;
  allow: GuardAllow[];
  /** Agent identity, memory, credential, and config paths. */
  protectedPaths: string[];
  skillDirs: string[];
  homeDir: string;
  stateDir: string;
  workspaceDir: string;
}

export interface Violation {
  ruleId: GuardRuleId;
  severity: GuardSeverity;
  message: string;
  evidence: string;
  host?: string;
  path?: string;
}

export interface SuppressedViolation {
  ruleId: GuardRuleId;
  allowId: string;
  host?: string;
  path?: string;
}

export interface GuardDecision {
  action: 'allow' | 'block';
  mode: GuardMode;
  wouldBlock: boolean;
  violations: Violation[];
  allowed: SuppressedViolation[];
  reason: string;
}

export interface AuditEvent {
  schemaVersion: 1;
  time: string;
  kind: 'decision' | 'policy-error' | 'guard-error';
  mode: GuardMode;
  action: 'allow' | 'block';
  wouldBlock: boolean;
  tool: string;
  skill?: string;
  ruleIds: string[];
  allowIds: string[];
  reason: string;
}

export interface GuardLogOptions {
  path: string;
  maxBytes: number;
  maxFiles: number;
}

export const DEFAULT_LOG_MAX_BYTES = 1024 * 1024;
export const DEFAULT_LOG_MAX_FILES = 5;
export const GUARD_LOG_NAME = 'guard.log.jsonl';
export const GUARD_POLICY_NAME = 'guard-policy.json';
export const GUARD_PLUGIN_ID = 'ironheights-guard';
