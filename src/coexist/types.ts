import type { Severity } from '../core/types.ts';
import type { ToolKind, ToolTraits, Tri } from './registry.ts';

export type EvidenceKind =
  | 'plugin-manifest'
  | 'plugin-config'
  | 'skill-dir'
  | 'skill-name'
  | 'hook-dir'
  | 'hook-config'
  | 'state-path'
  | 'cli-on-path'
  | 'repo-ci'
  | 'mcp-server'
  | 'code-hint';

export interface Evidence {
  kind: EvidenceKind;
  detail: string;
  path?: string;
}

export type Confidence = 'high' | 'medium' | 'low';

/** `enabled` and `disabled` come from an explicit OpenClaw config entry. `present` means files exist. */
export type ToolStatus = 'enabled' | 'disabled' | 'present';

export interface DetectedTool {
  id: string;
  name: string;
  /** False for a hook plugin found only by reading its code. */
  listed: boolean;
  kind: ToolKind | 'unlisted-plugin';
  confidence: Confidence;
  status: ToolStatus;
  /** Mode from OpenClaw config, or the manifest default for a listed tool. */
  mode?: string;
  modeSource?: 'config' | 'default';
  registersBeforeToolCall: Tri;
  canBlock: Tri;
  traits: ToolTraits;
  evidence: Evidence[];
  sources: string[];
}

export interface GuardSelfState {
  pluginEnabled: boolean | 'unknown';
  pluginListedInAllow: boolean | 'not-set';
  pluginDenied: boolean;
  mode: 'monitor' | 'enforce';
  modeSource: string;
  priority: number;
  policyPath: string;
  logPath: string;
  home: string;
  baselineExists: boolean;
  effectiveAllowDomains: string[];
}

export interface CoexistFinding {
  id: string;
  class: string;
  severity: Severity;
  title: string;
  detail: string;
  tools: string[];
  fix: string[];
  /** Config text to copy. Ironheights never writes it. */
  snippet?: string;
}

export interface CoexistReport {
  schemaVersion: 1;
  tool: { name: string; version: string };
  command: 'coexist';
  scannedAt: string;
  openclaw: {
    stateDir: string;
    configPath: string;
    configFound: boolean;
    configParsed: boolean;
  };
  ironheights: GuardSelfState;
  tools: DetectedTool[];
  proxyEnv: string[];
  findings: CoexistFinding[];
  summary: { toolCount: number; enabledToolCount: number; findingCount: number };
  notes: string[];
  limits: string[];
}
