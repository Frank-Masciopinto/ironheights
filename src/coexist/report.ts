import { SEVERITY_RANK } from '../core/verdict.ts';
import type { Severity } from '../core/types.ts';
import { paint } from '../util/terminal.ts';
import { TOOL_NAME, TOOL_VERSION } from '../version.ts';
import { analyzeConflicts, type ConflictOptions } from './conflicts.ts';
import { detectCoexistence, type DetectOptions, type Detection } from './detect.ts';
import type { CoexistFinding, CoexistReport, DetectedTool } from './types.ts';

export const COEXIST_LIMITS: string[] = [
  'Detection is heuristic. It reads files and names. It does not run other tools or ask a running Gateway.',
  'A name can be copied. A match means something with that name is present, not that it is the real tool.',
  'A tool we do not list, or one that was renamed, is not found. Absence of findings is not proof that tools will not interfere.',
  'Hook order and blocking follow the OpenClaw plugin docs checked on 11 October 2026.',
];

export async function buildCoexistReport(
  options: DetectOptions & ConflictOptions & { now?: Date } = {},
): Promise<CoexistReport> {
  const detection = await detectCoexistence(options);
  const findings = await analyzeConflicts(detection, {
    ...(options.env ? { env: options.env } : {}),
    ...(options.config ? { config: options.config } : {}),
  });
  return toReport(detection, findings, options.now ?? new Date());
}

export function toReport(
  detection: Detection,
  findings: CoexistFinding[],
  now: Date,
): CoexistReport {
  const { located } = detection;
  return {
    schemaVersion: 1,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    command: 'coexist',
    scannedAt: now.toISOString(),
    openclaw: {
      stateDir: located.stateDir,
      configPath: located.configPath,
      configFound: located.configFound,
      configParsed: located.configParsed,
    },
    ironheights: detection.self,
    tools: detection.tools,
    proxyEnv: detection.proxyEnv,
    findings,
    summary: {
      toolCount: detection.tools.length,
      enabledToolCount: detection.tools.filter((tool) => tool.status !== 'disabled').length,
      findingCount: findings.length,
    },
    notes: detection.notes,
    limits: COEXIST_LIMITS,
  };
}

export function worstSeverity(findings: CoexistFinding[]): Severity | undefined {
  let worst: Severity | undefined;
  for (const finding of findings) {
    if (!worst || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[worst]) worst = finding.severity;
  }
  return worst;
}

const COLOR: Record<Severity, string> = {
  critical: '31',
  high: '31',
  medium: '33',
  low: '36',
  info: '2',
};

export function renderCoexistText(report: CoexistReport, color: boolean): string {
  const lines: string[] = [];
  const self = report.ironheights;
  lines.push('Ironheights coexistence check (read-only, offline, heuristic)');
  lines.push(`OpenClaw state: ${report.openclaw.stateDir}`);
  lines.push(
    `OpenClaw config: ${report.openclaw.configFound ? (report.openclaw.configParsed ? 'read' : 'found, not parsed') : 'missing'} ${report.openclaw.configPath}`,
  );
  lines.push(
    `Ironheights guard: plugin ${self.pluginEnabled === true ? 'enabled' : self.pluginEnabled === false ? 'not enabled' : 'unknown'}, mode ${self.mode} (${self.modeSource}), priority ${self.priority}`,
  );
  lines.push('');
  if (report.tools.length === 0) {
    lines.push('Other security tools: none detected.');
  } else {
    lines.push(`Other security tools detected: ${report.tools.length}`);
    for (const tool of report.tools) lines.push(...toolLines(tool));
  }
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('Conflicts: none found.');
  } else {
    lines.push(`Conflicts and notes: ${report.findings.length}`);
    for (const finding of report.findings) {
      const label = paint(color, COLOR[finding.severity], `[${finding.severity}]`);
      lines.push(`  ${label} ${finding.id} ${finding.title}`);
      lines.push(`    ${finding.detail}`);
      for (const fix of finding.fix) lines.push(`    fix: ${fix}`);
      if (finding.snippet) {
        lines.push('    config (copy it yourself, Ironheights does not write it):');
        for (const line of finding.snippet.split('\n')) lines.push(`      ${line}`);
      }
    }
  }
  for (const note of report.notes) lines.push(`Note: ${note}`);
  lines.push('');
  for (const limit of report.limits) lines.push(limit);
  return lines.join('\n');
}

function toolLines(tool: DetectedTool): string[] {
  const mode = tool.mode ? `, mode ${tool.mode} (${tool.modeSource ?? 'config'})` : '';
  const guard =
    tool.registersBeforeToolCall === 'yes'
      ? ', guards tool calls'
      : tool.registersBeforeToolCall === 'unknown' && tool.kind === 'runtime-guard'
        ? ', may guard tool calls'
        : '';
  const lines = [
    `  - ${tool.name} [${tool.kind}] ${tool.status}, ${tool.confidence} confidence${mode}${guard}`,
  ];
  for (const item of tool.evidence.slice(0, 4)) {
    lines.push(`      ${item.kind}: ${item.detail}${item.path ? ` (${item.path})` : ''}`);
  }
  if (tool.evidence.length > 4) lines.push(`      +${tool.evidence.length - 4} more`);
  return lines;
}

export function renderCoexistSummary(report: CoexistReport): string {
  if (report.tools.length === 0) {
    return 'Other security tools: none detected (heuristic). Run `ironheights coexist` for details.';
  }
  const names = report.tools.map((tool) => tool.name).slice(0, 6);
  const more =
    report.tools.length > names.length ? ` and ${report.tools.length - names.length} more` : '';
  return `Other security tools: ${names.join(', ')}${more}. ${report.findings.length} note${report.findings.length === 1 ? '' : 's'}. Run \`ironheights coexist\`.`;
}
