import picomatch from 'picomatch';
import type {
  Finding,
  RefusedSuppression,
  ResolvedConfig,
  ScannedFile,
  SuppressedFinding,
} from './types.ts';

const MIN_REASON = 8;
const RULE_ID = 'IH-[A-Z]+-\\d{3}';
const MARKER = new RegExp(
  `ironheights-ignore\\b(?:\\s+(\\*|${RULE_ID}(?:,${RULE_ID})*))?(?:\\s+reason=(?:"([^"]*)"|'([^']*)'|([^\\s]+)))?`,
  'g',
);

interface Directive {
  rules: string[];
  reason: string;
}

export interface SuppressionOutcome {
  active: Finding[];
  suppressed: SuppressedFinding[];
  refused: RefusedSuppression[];
  warnings: string[];
}

type SuppressionConfig = Pick<
  ResolvedConfig,
  'suppressions' | 'suppressCritical' | 'suppressIntegrity'
>;

export function applySuppressions(
  findings: Finding[],
  files: Array<Pick<ScannedFile, 'relativePath' | 'text'>>,
  config: SuppressionConfig,
): SuppressionOutcome {
  const inline = new Map<string, Map<number, Directive[]>>();
  const warnings: string[] = [];
  for (const file of files) {
    collectDirectives(file.relativePath, file.text, inline, warnings);
  }

  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  const refused: RefusedSuppression[] = [];

  for (const finding of findings) {
    const reason = matchReason(finding, inline, config);
    if (!reason) {
      active.push(finding);
      continue;
    }
    const detail = refusalDetail(finding, config);
    if (detail) {
      active.push(finding);
      refused.push({
        ruleId: finding.ruleId,
        severity: finding.severity,
        file: finding.file,
        ...(finding.line !== undefined ? { line: finding.line } : {}),
        detail,
      });
      continue;
    }
    suppressed.push({
      ruleId: finding.ruleId,
      severity: finding.severity,
      file: finding.file,
      ...(finding.line !== undefined ? { line: finding.line } : {}),
      evidence: finding.evidence,
      reason,
    });
  }

  return { active, suppressed, refused, warnings };
}

function collectDirectives(
  file: string,
  text: string,
  inline: Map<string, Map<number, Directive[]>>,
  warnings: string[],
): void {
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    MARKER.lastIndex = 0;
    let match = MARKER.exec(line);
    while (match) {
      const rulePart = match[1];
      const reason = (match[2] ?? match[3] ?? match[4] ?? '').trim();
      const lineNumber = index + 1;
      if (!rulePart || reason.length < MIN_REASON) {
        warnings.push(
          `${file}:${lineNumber} ironheights-ignore needs a rule id and a reason of at least ${MIN_REASON} characters`,
        );
      } else {
        const rules = rulePart === '*' ? ['*'] : rulePart.split(',');
        const bucket = inline.get(file) ?? new Map<number, Directive[]>();
        const list = bucket.get(lineNumber) ?? [];
        list.push({ rules, reason });
        bucket.set(lineNumber, list);
        inline.set(file, bucket);
      }
      match = MARKER.exec(line);
    }
  }
}

function matchReason(
  finding: Finding,
  inline: Map<string, Map<number, Directive[]>>,
  config: SuppressionConfig,
): string | undefined {
  const fromInline = inlineReason(finding, inline);
  if (fromInline) return fromInline;
  for (const entry of config.suppressions) {
    if (entry.ruleId !== finding.ruleId) continue;
    if (entry.line !== undefined && entry.line !== finding.line) continue;
    if (entry.path && !picomatch(entry.path, { dot: true })(finding.file)) continue;
    return entry.reason;
  }
  return undefined;
}

function inlineReason(
  finding: Finding,
  inline: Map<string, Map<number, Directive[]>>,
): string | undefined {
  if (finding.line === undefined) return undefined;
  const lines = inline.get(finding.file);
  if (!lines) return undefined;
  const directives = [...(lines.get(finding.line) ?? []), ...(lines.get(finding.line - 1) ?? [])];
  for (const directive of directives) {
    if (directive.rules.includes('*') || directive.rules.includes(finding.ruleId)) {
      return directive.reason;
    }
  }
  return undefined;
}

function refusalDetail(finding: Finding, config: SuppressionConfig): string | undefined {
  const reasons: string[] = [];
  if (finding.severity === 'critical' && !config.suppressCritical) {
    reasons.push('critical findings stay visible unless suppressCritical is true');
  }
  if (finding.ruleId.startsWith('IH-INT-') && !config.suppressIntegrity) {
    reasons.push('integrity findings stay visible unless suppressIntegrity is true');
  }
  if (reasons.length === 0) return undefined;
  return reasons.join('; ');
}
