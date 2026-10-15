import picomatch from 'picomatch';
import type {
  EvidenceMatch,
  Finding,
  RefusedSuppression,
  ResolvedConfig,
  ScannedFile,
  SkillReport,
  StaleSuppression,
  SuppressedFinding,
  SuppressionEntry,
} from './types.ts';

const MIN_REASON = 8;
const RULE_ID = 'IH-[A-Z]+-\\d{3}';
const MARKER = new RegExp(
  `ironheights-ignore\\b(?:\\s+(\\*|${RULE_ID}(?:,${RULE_ID})*))?(?:\\s+reason=(?:"([^"]*)"|'([^']*)'|([^\\s]+)))?`,
  'g',
);

/** Printed by `--print-suppressions`. A real reason has to replace it. */
export const SUPPRESSION_REASON_PLACEHOLDER = 'TODO: reason';

export type AcceptanceDrift = NonNullable<Finding['acceptance']>;

interface Directive {
  rules: string[];
  reason: string;
}

export interface SuppressionOutcome {
  active: Finding[];
  suppressed: SuppressedFinding[];
  refused: RefusedSuppression[];
  warnings: string[];
  stale: StaleSuppression[];
  matches: EvidenceMatch[];
}

type SuppressionConfig = Pick<
  ResolvedConfig,
  'suppressions' | 'suppressCritical' | 'suppressIntegrity'
>;

interface ReasonMatch {
  reason: string;
  bound: boolean;
}

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
  const matched = new Set<number>();
  const matches: EvidenceMatch[] = [];
  const pending: Finding[] = [];

  for (const finding of findings) {
    for (const index of boundHits(finding, config)) {
      matched.add(index);
      const entry = config.suppressions[index];
      if (entry?.evidence === undefined) continue;
      matches.push({
        ruleId: entry.ruleId,
        ...(entry.path ? { path: entry.path } : {}),
        evidence: entry.evidence,
      });
    }
    const match = matchSuppression(finding, inline, config);
    if (!match) {
      pending.push(finding);
      continue;
    }
    const detail = refusalDetail(finding, config, match.reason);
    if (detail) {
      active.push(finding);
      refused.push({
        ruleId: finding.ruleId,
        severity: finding.severity,
        file: finding.file,
        ...(finding.line !== undefined ? { line: finding.line } : {}),
        ...(match.bound ? { evidence: finding.evidence } : {}),
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
      reason: match.reason,
    });
  }

  const matchedKeys = new Set(matches.map((item) => entryKey(item)));
  for (const finding of pending) {
    const label = acceptanceFor(finding, config.suppressions, matchedKeys);
    active.push(label ? { ...finding, acceptance: label } : finding);
  }

  return {
    active,
    suppressed,
    refused,
    warnings,
    stale: staleEntries(config, files, findings, matched),
    matches,
  };
}

/**
 * Drop stale entries that matched in another skill, and relabel findings once
 * every skill has been scanned. A named acceptance is global: another skill
 * with the same rule and path does not inherit it.
 */
export function reconcileEvidenceDrift(
  skills: SkillReport[],
  suppressions: readonly SuppressionEntry[],
): SkillReport[] {
  const matched = new Set<string>();
  for (const skill of skills) {
    for (const item of skill.evidenceMatches ?? []) matched.add(entryKey(item));
  }
  return skills.map((skill) => {
    const refused = skill.suppressionRefused ?? [];
    const findings = skill.findings.map((finding) => {
      if (wasRefused(finding, refused)) return withoutAcceptance(finding);
      const label = acceptanceFor(finding, suppressions, matched);
      if (!label) return withoutAcceptance(finding);
      if (finding.acceptance === label) return finding;
      return { ...finding, acceptance: label };
    });
    const stale = (skill.staleSuppressions ?? []).filter((item) => !matched.has(entryKey(item)));
    const next: SkillReport = { ...skill, findings };
    if (stale.length > 0) next.staleSuppressions = stale;
    else delete next.staleSuppressions;
    return next;
  });
}

export function acceptanceLabel(label: AcceptanceDrift): string {
  switch (label) {
    case 'accepted finding changed':
    case 'not accepted':
      return label;
    default: {
      const neverLabel: never = label;
      return neverLabel;
    }
  }
}

/** One config entry per current finding. The reason is a placeholder until a person edits it. */
export function suggestedSuppressions(findings: readonly Finding[]): SuppressionEntry[] {
  const seen = new Set<string>();
  const entries: SuppressionEntry[] = [];
  for (const finding of findings) {
    const key = `${finding.ruleId}\0${finding.file}\0${finding.evidence}`;
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push({
      ruleId: finding.ruleId,
      path: finding.file,
      evidence: finding.evidence,
      reason: SUPPRESSION_REASON_PLACEHOLDER,
    });
  }
  return entries;
}

export function renderSuppressionConfig(findings: readonly Finding[]): string {
  return `${JSON.stringify({ suppressions: suggestedSuppressions(findings) }, null, 2)}\n`;
}

export function isPlaceholderReason(reason: string): boolean {
  return reason.trim() === SUPPRESSION_REASON_PLACEHOLDER;
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

function matchSuppression(
  finding: Finding,
  inline: Map<string, Map<number, Directive[]>>,
  config: SuppressionConfig,
): ReasonMatch | undefined {
  const fromInline = inlineReason(finding, inline);
  if (fromInline) return { reason: fromInline, bound: false };
  for (const entry of config.suppressions) {
    if (entry.ruleId !== finding.ruleId) continue;
    if (entry.evidence !== undefined) {
      if (!pathMatches(entry.path, finding.file)) continue;
      if (entry.evidence !== finding.evidence) continue;
      return { reason: entry.reason, bound: true };
    }
    if (entry.line !== undefined && entry.line !== finding.line) continue;
    if (!pathMatches(entry.path, finding.file)) continue;
    return { reason: entry.reason, bound: false };
  }
  return undefined;
}

function boundHits(finding: Finding, config: SuppressionConfig): number[] {
  const hits: number[] = [];
  config.suppressions.forEach((entry, index) => {
    if (entry.evidence === undefined) return;
    if (entry.ruleId !== finding.ruleId) return;
    if (!pathMatches(entry.path, finding.file)) return;
    if (entry.evidence !== finding.evidence) return;
    hits.push(index);
  });
  return hits;
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

function refusalDetail(
  finding: Finding,
  config: SuppressionConfig,
  reason: string,
): string | undefined {
  const reasons: string[] = [];
  if (finding.severity === 'critical' && !config.suppressCritical) {
    reasons.push('critical findings stay visible unless suppressCritical is true');
  }
  if (finding.ruleId.startsWith('IH-INT-') && !config.suppressIntegrity) {
    reasons.push('integrity findings stay visible unless suppressIntegrity is true');
  }
  if (isPlaceholderReason(reason)) {
    reasons.push(
      `reason is the placeholder "${SUPPRESSION_REASON_PLACEHOLDER}"; write why this finding is accepted`,
    );
  }
  if (reasons.length === 0) return undefined;
  return reasons.join('; ');
}

function acceptanceFor(
  finding: Finding,
  entries: readonly SuppressionEntry[],
  matched: ReadonlySet<string>,
): AcceptanceDrift | undefined {
  const bound = entries.filter(
    (entry) =>
      entry.evidence !== undefined &&
      entry.ruleId === finding.ruleId &&
      pathMatches(entry.path, finding.file),
  );
  if (bound.length === 0) return undefined;
  let stale = 0;
  let live = 0;
  for (const entry of bound) {
    const evidence = entry.evidence;
    if (evidence === undefined) continue;
    const key = entryKey({
      ruleId: entry.ruleId,
      ...(entry.path ? { path: entry.path } : {}),
      evidence,
    });
    if (matched.has(key)) live += 1;
    else stale += 1;
  }
  if (stale > 0 && live === 0) return 'accepted finding changed';
  if (live > 0) return 'not accepted';
  return undefined;
}

function staleEntries(
  config: SuppressionConfig,
  files: Array<Pick<ScannedFile, 'relativePath'>>,
  findings: readonly Finding[],
  matched: ReadonlySet<number>,
): StaleSuppression[] {
  const stale: StaleSuppression[] = [];
  config.suppressions.forEach((entry, index) => {
    if (entry.evidence === undefined || matched.has(index)) return;
    if (!entryInScope(entry, files, findings)) return;
    stale.push({
      ruleId: entry.ruleId,
      ...(entry.path ? { path: entry.path } : {}),
      evidence: entry.evidence,
      reason: entry.reason,
    });
  });
  return stale;
}

function entryInScope(
  entry: SuppressionEntry,
  files: Array<Pick<ScannedFile, 'relativePath'>>,
  findings: readonly Finding[],
): boolean {
  if (!entry.path) return true;
  return (
    files.some((file) => pathMatches(entry.path, file.relativePath)) ||
    findings.some((finding) => pathMatches(entry.path, finding.file))
  );
}

function pathMatches(path: string | undefined, file: string): boolean {
  if (!path) return true;
  return picomatch(path, { dot: true })(file);
}

function entryKey(entry: { ruleId: string; path?: string; evidence: string }): string {
  return `${entry.ruleId}\0${entry.path ?? ''}\0${entry.evidence}`;
}

function wasRefused(finding: Finding, refused: readonly RefusedSuppression[]): boolean {
  return refused.some(
    (item) =>
      item.ruleId === finding.ruleId &&
      item.file === finding.file &&
      item.line === finding.line &&
      (item.evidence === undefined || item.evidence === finding.evidence),
  );
}

function withoutAcceptance(finding: Finding): Finding {
  if (finding.acceptance === undefined) return finding;
  const next = { ...finding };
  delete next.acceptance;
  return next;
}
