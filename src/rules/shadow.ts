import type { Finding } from '../core/types.ts';

/**
 * Shadow mode for new detection checks.
 *
 * A rule marks a finding from a new check with `shadowCheck: '<name>'`. While that name is listed
 * here, the finding is reported at `info` with a "would block" note and never changes the score,
 * grade or verdict. `scripts/realworld-gate.py` scans the real-world clean set a second time with
 * `IRONHEIGHTS_SHADOW=enforce` (full severity) and lists every skill a shadow check would block.
 * A check is promoted by deleting its name from this set, which is only allowed once that list
 * is empty; after promotion the PR gate fails on any new real-world block. See docs/accuracy-gates.md.
 */
export const SHADOW_CHECKS: ReadonlySet<string> = new Set<string>([
  // 2026-11-06 four-idea checks (unlisted-payee, unlisted-other-field,
  // memory-api-key-identity, third-party-principal, prose-stub-mismatch)
  // were promoted after the enforce scan would block 0 and would review 0
  // real-world skills. See docs/experiments/batch-2026-11-06-four/RESULTS.md.
]);

export function shadowEnforced(): boolean {
  return process.env.IRONHEIGHTS_SHADOW === 'enforce';
}

export function applyShadow(
  finding: Finding,
  checks: ReadonlySet<string> = SHADOW_CHECKS,
): Finding {
  const check = finding.shadowCheck;
  if (check === undefined || !checks.has(check) || shadowEnforced()) return finding;
  if (finding.severity === 'info') return finding;
  const note = `Shadow check ${check}: would be ${finding.severity} once promoted. Log only; it does not change the verdict.`;
  return {
    ...finding,
    severity: 'info',
    wouldSeverity: finding.severity,
    note: finding.note ? `${finding.note} ${note}` : note,
  };
}
