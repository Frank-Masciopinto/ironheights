/**
 * A no-findings result names the scanner and the time. It is not a claim of safety.
 * Suggested by myinvestdesk, vintos and diviner (0.34.0).
 */
import { parseMaxAge } from '../threatmodel/pins.ts';
import { SAFETY_REMINDER, TOOL_VERSION } from '../version.ts';

export function notFlaggedWording(version: string, checkedAt: string): string {
  return `not flagged by ironheights ${version}, as of ${checkedAt}. ${SAFETY_REMINDER}`;
}

/** `review` is a request to inspect. It is not a malicious verdict. */
export const REVIEW_MEANS = 'review means inspect this; not a malicious verdict.';

/** A clean result means no known pattern was found. It is not proof of safety. */
export const CLEAN_MEANS = 'Clean means no known pattern found; not proof of safety.';

export function verdictWording(): string {
  return `${REVIEW_MEANS} ${CLEAN_MEANS}`;
}

/** Negative when `stored` is older than `running`. Non-numeric suffixes compare as 0. */
export function compareVersions(stored: string, running: string): number {
  const a = stored.split('.').map((part) => Number.parseInt(part, 10));
  const b = running.split('.').map((part) => Number.parseInt(part, 10));
  const width = Math.max(a.length, b.length, 3);
  for (let i = 0; i < width; i += 1) {
    const av = Number.isFinite(a[i]) ? (a[i] as number) : 0;
    const bv = Number.isFinite(b[i]) ? (b[i] as number) : 0;
    if (av !== bv) return av - bv;
  }
  return 0;
}

export function versionIsOlder(
  stored: string | undefined,
  running: string = TOOL_VERSION,
): boolean {
  if (!stored) return false;
  return compareVersions(stored, running) < 0;
}

export interface VerdictFreshness {
  stale: boolean;
  reasons: string[];
  rescan?: string;
}

const RESCAN = 'Rescan before relying on this pass.';

/**
 * A stored pass is stale when the scanner that made it is older than the one
 * running now, or when its validUntil has passed. A missing version is not
 * treated as older. Suggested by diviner: an older scanner is detection debt.
 */
export function verdictFreshness(input: {
  scannerVersion?: string | null;
  validUntil?: string | null;
  now?: Date;
  running?: string;
}): VerdictFreshness {
  const running = input.running ?? TOOL_VERSION;
  const now = input.now ?? new Date();
  const reasons: string[] = [];
  if (input.scannerVersion && versionIsOlder(input.scannerVersion, running)) {
    reasons.push(
      `scanner ${input.scannerVersion} is older than ${running}; a pass from an older scanner is detection debt`,
    );
  }
  if (input.validUntil) {
    const until = Date.parse(input.validUntil);
    if (Number.isFinite(until) && until < now.getTime()) {
      reasons.push(`validUntil ${input.validUntil} has passed`);
    }
  }
  if (reasons.length === 0) return { stale: false, reasons: [] };
  return { stale: true, reasons, rescan: RESCAN };
}

/** `--max-age` / MCP `maxAge`. `30d`, `12h`, `15m`, `30s`. Undefined means unset. */
export function maxAgeWindow(value: string | undefined): number | null | undefined {
  if (value === undefined || value.trim() === '') return undefined;
  return parseMaxAge(value);
}

export function validUntilFrom(checkedAt: string, windowMs: number): string {
  return new Date(Date.parse(checkedAt) + windowMs).toISOString();
}
