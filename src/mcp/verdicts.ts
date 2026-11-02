/**
 * Verdict typing for check_skill callers (0.28.0, ideas from Moltbook bots).
 *
 * - A check made after the skill loaded never returns a plain pass: it has its own verdict type.
 * - Lookups are by content hash plus a verified publisher; a bare name is refused.
 * - Any verdict type a gate does not recognise fails closed.
 * - A reach report is bound to the launching session and expires when the session changes.
 */
import { createHash } from 'node:crypto';

export const PRE_LOAD_VERDICTS = ['allow', 'block', 'unanswered', 'refused'] as const;
export const POST_LOAD_VERDICTS = ['post-load-unchanged', 'post-load-drifted'] as const;
export type Verdict = (typeof PRE_LOAD_VERDICTS)[number] | (typeof POST_LOAD_VERDICTS)[number];

export interface TimedVerdict {
  verdict: Verdict;
  checkedAt: string;
  loadedAt?: string;
  note?: string;
}

/**
 * Type a verdict by when it was made. If the check ran after load, "allow" becomes
 * post-load-unchanged (same hash as loaded) or post-load-drifted; never allow.
 */
export function typeVerdict(i: {
  decision: 'allow' | 'block' | 'unanswered' | 'refused';
  checkedAt: string;
  loadedAt?: string;
  loadedSha256?: string;
  checkedSha256?: string;
}): TimedVerdict {
  const late = i.loadedAt !== undefined && Date.parse(i.loadedAt) <= Date.parse(i.checkedAt);
  if (!late || i.decision === 'block' || i.decision === 'refused')
    return {
      verdict: i.decision,
      checkedAt: i.checkedAt,
      ...(i.loadedAt ? { loadedAt: i.loadedAt } : {}),
    };
  const same =
    Boolean(i.loadedSha256) && i.loadedSha256?.toLowerCase() === i.checkedSha256?.toLowerCase();
  return {
    verdict: same ? 'post-load-unchanged' : 'post-load-drifted',
    checkedAt: i.checkedAt,
    loadedAt: i.loadedAt as string,
    note: 'checked after load: the skill already ran between load and check, so this is not a gate pass',
  };
}

/** Gate: only a recognised pre-load allow proceeds. Unknown, post-load or missing = deny. */
export function gate(v: unknown): { proceed: boolean; reason: string } {
  const verdict =
    v && typeof v === 'object' && 'verdict' in v ? (v as { verdict: unknown }).verdict : v;
  if (verdict === 'allow') return { proceed: true, reason: 'pre-load allow' };
  if (typeof verdict === 'string' && (POST_LOAD_VERDICTS as readonly string[]).includes(verdict))
    return { proceed: false, reason: `${verdict}: a post-load verdict never gates a load` };
  if (typeof verdict === 'string' && (PRE_LOAD_VERDICTS as readonly string[]).includes(verdict))
    return { proceed: false, reason: verdict };
  return { proceed: false, reason: `unknown verdict type ${JSON.stringify(verdict)}: fail closed` };
}

export interface VerdictKey {
  name?: string;
  publisher?: string;
  publisherVerified?: boolean;
  sha256?: string;
}
export interface StoredVerdict extends Required<Pick<VerdictKey, 'publisher' | 'sha256'>> {
  name: string;
  verdict: TimedVerdict;
}

/** Look up by content hash plus verified publisher; a bare name, or an unverified publisher, is refused. */
export function lookupVerdict(
  store: StoredVerdict[],
  key: VerdictKey,
):
  | { status: 'found'; verdict: StoredVerdict }
  | { status: 'refused' | 'no-verdict'; reason: string } {
  if (!key.sha256 || !/^[0-9a-f]{64}$/i.test(key.sha256))
    return {
      status: 'refused',
      reason: 'lookup needs the content hash of the copy on disk; a name alone verifies nothing',
    };
  if (!key.publisher || !key.publisherVerified)
    return {
      status: 'refused',
      reason: 'lookup needs a publisher identity verified by the registry, not a claimed one',
    };
  const hit = store.find(
    (s) => s.sha256.toLowerCase() === key.sha256?.toLowerCase() && s.publisher === key.publisher,
  );
  if (!hit) return { status: 'no-verdict', reason: 'no verdict for this hash and publisher' };
  if (key.name && hit.name !== key.name)
    return { status: 'refused', reason: `hash belongs to ${hit.name}, not ${key.name}` };
  return { status: 'found', verdict: hit };
}

/** Digest of the launching session: session id plus the sorted env-var names (never values). */
export function sessionDigest(sessionId: string, envNames: string[]): string {
  return createHash('sha256')
    .update(sessionId + '\n' + [...new Set(envNames)].sort().join('\n'))
    .digest('hex');
}

export function checkSessionBinding(
  boundDigest: string,
  sessionId: string,
  liveEnvNames: string[],
): { status: 'current' | 'expired'; liveDigest: string; action?: string } {
  const liveDigest = sessionDigest(sessionId, liveEnvNames);
  return liveDigest === boundDigest
    ? { status: 'current', liveDigest }
    : { status: 'expired', liveDigest, action: 're-run the reach check or fail closed' };
}
