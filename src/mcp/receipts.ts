/**
 * Server-written check receipts for the MCP server (0.23.0).
 *
 * Every check_skill call, including one that failed, is recorded by the server in an
 * append-only JSONL file the agent does not write. A receipt is keyed by a check id that
 * binds the tool version, the rule-set hash, the content digest of the files read and the
 * time of the check. verify_check recomputes the digest and rule-set hash, so a verdict
 * repeated later without its provenance, or about files that changed or are gone, is not
 * confirmed. Suggested by Moltbook bots (credits in CHANGELOG 0.23.0).
 */
import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import { snapshotSkill } from '../drift/drift.ts';
import { allRules } from '../rules/index.ts';
import { TOOL_NAME, TOOL_VERSION } from '../version.ts';

export type Decision = 'allow' | 'blocked_pending_approval' | 'blocked';
export type CheckState = 'checked' | 'checker-unavailable';

export interface Provenance {
  tool: string;
  version: string;
  rulesetHash: string;
  checkedAt: string;
  /** sha256 over the sorted (path, file sha256) list of the files read. Null when nothing was read. */
  contentDigest: string | null;
  files: number;
  /** Who produced the scanned bytes, when known (ClawHub owner/slug@version). */
  subjectProducer: string | null;
}

export interface MatchedLine {
  rule: string;
  file: string;
  line: number;
  /** sha256 of the exact file that matched, so the receipt stays checkable after an update. */
  fileSha256: string | null;
}

export interface Receipt {
  checkId: string;
  state: CheckState;
  decision: Decision;
  verdict: string;
  target: string;
  /** Local folder the digest was computed over; absent for remote refs (temp folder removed). */
  localPath?: string;
  provenance: Provenance;
  matched: MatchedLine[];
  reason?: string;
  /** What would change the decision. */
  wouldChange: string;
}

let cachedRuleset: string | undefined;

export function rulesetHash(): string {
  if (!cachedRuleset) {
    const rules = allRules()
      .map((r) => `${r.id}|${r.severity}|${r.title}`)
      .sort();
    cachedRuleset = createHash('sha256')
      .update(`${TOOL_VERSION}\n${rules.join('\n')}`)
      .digest('hex');
  }
  return cachedRuleset;
}

export async function contentDigest(
  dir: string,
): Promise<{ digest: string | null; files: Record<string, string> }> {
  const snap = await snapshotSkill(dir);
  const entries = Object.entries(snap.files).sort(([a], [b]) => a.localeCompare(b));
  if (!entries.length) return { digest: null, files: {} };
  const h = createHash('sha256');
  for (const [path, sha] of entries) h.update(`${path}\0${sha}\n`);
  return { digest: h.digest('hex'), files: snap.files };
}

export function decisionFor(verdict: string): Decision {
  if (verdict === 'no-findings') return 'allow';
  if (verdict === 'block') return 'blocked';
  return 'blocked_pending_approval';
}

export function checkIdFor(p: Provenance, target: string, decision: Decision): string {
  const h = createHash('sha256')
    .update(
      [
        p.tool,
        p.version,
        p.rulesetHash,
        p.contentDigest ?? 'none',
        p.checkedAt,
        target,
        decision,
      ].join('\n'),
    )
    .digest('hex');
  return `ihc_${h.slice(0, 40)}`;
}

export function receiptsPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(ironheightsHome(env), 'mcp-receipts.jsonl');
}

export async function writeReceipt(path: string, receipt: Receipt): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, JSON.stringify(receipt) + '\n');
}

export async function findReceipt(path: string, checkId: string): Promise<Receipt | undefined> {
  let raw = '';
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    return undefined;
  }
  let found: Receipt | undefined;
  for (const line of raw.split('\n')) {
    if (!line.includes(checkId)) continue;
    try {
      const r = JSON.parse(line) as Receipt;
      if (r.checkId === checkId) found = r;
    } catch {
      /* skip a bad line */
    }
  }
  return found;
}

export function provenance(
  checkedAt: string,
  digest: string | null,
  files: number,
  subjectProducer: string | null,
): Provenance {
  return {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    rulesetHash: rulesetHash(),
    checkedAt,
    contentDigest: digest,
    files,
    subjectProducer,
  };
}

export type VerifyStatus = 'live' | 'stale' | 'absent' | 'unverifiable';

export interface VerifyResult {
  checkId: string;
  status: VerifyStatus;
  /** Only `live` carries the original decision; every other status is blocked. */
  decision: Decision;
  reason: string;
  receipt?: Receipt;
}

/** Re-check a receipt against the files on disk now and the rule set loaded now. */
export async function verifyReceipt(
  receipt: Receipt | undefined,
  checkId: string,
  pathNow?: string,
): Promise<VerifyResult> {
  if (!receipt)
    return {
      checkId,
      status: 'absent',
      decision: 'blocked',
      reason:
        'no receipt with this check id was written by this server; a verdict without a receipt is treated as absent',
    };
  const blocked = (status: VerifyStatus, reason: string): VerifyResult => ({
    checkId,
    status,
    decision: 'blocked',
    reason,
    receipt,
  });
  if (receipt.state !== 'checked') return blocked('stale', 'the original check did not complete');
  if (
    receipt.provenance.rulesetHash !== rulesetHash() ||
    receipt.provenance.version !== TOOL_VERSION
  )
    return blocked(
      'stale',
      'checked with a different Ironheights version or rule set; check again',
    );
  const dir = pathNow ?? receipt.localPath;
  if (!dir)
    return blocked(
      'unverifiable',
      'remote skill: the scanned bytes are not on disk to re-hash; run check_skill again',
    );
  const now = await contentDigest(dir).catch(() => ({ digest: null, files: {} }));
  if (!now.digest) return blocked('absent', `the checked files are gone: ${dir}`);
  if (now.digest !== receipt.provenance.contentDigest)
    return blocked('stale', 'the files changed since this check; check again');
  return {
    checkId,
    status: 'live',
    decision: receipt.decision,
    reason: 'same files, same rule set, same version as the receipt',
    receipt,
  };
}
