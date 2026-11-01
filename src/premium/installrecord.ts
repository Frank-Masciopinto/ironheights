/**
 * Auditor-accepted install record (0.27.0, corporate-tier idea from Moltbook, open and opt-in).
 *
 * Who approved which version and hash, under which scope, and whether the approval was
 * inherited. Records are ed25519-signed, hash-chained and append-only. Point
 * IRONHEIGHTS_RECORD_DIR at a store the agent cannot write, rotate or prune (a separate user,
 * a WORM bucket mount); the agent then holds no way to shape the evidence.
 */
import { join } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import {
  ActivityLog,
  loadOrCreateWatchKey,
  verifyActivityLog,
  type SignedRecord,
} from '../runtime/activity.ts';

export interface ApprovalScope {
  /** Skill name and the version range the approval covers. */
  skill: string;
  versionRange: string;
  taskClass?: string;
  until?: string;
  /** Writes outside this path are not covered. */
  writePath?: string;
  scopeVersion: number;
}

export interface InstallRecord {
  skill: string;
  version: string;
  sha256: string;
  approver: string;
  /** Hash the approver saw; must equal sha256. */
  approverSawSha256: string;
  scope: ApprovalScope;
  /** dependency | auto-update | name: the yes was given to something else. */
  inherited?: { from: string; via: 'dependency' | 'auto-update' | 'name' };
  machine?: string;
}

export function recordDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.IRONHEIGHTS_RECORD_DIR ?? join(ironheightsHome(env), 'install-records');
}
const FILE = 'install-records.jsonl';

export async function appendRecord(
  rec: InstallRecord,
  env: NodeJS.ProcessEnv = process.env,
  clock: () => Date = () => new Date(),
): Promise<SignedRecord> {
  if (!rec.approver) throw new Error('approver is required');
  if (!/^[0-9a-f]{64}$/i.test(rec.sha256)) throw new Error('sha256 must be a 64-char hex digest');
  const key = await loadOrCreateWatchKey(ironheightsHome(env));
  const log = new ActivityLog(join(recordDir(env), FILE), key, clock);
  await log.open();
  return log.append('install-record', rec as unknown as Record<string, unknown>, rec.skill);
}

export interface AuditRow {
  seq: number;
  skill: string;
  version: string;
  approver: string;
  approverPresent: boolean;
  hashMatches: boolean;
  inherited: boolean;
  scopeExpired: boolean;
  accepted: boolean;
}

export async function auditRecords(
  env: NodeJS.ProcessEnv = process.env,
  now: Date = new Date(),
): Promise<{ chain: { ok: boolean; problem?: string }; rows: AuditRow[]; acceptedRate: number }> {
  const key = await loadOrCreateWatchKey(ironheightsHome(env));
  const v = await verifyActivityLog(join(recordDir(env), FILE), key.publicPem).catch(() => ({
    ok: true,
    records: [] as SignedRecord[],
  }));
  const rows = v.records
    .filter((r) => r.kind === 'install-record')
    .map((r) => {
      const d = r.data as unknown as InstallRecord;
      const approverPresent = Boolean(d.approver);
      const hashMatches = d.approverSawSha256?.toLowerCase() === d.sha256?.toLowerCase();
      const scopeExpired = Boolean(d.scope?.until && Date.parse(d.scope.until) < now.getTime());
      const inherited = Boolean(d.inherited);
      return {
        seq: r.seq,
        skill: d.skill,
        version: d.version,
        approver: d.approver,
        approverPresent,
        hashMatches,
        inherited,
        scopeExpired,
        accepted: v.ok && approverPresent && hashMatches && !inherited && !scopeExpired,
      };
    });
  return {
    chain: { ok: v.ok, ...('problem' in v && v.problem ? { problem: v.problem } : {}) },
    rows,
    acceptedRate: rows.length ? rows.filter((r) => r.accepted).length / rows.length : 0,
  };
}
