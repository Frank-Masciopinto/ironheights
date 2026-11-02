/**
 * Per-run receipts written by the loader (0.28.0, corporate-tier idea from Moltbook, open and opt-in).
 *
 * One line per running copy: which skill bytes loaded, where, who triggered the run and which
 * named approver approved that exact hash. The loader writes it, not the job, so a job cannot
 * report itself clean. ed25519-signed, hash-chained, append-only; IRONHEIGHTS_RECEIPT_DIR can
 * point at a store the agent cannot write.
 */
import { join } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import {
  ActivityLog,
  loadOrCreateWatchKey,
  verifyActivityLog,
  type SignedRecord,
} from '../runtime/activity.ts';

export interface RunReceipt {
  runId: string;
  copyId: string;
  machine: string;
  skill: string;
  loadedSha256: string;
  writer: 'loader';
  trigger: string;
  approver?: string;
  approvedSha256?: string;
  loadedAt: string;
}

export function receiptDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.IRONHEIGHTS_RECEIPT_DIR ?? join(ironheightsHome(env), 'run-receipts');
}
const FILE = 'run-receipts.jsonl';

export async function writeRunReceipt(
  r: RunReceipt,
  env: NodeJS.ProcessEnv = process.env,
  clock: () => Date = () => new Date(),
): Promise<SignedRecord> {
  if (r.writer !== 'loader') throw new Error('receipts are written by the loader, not the job');
  if (!/^[0-9a-f]{64}$/i.test(r.loadedSha256)) throw new Error('loadedSha256 must be 64-char hex');
  if (!r.trigger) throw new Error('trigger (who or what started the run) is required');
  if (!r.copyId) throw new Error('copyId is required: one receipt per running copy');
  const key = await loadOrCreateWatchKey(ironheightsHome(env));
  const log = new ActivityLog(join(receiptDir(env), FILE), key, clock);
  await log.open();
  return log.append('run-receipt', r as unknown as Record<string, unknown>, r.skill);
}

export async function auditRunReceipts(env: NodeJS.ProcessEnv = process.env) {
  const key = await loadOrCreateWatchKey(ironheightsHome(env));
  const v = await verifyActivityLog(join(receiptDir(env), FILE), key.publicPem).catch(() => ({
    ok: true,
    records: [] as SignedRecord[],
  }));
  const rows = v.records
    .filter((x) => x.kind === 'run-receipt')
    .map((x) => {
      const d = x.data as unknown as RunReceipt;
      const approved =
        Boolean(d.approver) && d.approvedSha256?.toLowerCase() === d.loadedSha256.toLowerCase();
      return { seq: x.seq, ...d, approved };
    });
  return {
    chain: { ok: v.ok, ...('problem' in v && v.problem ? { problem: v.problem } : {}) },
    rows,
    copies: new Set(rows.map((r) => `${r.machine}/${r.copyId}`)).size,
    unapproved: rows.filter((r) => !r.approved).length,
  };
}
