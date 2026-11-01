/**
 * Retained signed logs and receipts (0.26.0, first Pro feature, open and opt-in).
 *
 * A local retention store under IRONHEIGHTS_HOME/retained/. Records are kept in monthly
 * segments (receipts-YYYY-MM.jsonl). Each segment is a signed, hash-chained, append-only
 * log written with the same ed25519 key and format as `watch --activity`. Retention never
 * edits a segment: pruning deletes whole segments older than the retention window and
 * appends a signed `retention-prune` record (segment name, record count, last line hash) to
 * the current segment, so a deletion is always visible.
 */
import { createHash } from 'node:crypto';
import { readdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import { receiptsPath, type Receipt } from '../mcp/receipts.ts';
import {
  ActivityLog,
  loadOrCreateWatchKey,
  verifyActivityLog,
  type ActivityKind,
  type SignedRecord,
  type WatchKey,
} from '../runtime/activity.ts';

export const DEFAULT_RETENTION_DAYS = 365;
const SEGMENT = /^receipts-(\d{4})-(\d{2})\.jsonl$/;

export function retentionDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.IRONHEIGHTS_RETAINED_DIR ?? join(ironheightsHome(env), 'retained');
}

export function retentionDays(flag: number | undefined, env: NodeJS.ProcessEnv): number {
  const raw =
    flag ?? (env.IRONHEIGHTS_RETENTION_DAYS ? Number(env.IRONHEIGHTS_RETENTION_DAYS) : undefined);
  if (raw === undefined) return DEFAULT_RETENTION_DAYS;
  if (!Number.isFinite(raw) || raw < 1) throw new Error('retention days must be a number >= 1');
  return Math.floor(raw);
}

export const segmentName = (d: Date): string =>
  `receipts-${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}.jsonl`;

/** First instant after the segment's month ends. */
function segmentEnd(name: string): number {
  const m = SEGMENT.exec(name);
  if (!m) return Number.POSITIVE_INFINITY;
  return Date.UTC(Number(m[1]), Number(m[2]), 1);
}

export async function listSegments(dir: string): Promise<string[]> {
  const names = await readdir(dir).catch(() => [] as string[]);
  return names.filter((n) => SEGMENT.test(n)).sort();
}

export class RetentionStore {
  private constructor(
    readonly dir: string,
    readonly key: WatchKey,
    private readonly clock: () => Date,
  ) {}

  static async open(
    env: NodeJS.ProcessEnv = process.env,
    clock: () => Date = () => new Date(),
  ): Promise<RetentionStore> {
    const key = await loadOrCreateWatchKey(ironheightsHome(env));
    return new RetentionStore(retentionDir(env), key, clock);
  }

  async append(
    kind: ActivityKind,
    data: Record<string, unknown>,
    skill?: string,
  ): Promise<SignedRecord> {
    const now = this.clock();
    const log = new ActivityLog(join(this.dir, segmentName(now)), this.key, () => now);
    await log.open();
    return log.append(kind, data, skill);
  }

  async records(): Promise<Array<SignedRecord & { segment: string }>> {
    const out: Array<SignedRecord & { segment: string }> = [];
    for (const seg of await listSegments(this.dir)) {
      const text = await readFile(join(this.dir, seg), 'utf8');
      for (const line of text.split('\n').filter(Boolean)) {
        try {
          out.push({ ...(JSON.parse(line) as SignedRecord), segment: seg });
        } catch {
          /* verify reports bad lines */
        }
      }
    }
    return out;
  }

  /** Copy server-written check_skill receipts into the signed store (skips ones already kept). */
  async ingestReceipts(source: string): Promise<{ added: number; skipped: number }> {
    const raw = await readFile(source, 'utf8').catch(() => '');
    const seen = new Set(
      (await this.records())
        .filter((r) => r.kind === 'receipt')
        .map((r) => String((r.data as { checkId?: string }).checkId)),
    );
    let added = 0;
    let skipped = 0;
    for (const line of raw.split('\n').filter(Boolean)) {
      let r: Receipt;
      try {
        r = JSON.parse(line) as Receipt;
      } catch {
        skipped += 1;
        continue;
      }
      if (!r.checkId || seen.has(r.checkId)) {
        skipped += 1;
        continue;
      }
      seen.add(r.checkId);
      await this.append('receipt', { ...r, sourceLineSha256: sha(line) }, r.target);
      added += 1;
    }
    return { added, skipped };
  }

  /** Retain a reference to a verified watch --activity log: its head hash and record count. */
  async ingestActivityLog(file: string): Promise<SignedRecord> {
    const v = await verifyActivityLog(file, this.key.publicPem);
    if (!v.ok) throw new Error(`activity log did not verify: ${v.problem}`);
    const text = await readFile(file, 'utf8');
    const lines = text.split('\n').filter(Boolean);
    return this.append('activity-ref', {
      file,
      records: lines.length,
      headSha256: lines.length ? sha(lines[lines.length - 1] as string) : null,
      fileSha256: sha(text),
    });
  }

  async prune(days: number): Promise<string[]> {
    const cutoff = this.clock().getTime() - days * 86_400_000;
    const current = segmentName(this.clock());
    const removed: string[] = [];
    for (const seg of await listSegments(this.dir)) {
      if (seg === current || segmentEnd(seg) > cutoff) continue;
      const text = await readFile(join(this.dir, seg), 'utf8');
      const lines = text.split('\n').filter(Boolean);
      const v = await verifyActivityLog(join(this.dir, seg), this.key.publicPem);
      await this.append('retention-prune', {
        segment: seg,
        records: lines.length,
        verifiedBeforeDelete: v.ok,
        lastLineSha256: lines.length ? sha(lines[lines.length - 1] as string) : null,
        retentionDays: days,
      });
      await rm(join(this.dir, seg));
      removed.push(seg);
    }
    return removed;
  }

  async verify(): Promise<{ ok: boolean; segments: number; records: number; problems: string[] }> {
    const problems: string[] = [];
    let records = 0;
    const segs = await listSegments(this.dir);
    for (const seg of segs) {
      const v = await verifyActivityLog(join(this.dir, seg), this.key.publicPem);
      records += v.records.length;
      if (!v.ok) problems.push(`${seg}: ${v.problem}`);
    }
    return { ok: problems.length === 0, segments: segs.length, records, problems };
  }

  /** A self-contained bundle: public key plus the raw signed segments, verifiable offline. */
  async exportBundle(): Promise<RetentionBundle> {
    const segments: Record<string, string> = {};
    for (const seg of await listSegments(this.dir))
      segments[seg] = await readFile(join(this.dir, seg), 'utf8');
    return {
      format: 'ironheights-retained/1',
      exportedAt: this.clock().toISOString(),
      keyId: this.key.keyId,
      publicKey: this.key.publicPem,
      segments,
    };
  }
}

export interface RetentionBundle {
  format: 'ironheights-retained/1';
  exportedAt: string;
  keyId: string;
  publicKey: string;
  segments: Record<string, string>;
}

export function sha(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

export { receiptsPath };
