/**
 * Signed, append-only activity log for `ironheights watch --activity` (0.25.0).
 *
 * Each line is a JSON record with a sequence number, the SHA-256 of the previous line and an
 * ed25519 signature over the record, made with a local key kept in IRONHEIGHTS_HOME. Removing,
 * reordering or editing a line breaks the chain; `verifyActivityLog` says where.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { appendFile, chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export type ActivityKind =
  | 'watch-start'
  | 'file'
  | 'net'
  | 'heartbeat'
  | 'observer-stale'
  | 'check-start'
  | 'check-end'
  | 'check-stall'
  | 'refusal'
  | 'action'
  | 'after-refusal'
  | 'receipt'
  | 'activity-ref'
  | 'attestation'
  | 'retention-prune'
  | 'alert'
  | 'install-record';

export interface ActivityRecord {
  seq: number;
  at: string;
  kind: ActivityKind;
  skill?: string;
  data: Record<string, unknown>;
  prev: string;
}
export interface SignedRecord extends ActivityRecord {
  sig: string;
}

export interface WatchKey {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicPem: string;
  keyId: string;
}

export async function loadOrCreateWatchKey(home: string): Promise<WatchKey> {
  const priv = join(home, 'watch-key.pem');
  const pub = join(home, 'watch-key.pub.pem');
  let pem: string;
  try {
    pem = await readFile(priv, 'utf8');
  } catch {
    const kp = generateKeyPairSync('ed25519');
    pem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    await mkdir(home, { recursive: true, mode: 0o700 });
    await writeFile(priv, pem, { mode: 0o600 });
    await chmod(priv, 0o600).catch(() => undefined);
    await writeFile(pub, kp.publicKey.export({ type: 'spki', format: 'pem' }).toString());
  }
  const privateKey = createPrivateKey(pem);
  const publicKey = createPublicKey(privateKey);
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return {
    privateKey,
    publicKey,
    publicPem,
    keyId: createHash('sha256').update(publicPem).digest('hex').slice(0, 16),
  };
}

const canon = (r: ActivityRecord): string =>
  JSON.stringify({
    seq: r.seq,
    at: r.at,
    kind: r.kind,
    skill: r.skill ?? null,
    data: r.data,
    prev: r.prev,
  });

export const GENESIS = '0'.repeat(64);

export class ActivityLog {
  private seq = 0;
  private prev = GENESIS;
  constructor(
    readonly file: string,
    private readonly key: WatchKey,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  /** Resume the chain from an existing file. */
  async open(): Promise<void> {
    await mkdir(dirname(this.file), { recursive: true });
    const text = await readFile(this.file, 'utf8').catch(() => '');
    const lines = text.split('\n').filter(Boolean);
    const last = lines[lines.length - 1];
    if (last) {
      const r = JSON.parse(last) as SignedRecord;
      this.seq = r.seq;
      this.prev = createHash('sha256').update(last).digest('hex');
    }
  }

  async append(
    kind: ActivityKind,
    data: Record<string, unknown>,
    skill?: string,
    at?: string,
  ): Promise<SignedRecord> {
    const rec: ActivityRecord = {
      seq: this.seq + 1,
      at: at ?? this.clock().toISOString(),
      kind,
      ...(skill ? { skill } : {}),
      data,
      prev: this.prev,
    };
    const sig = sign(null, Buffer.from(canon(rec)), this.key.privateKey).toString('base64');
    const line = JSON.stringify({ ...rec, sig });
    await appendFile(this.file, line + '\n', { mode: 0o600 });
    this.seq = rec.seq;
    this.prev = createHash('sha256').update(line).digest('hex');
    return { ...rec, sig };
  }
}

export interface LogVerification {
  ok: boolean;
  records: SignedRecord[];
  /** First problem, with the 1-based line number. */
  problem?: string;
}

export async function verifyActivityLog(file: string, publicPem: string): Promise<LogVerification> {
  const pub = createPublicKey(publicPem);
  const text = await readFile(file, 'utf8');
  const lines = text.split('\n').filter(Boolean);
  const records: SignedRecord[] = [];
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] as string;
    let r: SignedRecord;
    try {
      r = JSON.parse(line) as SignedRecord;
    } catch {
      return { ok: false, records, problem: `line ${i + 1}: not JSON` };
    }
    if (r.seq !== i + 1)
      return { ok: false, records, problem: `line ${i + 1}: sequence ${r.seq}, expected ${i + 1}` };
    if (r.prev !== prev)
      return {
        ok: false,
        records,
        problem: `line ${i + 1}: chain broken (a line was removed, reordered or edited)`,
      };
    if (!verify(null, Buffer.from(canon(r)), pub, Buffer.from(r.sig ?? '', 'base64')))
      return { ok: false, records, problem: `line ${i + 1}: bad signature` };
    records.push(r);
    prev = createHash('sha256').update(line).digest('hex');
  }
  return { ok: true, records };
}
