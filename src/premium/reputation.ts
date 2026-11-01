/**
 * Publisher reputation (0.26.0, Publisher / Registry track, open and opt-in).
 *
 * Computed only from attestations this machine made and retained (`ironheights attest
 * owner/slug@version`), after the retention store verifies. Nothing is fetched, estimated or
 * filled in. See docs/publisher.md for the methodology; the same text ships in the output.
 */
import { sign } from 'node:crypto';
import type { SignedRecord, WatchKey } from '../runtime/activity.ts';
import { TOOL_VERSION } from '../version.ts';
import { stable } from './attest.ts';

export const METHODOLOGY_VERSION = 'ironheights-reputation/1';
export const METHODOLOGY = [
  'Inputs: attestation records in the local signed retention store that carry a ClawHub publisher; local-folder attestations are ignored.',
  'Per publisher, each skill (slug) counts once, using its most recent attestation.',
  'Counts: verified (no-findings), review, block, incomplete, from those latest attestations; everBlocked counts slugs with any block attestation in history.',
  'Tier: insufficient-data when fewer than minSkills skills; flagged when any latest verdict is block; mixed when any latest verdict is review or incomplete, or any slug was ever blocked; clean when every latest verdict is verified.',
  'No numeric score, no weighting, no outside data. Reputation reflects only what this machine attested, with this Ironheights rule set.',
].join(' ');

export type Tier = 'insufficient-data' | 'flagged' | 'mixed' | 'clean';

export interface PublisherReputation {
  publisher: string;
  tier: Tier;
  skills: number;
  attestations: number;
  verified: number;
  review: number;
  blocked: number;
  incomplete: number;
  everBlocked: number;
  firstAttestedAt: string;
  lastAttestedAt: string;
  latest: Array<{ slug: string; version: string; verdict: string; at: string; recordSeq: number }>;
}

export interface ReputationReport {
  format: typeof METHODOLOGY_VERSION;
  generatedAt: string;
  version: string;
  methodology: string;
  minSkills: number;
  inputRecords: number;
  publishers: PublisherReputation[];
}

interface AttRecord {
  publisher?: string | null;
  verdict?: string;
  issuedAt?: string;
  source?: { slug?: string; version?: string };
}

export function computeReputation(
  records: SignedRecord[],
  opts: { publisher?: string; minSkills?: number; now: Date },
): ReputationReport {
  const minSkills = opts.minSkills ?? 3;
  const by = new Map<string, Array<{ d: AttRecord; slug: string; at: string; seq: number }>>();
  let inputRecords = 0;
  for (const r of records) {
    if (r.kind !== 'attestation') continue;
    const d = r.data as AttRecord;
    if (!d.publisher || !d.source?.slug || !d.verdict) continue;
    if (opts.publisher && d.publisher !== opts.publisher) continue;
    inputRecords += 1;
    const list = by.get(d.publisher) ?? [];
    list.push({ d, slug: d.source.slug, at: d.issuedAt ?? r.at, seq: r.seq });
    by.set(d.publisher, list);
  }
  const publishers: PublisherReputation[] = [];
  for (const [publisher, list] of by) {
    list.sort((a, b) => a.at.localeCompare(b.at) || a.seq - b.seq);
    const latestBySlug = new Map<string, (typeof list)[number]>();
    const everBlocked = new Set<string>();
    for (const e of list) {
      latestBySlug.set(e.slug, e);
      if (e.d.verdict === 'block') everBlocked.add(e.slug);
    }
    const latest = [...latestBySlug.entries()]
      .map(([slug, e]) => ({
        slug,
        version: e.d.source?.version ?? '',
        verdict: e.d.verdict as string,
        at: e.at,
        recordSeq: e.seq,
      }))
      .sort((a, b) => a.slug.localeCompare(b.slug));
    const n = (v: string) => latest.filter((l) => l.verdict === v).length;
    const verified = n('no-findings');
    const review = n('review');
    const blocked = n('block');
    const incomplete = n('incomplete');
    const tier: Tier =
      latest.length < minSkills
        ? 'insufficient-data'
        : blocked > 0
          ? 'flagged'
          : review > 0 || incomplete > 0 || everBlocked.size > 0
            ? 'mixed'
            : 'clean';
    const first = list[0];
    const last = list[list.length - 1];
    if (!first || !last) continue;
    publishers.push({
      publisher,
      tier,
      skills: latest.length,
      attestations: list.length,
      verified,
      review,
      blocked,
      incomplete,
      everBlocked: everBlocked.size,
      firstAttestedAt: first.at,
      lastAttestedAt: last.at,
      latest,
    });
  }
  publishers.sort((a, b) => a.publisher.localeCompare(b.publisher));
  return {
    format: METHODOLOGY_VERSION,
    generatedAt: opts.now.toISOString(),
    version: TOOL_VERSION,
    methodology: METHODOLOGY,
    minSkills,
    inputRecords,
    publishers,
  };
}

export function signReputation(rep: ReputationReport, key: WatchKey) {
  return {
    reputation: rep,
    keyId: key.keyId,
    publicKey: key.publicPem,
    signature: sign(null, Buffer.from(stable(rep)), key.privateKey).toString('base64'),
  };
}
