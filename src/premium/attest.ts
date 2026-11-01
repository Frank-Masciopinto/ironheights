/**
 * "Verified by Ironheights" attestations (0.26.0, open and opt-in).
 *
 * `ironheights attest <skill>` scans a local skill, then signs a statement binding the
 * skill's content digest, the verdict, the tool version and the rule-set hash, using the
 * local ed25519 key. Only a `no-findings` verdict is marked verified; any other verdict is
 * still attested, honestly, as not verified. The badge SVG is static, so a registry or
 * README can serve it next to the JSON.
 */
import { createPublicKey, sign, verify } from 'node:crypto';
import { contentDigest, rulesetHash } from '../mcp/receipts.ts';
import type { WatchKey } from '../runtime/activity.ts';
import { TOOL_NAME, TOOL_VERSION } from '../version.ts';

export const ATTESTATION_TYPE = 'https://www.ironheights.dev/attestation/v1';

export interface AttestationStatement {
  type: typeof ATTESTATION_TYPE;
  subject: { name: string; contentDigest: string; files: number };
  verdict: string;
  verified: boolean;
  findings: number;
  tool: string;
  version: string;
  rulesetHash: string;
  issuedAt: string;
  expiresAt: string;
  keyId: string;
  /** Where the bytes came from (0.26.0): set for a ClawHub ref, absent for a local folder. */
  source?: AttestationSource;
  /** ClawHub owner handle, used by publisher reputation. Null for a local folder. */
  publisher?: string | null;
}

export interface AttestationSource {
  registry: 'clawhub';
  ref: string;
  owner: string;
  slug: string;
  version: string;
}

export interface Attestation {
  statement: AttestationStatement;
  publicKey: string;
  signature: string;
}

/** Stable JSON: keys sorted at every level, so field order never changes the signed bytes. */
export function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
  if (v && typeof v === 'object')
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`)
      .join(',')}}`;
  return JSON.stringify(v);
}
const canon = (s: AttestationStatement): string => stable(s);

export async function buildAttestation(input: {
  dir: string;
  name: string;
  verdict: string;
  findings: number;
  key: WatchKey;
  now?: Date;
  validDays?: number;
  source?: AttestationSource;
}): Promise<Attestation> {
  const { digest, files } = await contentDigest(input.dir);
  if (!digest) throw new Error(`no files to attest in ${input.dir}`);
  const now = input.now ?? new Date();
  const statement: AttestationStatement = {
    type: ATTESTATION_TYPE,
    subject: { name: input.name, contentDigest: digest, files: Object.keys(files).length },
    verdict: input.verdict,
    verified: input.verdict === 'no-findings',
    findings: input.findings,
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    rulesetHash: rulesetHash(),
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + (input.validDays ?? 30) * 86_400_000).toISOString(),
    keyId: input.key.keyId,
    ...(input.source
      ? { source: input.source, publisher: input.source.owner }
      : { publisher: null }),
  };
  return {
    statement,
    publicKey: input.key.publicPem,
    signature: sign(null, Buffer.from(canon(statement)), input.key.privateKey).toString('base64'),
  };
}

export interface AttestationCheck {
  ok: boolean;
  verified: boolean;
  reason: string;
}

/**
 * Check the signature, the expiry, an optional trusted public key and, when a folder is
 * given, that the files on disk still match the attested digest.
 */
export async function verifyAttestation(
  a: Attestation,
  opts: { dir?: string; trustedPublicKey?: string; now?: Date } = {},
): Promise<AttestationCheck> {
  const fail = (reason: string): AttestationCheck => ({ ok: false, verified: false, reason });
  if (a?.statement?.type !== ATTESTATION_TYPE) return fail('not an Ironheights attestation');
  const pem = opts.trustedPublicKey ?? a.publicKey;
  if (opts.trustedPublicKey && normalize(opts.trustedPublicKey) !== normalize(a.publicKey))
    return fail('signed by a different key than the trusted one');
  let good = false;
  try {
    good = verify(
      null,
      Buffer.from(canon(a.statement)),
      createPublicKey(pem),
      Buffer.from(a.signature, 'base64'),
    );
  } catch {
    good = false;
  }
  if (!good) return fail('bad signature');
  if (Date.parse(a.statement.expiresAt) <= (opts.now ?? new Date()).getTime())
    return fail(`expired at ${a.statement.expiresAt}`);
  if (opts.dir) {
    const now = await contentDigest(opts.dir).catch(() => ({ digest: null }));
    if (now.digest !== a.statement.subject.contentDigest)
      return fail('the files changed since this attestation');
  }
  return a.statement.verified
    ? {
        ok: true,
        verified: true,
        reason: opts.trustedPublicKey
          ? 'verified by a trusted key'
          : 'signature good (self-signed key; pass --public-key to pin a trusted one)',
      }
    : {
        ok: true,
        verified: false,
        reason: `signature good; verdict ${a.statement.verdict}, not verified`,
      };
}

const normalize = (p: string) => p.replace(/\s+/g, '');

const esc = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string,
  );

/** Shields-style static badge. */
export function badgeSvg(a: Pick<AttestationStatement, 'verified' | 'verdict'>): string {
  const label = 'Ironheights';
  const value = a.verified ? 'verified' : a.verdict;
  const color = a.verified ? '#2ea44f' : a.verdict === 'review' ? '#dfb317' : '#e05d44';
  const lw = 6 * label.length + 14;
  const vw = 6 * value.length + 14;
  const w = lw + vw;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(label)}: ${esc(value)}"><title>${esc(label)}: ${esc(value)}</title><rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${vw}" height="20" fill="${color}"/><g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11"><text x="${lw / 2}" y="14">${esc(label)}</text><text x="${lw + vw / 2}" y="14">${esc(value)}</text></g></svg>\n`;
}
