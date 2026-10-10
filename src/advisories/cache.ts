import { readFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { writeAtomic } from '../util/atomic.ts';
import { verifyAdvisorySignature } from './crypto.ts';
import { ADVISORY_JSON_MAX_BYTES, ADVISORY_SIG_MAX_BYTES } from './endpoints.ts';
import { parseAdvisoryDocument, type AdvisoryDocument } from './schema.ts';

export interface AdvisoryCachePaths {
  jsonPath: string;
  sigPath: string;
}

export type AdvisoryCacheRead =
  | { status: 'missing' }
  | { status: 'ok'; document: AdvisoryDocument; bytes: Uint8Array }
  | { status: 'rejected'; message: string };

export function advisoryCachePaths(home: string): AdvisoryCachePaths {
  return {
    jsonPath: join(home, 'advisories.json'),
    sigPath: join(home, 'advisories.json.sig'),
  };
}

/**
 * Read the local cache. A missing cache is normal (offline, feed not fetched).
 * A present cache with a bad signature, an unconfigured key, or a bad schema
 * is rejected. Callers must not use rejected bytes.
 */
export async function readAdvisoryCache(
  home: string,
  publicKey: Uint8Array | null,
): Promise<AdvisoryCacheRead> {
  const paths = advisoryCachePaths(home);
  const jsonRaw = await readOptional(paths.jsonPath, ADVISORY_JSON_MAX_BYTES);
  const sigRaw = await readOptional(paths.sigPath, ADVISORY_SIG_MAX_BYTES);
  if (jsonRaw.status === 'rejected') return { status: 'rejected', message: jsonRaw.message };
  if (sigRaw.status === 'rejected') return { status: 'rejected', message: sigRaw.message };
  if (jsonRaw.status === 'missing' && sigRaw.status === 'missing') return { status: 'missing' };
  if (jsonRaw.status === 'missing' || sigRaw.status === 'missing') {
    return { status: 'rejected', message: 'Advisory cache is incomplete. Refusing to use it.' };
  }
  if (!publicKey) {
    return {
      status: 'rejected',
      message:
        'The production advisory public key is not configured (src/advisories/pinned-key.ts). Refusing to trust the cached feed.',
    };
  }
  const bytes = new Uint8Array(jsonRaw.bytes);
  const sig = sigRaw.text;
  if (!verifyAdvisorySignature(bytes, sig, publicKey)) {
    return {
      status: 'rejected',
      message: 'Advisory cache signature is invalid. Refusing to use the cached feed.',
    };
  }
  try {
    const document = parseAdvisoryDocument(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return { status: 'ok', document, bytes };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'advisory feed was rejected';
    return { status: 'rejected', message };
  }
}

/** Write both files only after the caller has verified the signature. */
export async function writeAdvisoryCache(
  home: string,
  jsonText: string,
  signatureText: string,
): Promise<AdvisoryCachePaths> {
  const paths = advisoryCachePaths(home);
  const jsonNew = `${paths.jsonPath}.new`;
  const sigNew = `${paths.sigPath}.new`;
  await writeAtomic(jsonNew, jsonText, 0o644);
  await writeAtomic(
    sigNew,
    signatureText.endsWith('\n') ? signatureText : `${signatureText}\n`,
    0o644,
  );
  await rename(sigNew, paths.sigPath);
  await rename(jsonNew, paths.jsonPath);
  return paths;
}

export async function removePartialAdvisoryWrite(home: string): Promise<void> {
  const paths = advisoryCachePaths(home);
  await rm(`${paths.jsonPath}.new`, { force: true });
  await rm(`${paths.sigPath}.new`, { force: true });
}

async function readOptional(
  filePath: string,
  maxBytes: number,
): Promise<
  | { status: 'missing' }
  | { status: 'rejected'; message: string }
  | { status: 'ok'; bytes: Buffer; text: string }
> {
  try {
    const bytes = await readFile(filePath);
    if (bytes.byteLength > maxBytes) {
      return { status: 'rejected', message: `advisory cache file exceeds ${maxBytes} bytes` };
    }
    return { status: 'ok', bytes, text: bytes.toString('utf8') };
  } catch (error) {
    if (isEnoent(error)) return { status: 'missing' };
    const message = error instanceof Error ? error.message : 'cannot read advisory cache';
    return { status: 'rejected', message };
  }
}

function isEnoent(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
