import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { UsageError } from '../core/errors.ts';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export type BaselineAlg = 'hmac-sha256' | 'ed25519';

export interface BaselineKey {
  alg: BaselineAlg;
  keyId: string;
  secret?: Uint8Array;
  seed?: Uint8Array;
  publicKey?: Uint8Array;
}

const KEY_HEADER = 'ironheights-baseline-key-v1';
const SIG_HEADER = 'ironheights-baseline-sig-v1';

export async function loadBaselineKey(
  filePath: string,
  purpose: 'sign' | 'verify',
): Promise<BaselineKey> {
  const info = await stat(filePath).catch(() => {
    throw new UsageError(`cannot read baseline key file: ${filePath}`);
  });
  // Node on Windows reports 0666 for a normal file. Unix mode bits are not ACLs.
  if (process.platform !== 'win32' && (info.mode & 0o077) !== 0) {
    throw new UsageError('baseline key file must not be readable by group or others');
  }
  const text = await readFile(filePath, 'utf8');
  const key = parseBaselineKey(text);
  if (purpose === 'sign') {
    if (key.alg === 'hmac-sha256' && !key.secret)
      throw new UsageError('baseline key is missing secret');
    if (key.alg === 'ed25519' && !key.seed) throw new UsageError('baseline key is missing seed');
  }
  if (purpose === 'verify' && key.alg === 'ed25519' && !key.publicKey) {
    throw new UsageError('baseline key is missing publicKey');
  }
  if (purpose === 'verify' && key.alg === 'hmac-sha256' && !key.secret) {
    throw new UsageError('baseline key is missing secret');
  }
  return key;
}

export function parseBaselineKey(text: string): BaselineKey {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
  if (lines[0] !== KEY_HEADER) throw new UsageError('baseline key file header is not recognized');
  const fields = readFields(lines.slice(1));
  const alg = fields.alg;
  if (alg !== 'hmac-sha256' && alg !== 'ed25519')
    throw new UsageError('baseline key alg must be hmac-sha256 or ed25519');
  if (alg === 'hmac-sha256') {
    const secret = decodeExact(fields.secret, 32, 'secret');
    return { alg, secret, keyId: keyIdFor(secret) };
  }
  const publicKey = fields.publicKey ? decodeExact(fields.publicKey, 32, 'publicKey') : undefined;
  const seed = fields.seed ? decodeExact(fields.seed, 32, 'seed') : undefined;
  const derived = seed ? publicRawFromSeed(seed) : undefined;
  if (publicKey && derived && !timingSafeEqual(Buffer.from(publicKey), Buffer.from(derived))) {
    throw new UsageError('baseline key publicKey does not match seed');
  }
  const rawPublic = publicKey ?? derived;
  if (!rawPublic) throw new UsageError('baseline key is missing publicKey');
  return { alg, keyId: keyIdFor(rawPublic), publicKey: rawPublic, ...(seed ? { seed } : {}) };
}

export function signBaselineBytes(body: string, key: BaselineKey): string {
  const signature =
    key.alg === 'hmac-sha256'
      ? hmac(body, required(key.secret, 'secret'))
      : edSign(body, required(key.seed, 'seed'));
  return `${SIG_HEADER}\nalg: ${key.alg}\nkeyId: ${key.keyId}\nsignature: ${Buffer.from(signature).toString('base64')}\n`;
}

export function verifyBaselineBytes(body: string, sigText: string, key: BaselineKey): boolean {
  const parsed = parseSignature(sigText);
  if (!parsed || parsed.alg !== key.alg || parsed.keyId !== key.keyId) return false;
  if (key.alg === 'hmac-sha256') {
    const expected = hmac(body, required(key.secret, 'secret'));
    return (
      expected.byteLength === parsed.signature.byteLength &&
      timingSafeEqual(Buffer.from(expected), Buffer.from(parsed.signature))
    );
  }
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(required(key.publicKey, 'publicKey'))]),
      format: 'der',
      type: 'spki',
    });
    return verify(null, Buffer.from(body), publicKey, Buffer.from(parsed.signature));
  } catch {
    return false;
  }
}

function parseSignature(
  text: string,
): { alg: BaselineAlg; keyId: string; signature: Uint8Array } | undefined {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (lines[0] !== SIG_HEADER) return undefined;
  let fields: Record<string, string>;
  try {
    fields = readFields(lines.slice(1));
  } catch {
    return undefined;
  }
  const alg = fields.alg;
  if (alg !== 'hmac-sha256' && alg !== 'ed25519') return undefined;
  const keyId = fields.keyId ?? '';
  if (!/^[a-f0-9]{16}$/.test(keyId)) return undefined;
  let signature: Uint8Array;
  try {
    signature = decodeExact(fields.signature, alg === 'hmac-sha256' ? 32 : 64, 'signature');
  } catch {
    return undefined;
  }
  return { alg, keyId, signature };
}

function hmac(body: string, secret: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac('sha256', secret).update(body).digest());
}

function edSign(body: string, seed: Uint8Array): Uint8Array {
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  });
  return new Uint8Array(sign(null, Buffer.from(body), privateKey));
}

function publicRawFromSeed(seed: Uint8Array): Uint8Array {
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  });
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return new Uint8Array(der.subarray(der.length - 32));
}

function keyIdFor(material: Uint8Array): string {
  return createHash('sha256').update(material).digest('hex').slice(0, 16);
}

function readFields(lines: string[]): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const line of lines) {
    const split = line.indexOf(':');
    if (split <= 0) throw new UsageError('baseline key file has an unreadable line');
    const name = line.slice(0, split).trim();
    const value = line.slice(split + 1).trim();
    if (fields[name] !== undefined) throw new UsageError(`baseline key file repeats ${name}`);
    fields[name] = value;
  }
  return fields;
}

function decodeExact(value: string | undefined, bytes: number, label: string): Uint8Array {
  if (!value) throw new UsageError(`baseline key is missing ${label}`);
  let raw: Buffer;
  try {
    raw = Buffer.from(value, 'base64');
  } catch {
    throw new UsageError(`baseline key ${label} is not base64`);
  }
  if (raw.byteLength !== bytes) throw new UsageError(`baseline key ${label} has the wrong length`);
  return new Uint8Array(raw);
}

function required(value: Uint8Array | undefined, label: string): Uint8Array {
  if (!value) throw new UsageError(`baseline key is missing ${label}`);
  return value;
}
