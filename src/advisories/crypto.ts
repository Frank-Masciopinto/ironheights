import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { NetworkError } from '../core/errors.ts';

/** SPKI prefix for a raw 32-byte Ed25519 public key. */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
/** PKCS#8 prefix for a raw 32-byte Ed25519 seed. */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function publicKeyFromRaw(raw: Uint8Array): KeyObject {
  if (raw.byteLength !== 32) throw new NetworkError('advisory public key must be 32 bytes');
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
    format: 'der',
    type: 'spki',
  });
}

export function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.byteLength !== 32) throw new NetworkError('advisory private key must be 32 bytes');
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  });
}

export function publicKeyHexFromSeed(seed: Uint8Array): string {
  const derived = createPublicKey(privateKeyFromSeed(seed));
  const der = derived.export({ format: 'der', type: 'spki' });
  return Buffer.from(der.subarray(der.length - 32)).toString('hex');
}

/**
 * Detached signature text. The signed message is the exact advisory JSON bytes,
 * not a re-serialization.
 */
export function signAdvisoryBytes(message: Uint8Array, seed: Uint8Array): string {
  const signature = sign(null, Buffer.from(message), privateKeyFromSeed(seed));
  return `ed25519 ${signature.toString('base64')}\n`;
}

export function verifyAdvisorySignature(
  message: Uint8Array,
  signatureText: string,
  publicKey: Uint8Array,
): boolean {
  const parsed = parseDetachedSignature(signatureText);
  if (!parsed) return false;
  try {
    return verify(null, Buffer.from(message), publicKeyFromRaw(publicKey), Buffer.from(parsed));
  } catch {
    return false;
  }
}

export function parseDetachedSignature(signatureText: string): Uint8Array | undefined {
  const match = /^ed25519 ([A-Za-z0-9+/]{86,88}={0,2})\n?$/.exec(signatureText);
  if (!match?.[1]) return undefined;
  let raw: Buffer;
  try {
    raw = Buffer.from(match[1], 'base64');
  } catch {
    return undefined;
  }
  if (raw.byteLength !== 64) return undefined;
  return new Uint8Array(raw);
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}
