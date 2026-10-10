/**
 * Ed25519 public key for https://ironheights.dev/advisories.json.
 *
 * Set this to the hex encoding of the raw 32-byte public key before publishing
 * a feed. The matching private key is not in this repository. Until this
 * constant is replaced, the CLI refuses every feed (fail closed).
 * See docs/advisories.md.
 */
export const PINNED_ADVISORY_PUBLIC_KEY_HEX = 'UNCONFIGURED';

const UNCONFIGURED = 'UNCONFIGURED';

/** Raw 32-byte production public key, or null when the owner has not pinned one yet. */
export function pinnedAdvisoryPublicKey(): Uint8Array | null {
  if (PINNED_ADVISORY_PUBLIC_KEY_HEX === UNCONFIGURED) return null;
  if (!/^[0-9a-f]{64}$/.test(PINNED_ADVISORY_PUBLIC_KEY_HEX)) return null;
  return hexToBytes(PINNED_ADVISORY_PUBLIC_KEY_HEX);
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error('invalid hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
