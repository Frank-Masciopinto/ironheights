/**
 * Ed25519 public key for https://ironheights.dev/advisories.json.
 *
 * Raw 32-byte key, lowercase hex. The matching private key is held offline
 * and is not in this repository. Rotation is a CLI release that changes this
 * constant, then a feed signed by the new key. See docs/advisories.md.
 */
export const PINNED_ADVISORY_PUBLIC_KEY_HEX: string =
  '8424b837422792656e6e7500869395a5afe64bf163baa63acea83f1e97cc2b6c';

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
