/**
 * Shannon entropy in bits per character.
 * IH-CRED-002 treats an assignment as a secret when the value is at least
 * {@link ENTROPY_MIN_LENGTH} characters and entropy is at least {@link ENTROPY_THRESHOLD}.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

export const ENTROPY_THRESHOLD = 4;
export const ENTROPY_MIN_LENGTH = 20;
