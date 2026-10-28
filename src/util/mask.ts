import { stripControls } from './text.ts';

/** Keep the first four characters and replace the rest with asterisks. */
export function maskSecret(value: string): string {
  const clean = stripControls(value);
  if (clean.length <= 4) return '*'.repeat(Math.max(clean.length, 4));
  return `${clean.slice(0, 4)}${'*'.repeat(Math.min(clean.length - 4, 28))}`;
}

/**
 * Keep the first four and last four characters. IH-CRED-006 uses this so a
 * fallback secret can be recognized in a report without printing the middle.
 */
export function maskSecretEnds(value: string): string {
  const clean = stripControls(value);
  if (clean.length <= 8) return '*'.repeat(Math.max(clean.length, 4));
  const hidden = Math.min(clean.length - 8, 24);
  return `${clean.slice(0, 4)}${'*'.repeat(hidden)}${clean.slice(-4)}`;
}

export function maskWithin(line: string, secret: string): string {
  if (secret.length === 0) return line;
  return line.split(secret).join(maskSecret(secret));
}
