import { stripControls } from './text.ts';

/** Keep the first four characters and replace the rest with asterisks. */
export function maskSecret(value: string): string {
  const clean = stripControls(value);
  if (clean.length <= 4) return '*'.repeat(Math.max(clean.length, 4));
  return `${clean.slice(0, 4)}${'*'.repeat(Math.min(clean.length - 4, 28))}`;
}

export function maskWithin(line: string, secret: string): string {
  if (secret.length === 0) return line;
  return line.split(secret).join(maskSecret(secret));
}
