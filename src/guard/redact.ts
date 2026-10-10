import { maskSecret } from '../util/mask.ts';

/**
 * Mask secrets before they reach a block reason or the audit log.
 * The block reason is shown to the agent, so it must not echo the secret.
 */

const PEM =
  /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]{0,4000}?-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----/g;
const AWS = /\bAKIA[0-9A-Z]{16}\b/g;
const GITHUB =
  /\b(?:ghp_[A-Za-z0-9]{20,80}|github_pat_[A-Za-z0-9_]{20,80}|gho_[A-Za-z0-9]{20,80})\b/g;
const SLACK = /\bxox[baprs]-[A-Za-z0-9-]{10,80}\b/g;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]{12,200}/gi;
const QUERY = /([?&](?:api[_-]?key|token|secret|password|passwd)=)([^&\s]{4,200})/gi;
const ASSIGN =
  /(\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key)\b\s*[:=]\s*['"])([A-Za-z0-9+/=_-]{20,200})(['"])/gi;

export function redactSecrets(value: string): string {
  if (value.length === 0) return value;
  let out = value;
  out = replace(out, PEM, (match) => maskSecret(match));
  out = replace(out, AWS, (match) => maskSecret(match));
  out = replace(out, GITHUB, (match) => maskSecret(match));
  out = replace(out, SLACK, (match) => maskSecret(match));
  out = replace(out, BEARER, (match) => {
    const token = match.replace(/^Bearer\s+/i, '');
    return `Bearer ${maskSecret(token)}`;
  });
  out = replace(
    out,
    QUERY,
    (_match, prefix: string, secret: string) => `${prefix}${maskSecret(secret)}`,
  );
  out = replace(out, ASSIGN, (_match, prefix: string, secret: string, suffix: string) => {
    return `${prefix}${maskSecret(secret)}${suffix}`;
  });
  return out;
}

function replace(value: string, pattern: RegExp, replacer: (...args: string[]) => string): string {
  pattern.lastIndex = 0;
  return value.replace(pattern, replacer);
}
