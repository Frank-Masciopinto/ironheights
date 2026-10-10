const REPLACEMENT = '[REDACTED]';

/**
 * Best-effort secret scrub before skill text leaves the machine.
 * A value that matches none of these shapes is still sent.
 */
export function redactSecrets(
  input: string,
  extras: readonly string[] = [],
): { text: string; count: number } {
  let text = input;
  let count = 0;
  for (const secret of extras) {
    if (secret.length < 8 || !text.includes(secret)) continue;
    const parts = text.split(secret);
    count += parts.length - 1;
    text = parts.join(REPLACEMENT);
  }
  for (const pattern of tokenPatterns()) {
    text = text.replace(pattern, () => {
      count += 1;
      return REPLACEMENT;
    });
  }
  text = text.replace(assignmentPattern(), (_match, prefix: string) => {
    count += 1;
    return `${prefix}"${REPLACEMENT}"`;
  });
  return { text, count };
}

function tokenPatterns(): RegExp[] {
  return [
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]{0,8000}?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g,
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g,
    /\bAKIA[0-9A-Z]{16}\b/g,
    /\bghp_[A-Za-z0-9]{20,80}\b/g,
    /\bgithub_pat_[A-Za-z0-9_]{20,80}\b/g,
    /\bgh[ousr]_[A-Za-z0-9]{20,80}\b/g,
    /\bxox[baprs]-[A-Za-z0-9-]{10,80}\b/g,
    /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,120}\b/g,
    /\bnpm_[A-Za-z0-9]{20,80}\b/g,
    /\bBearer\s+[A-Za-z0-9._~+/-]{16,200}/g,
  ];
}

function assignmentPattern(): RegExp {
  return /(\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key)\b\s*[:=]\s*)(['"])([A-Za-z0-9+/=_-]{20,200})\2/gi;
}
