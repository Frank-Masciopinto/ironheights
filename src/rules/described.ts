/**
 * Lines that describe a danger instead of performing it.
 * A regex in a rule-authoring field, a hint inside echo/printf, or a commented
 * placeholder path. A live shell sink on the same line is still the danger.
 */

const REGEX_ESCAPE = /\\[sSdDwWbBnrt()[\]{}+|.*?^$]/;
const LIVE_SINK =
  /\/dev\/tcp\/(?!127\.0\.0\.1\b|localhost\b)[A-Za-z0-9._-]+\/\d+|\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b|\bnc(?:at)?\b[^\n]{0,80}-e\s+\/bin\/(?:ba)?sh\b/i;

/** `pattern: \.env$` or a `Matches:` cheat-sheet row. Not a command. */
export function isDescribedRegex(line: string): boolean {
  if (LIVE_SINK.test(line)) return false;
  if (!REGEX_ESCAPE.test(line)) return false;
  return /(?:^|\s)pattern\s*:/i.test(line) || /\bMatches\s*:/.test(line);
}

function withoutQuotes(line: string): string {
  return line.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, ' ');
}

/**
 * The pattern hits only inside an echo or printf string, and that string is not
 * piped into a shell. `echo "sudo …" | sh` stays a hit.
 */
export function echoHintOnly(line: string, pattern: RegExp): boolean {
  if (!/\b(?:echo|printf)\b/i.test(line)) return false;
  const bare = withoutQuotes(line);
  if (/\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\|\s*(?:python3?|node)\b/i.test(bare)) return false;
  const flags = pattern.flags.replace('g', '');
  if (!new RegExp(pattern.source, flags).test(line)) return false;
  return !new RegExp(pattern.source, flags).test(bare);
}

/**
 * A full-line comment whose path is a placeholder (`[user]`, `<name>`), with no
 * verb that reads or sends the file.
 */
export function placeholderConfigComment(line: string): boolean {
  if (!/^\s*#/.test(line)) return false;
  if (!/\[[^\]\n]+\]|<[^>\n]+>/.test(line)) return false;
  return !/\b(?:cat|type|Get-Content|less|more|head|tail|curl|wget|send|post|upload|read|source|export|scp|rsync)\b/i.test(
    line,
  );
}
