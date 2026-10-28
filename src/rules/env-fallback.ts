import type { Finding, Rule, ScannedFile } from '../core/types.ts';
import { shannonEntropy } from '../util/entropy.ts';
import { maskSecretEnds } from '../util/mask.ts';
import { createFinding, pushUnique } from './helpers.ts';

/**
 * IH-CRED-006: a credential hard-coded as the default of an environment lookup.
 * The value ships in the package even when the variable is set in production.
 *
 * Shapes: os.getenv("NAME", "..."), os.environ.get("NAME", "..."),
 * getenv(...) or "...", process.env.NAME || / ?? "...", process.env["NAME"],
 * and ${NAME:-...}. Whitespace and newlines inside the call still match
 * (a 3-line os.environ.get was missed by line-oriented checks).
 *
 * A literal of length >= 16 that starts with a known key prefix is enough.
 * 0x + 64 hex is one of those prefixes and runs only on code (this rule does
 * not apply to Markdown, where transaction hashes are noise). Any other
 * literal needs Shannon entropy >= 3.5, length >= 20, and a secret-like
 * variable name. Entropy alone flags public 0x addresses in crypto skills,
 * so the name gate stays, and a 42-character 0x address is never a secret.
 * Env-to-env fallbacks (process.env.A || process.env.B) are not this rule.
 */

const PREFIX_MIN_LENGTH = 16;
const ENTROPY_MIN_LENGTH = 20;
const ENTROPY_THRESHOLD = 3.5;

/** Known key prefixes. 0x + 64 hex is handled separately and only for code. */
const KEY_PREFIX = /^(?:AIza|sk_|sk-|ghp_|github_pat_|xox[abprs]-|AKIA)/;
const HEX_PRIVATE_KEY = /^0x[0-9a-fA-F]{64}$/;
const PUBLIC_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/**
 * One quoted literal, single line, at most 300 characters inside the quotes.
 * Bounded so a missing closer cannot scan the rest of the file.
 */
const QUOTED =
  '(?:\'(?:\\\\.|[^\'\\\\\\n]){0,300}\'|"(?:\\\\.|[^"\\\\\\n]){0,300}"|`(?:\\\\.|[^`\\\\\\n]){0,300}`)';

const WS = String.raw`\s{0,200}`;
const PY_NAME = String.raw`(['"])([A-Za-z_]\w{0,80})\1`;
const PY_PREFIX = String.raw`(?:[rRuUbBfF]{1,2})?`;

const PY_GETENV_DEFAULT = new RegExp(
  String.raw`\b(?:os\.)?getenv${WS}\(${WS}${PY_NAME}${WS},${WS}(?:default${WS}=${WS})?${PY_PREFIX}(${QUOTED})`,
  'g',
);
const PY_ENVIRON_DEFAULT = new RegExp(
  String.raw`\bos\.environ\.get${WS}\(${WS}${PY_NAME}${WS},${WS}(?:default${WS}=${WS})?${PY_PREFIX}(${QUOTED})`,
  'g',
);
const PY_GETENV_OR = new RegExp(
  String.raw`\b(?:os\.)?getenv${WS}\(${WS}${PY_NAME}${WS}\)${WS}\bor${WS}\(?${WS}${PY_PREFIX}(${QUOTED})`,
  'g',
);
const PY_ENVIRON_OR = new RegExp(
  String.raw`\bos\.environ\.get${WS}\(${WS}${PY_NAME}${WS}\)${WS}\bor${WS}\(?${WS}${PY_PREFIX}(${QUOTED})`,
  'g',
);
const JS_DOT = new RegExp(
  String.raw`\bprocess\.env\??\.([A-Za-z_]\w{0,80})${WS}(?:\|\||\?\?)${WS}\(?${WS}(${QUOTED})`,
  'g',
);
const JS_BRACKET = new RegExp(
  '\\bprocess\\.env\\??\\[\\s{0,40}([\'"`])([A-Za-z_]\\w{0,80})\\1\\s{0,40}\\]\\s{0,200}(?:\\|\\||\\?\\?)\\s{0,200}\\(?\\s{0,40}(' +
    QUOTED +
    ')',
  'g',
);
const SHELL_DEFAULT = /\$\{([A-Za-z_]\w{0,80}):-\s{0,40}([^}\n]{0,300})\}/g;

const SECRET_WORD =
  /^(?:keys?|tokens?|secrets?|passwords?|passwd|private|credentials?|apikey|apisecret)$/i;

type FallbackStyle = 'js' | 'py-default' | 'py-or' | 'shell';
type FallbackReason = 'prefix' | 'entropy';

interface FallbackHit {
  at: number;
  name: string;
  value: string;
  style: FallbackStyle;
  reason: FallbackReason;
}

export const cred006: Rule = {
  id: 'IH-CRED-006',
  title: 'Hard-coded environment fallback',
  category: 'credentials',
  severity: 'high',
  priority: 'P0',
  description:
    'A credential used as the default of an environment-variable lookup is shipped in the package. os.getenv, os.environ.get, getenv(...) or, process.env || or ??, and ${VAR:-...} count, including when the call is split across lines. A known key prefix of length at least 16 is enough in a code file. Other literals need Shannon entropy of at least 3.5, length at least 20, and a secret-like variable name. A 42-character 0x address is not a secret. Markdown is not scanned, so transaction hashes there are ignored. An env var falling back to another env var is not this rule.',
  remediation:
    'Remove the fallback secret, rotate it, and read the environment variable with no default.',
  appliesTo: ['script'],
  examples: {
    matches: [
      'os.getenv("GOOGLE_API_KEY", "AIzaSyFAKEWeatherKeyNotReal00000Wxyz")',
      "process.env.PRIVATE_KEY || '0x0123456789abcdeffedcba9876543210aaaabbbbccccdddd1111222233334444'",
      '${OPENAI_API_KEY:-sk-FAKEshellFallbackNotReal0123456789abcd}',
    ],
    nonMatches: [
      'os.getenv("API_KEY", "your-api-key-here")',
      'process.env.TOKEN || "changeme"',
      'process.env.API_KEY || process.env.BACKUP_API_KEY',
      'process.env.PRIVATE_KEY || "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"',
      '${TOKEN:-$OTHER_TOKEN}',
    ],
  },
  check: checkCred006,
};

function checkCred006(file: ScannedFile): Finding[] {
  // Code files only. Markdown stays out so a 0x+64 hex tx hash or selector
  // in docs cannot take the private-key arm, and prose cannot take the others.
  if (file.kind !== 'script' || file.text === '') return [];
  const hits = collectHits(file.text);
  hits.sort((a, b) => a.at - b.at);
  const findings: Finding[] = [];
  const seen = new Set<number>();
  for (const hit of hits) {
    if (seen.has(hit.at)) continue;
    seen.add(hit.at);
    const masked = maskSecretEnds(hit.value);
    pushUnique(
      findings,
      createFinding(cred006, file, {
        line: lineNumberAt(file.text, hit.at),
        evidence: evidenceFor(hit.style, hit.name, masked),
        message: 'A credential is hard-coded as the fallback for an environment variable.',
        confidence: hit.reason === 'prefix' ? 'high' : 'medium',
      }),
    );
  }
  return findings;
}

function collectHits(text: string): FallbackHit[] {
  const hits: FallbackHit[] = [];
  collectCall(hits, text, PY_GETENV_DEFAULT, 'py-default', 2, 3);
  collectCall(hits, text, PY_ENVIRON_DEFAULT, 'py-default', 2, 3);
  collectCall(hits, text, PY_GETENV_OR, 'py-or', 2, 3);
  collectCall(hits, text, PY_ENVIRON_OR, 'py-or', 2, 3);
  collectCall(hits, text, JS_DOT, 'js', 1, 2);
  collectCall(hits, text, JS_BRACKET, 'js', 2, 3);
  collectShell(hits, text);
  return hits;
}

function collectCall(
  hits: FallbackHit[],
  text: string,
  re: RegExp,
  style: FallbackStyle,
  nameGroup: number,
  literalGroup: number,
): void {
  re.lastIndex = 0;
  for (const match of text.matchAll(re)) {
    if (match.index === undefined) continue;
    if (inComment(text, match.index)) continue;
    const name = match[nameGroup] ?? '';
    const quoted = match[literalGroup] ?? '';
    const value = unquote(quoted);
    if (value === undefined) continue;
    const reason = fallbackReason(name, value);
    if (!reason) continue;
    const at = match.index + match[0].lastIndexOf(quoted);
    hits.push({ at, name, value, style, reason });
  }
}

function collectShell(hits: FallbackHit[], text: string): void {
  SHELL_DEFAULT.lastIndex = 0;
  for (const match of text.matchAll(SHELL_DEFAULT)) {
    if (match.index === undefined) continue;
    if (inComment(text, match.index)) continue;
    const name = match[1] ?? '';
    const raw = match[2] ?? '';
    const value = shellLiteral(raw);
    if (value === undefined) continue;
    const reason = fallbackReason(name, value);
    if (!reason) continue;
    const at = match.index + match[0].lastIndexOf(raw);
    hits.push({ at, name, value, style: 'shell', reason });
  }
}

function fallbackReason(name: string, value: string): FallbackReason | undefined {
  const literal = value.trim();
  if (literal.length === 0 || isPlaceholder(literal)) return undefined;
  if (
    literal.length >= PREFIX_MIN_LENGTH &&
    (KEY_PREFIX.test(literal) || HEX_PRIVATE_KEY.test(literal))
  ) {
    return 'prefix';
  }
  if (
    literal.length >= ENTROPY_MIN_LENGTH &&
    !PUBLIC_ADDRESS.test(literal) &&
    isSecretName(name) &&
    shannonEntropy(literal) >= ENTROPY_THRESHOLD
  ) {
    return 'entropy';
  }
  return undefined;
}

function isSecretName(name: string): boolean {
  const tokens = name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .split(/\s+/)
    .filter((part) => part.length > 0);
  for (const token of tokens) {
    if (SECRET_WORD.test(token)) return true;
    if (/^auth$/i.test(token)) return true;
    if (/^(?:authenticat|authoriz)/i.test(token)) return true;
  }
  return false;
}

function isPlaceholder(value: string): boolean {
  if (/^<[^>\n]{1,80}>$/.test(value)) return true;
  if (/^\[[^\]\n]{1,80}\]$/.test(value)) return true;
  if (/^\{[^}\n]{1,80}\}$/.test(value)) return true;
  if (
    /^(?:x+|changeme|change[-_ ]me|password|secret|token|none|null|undefined|todo|fixme|placeholder|example|sample|dummy|insert[-_ ]?key|replace[-_ ]?me)$/i.test(
      value,
    )
  ) {
    return true;
  }
  if (/your[-_ ]?(?:api[-_ ]?)?(?:key|token|secret|password)/i.test(value)) return true;
  if (/^(.)\1{11,}$/.test(value)) return true;
  return false;
}

/** Strip one pair of quotes. A template with ${...} is not a hard-coded literal. */
function unquote(quoted: string): string | undefined {
  if (quoted.length < 2) return undefined;
  const quote = quoted[0];
  if ((quote !== "'" && quote !== '"' && quote !== '`') || quoted.at(-1) !== quote)
    return undefined;
  const inner = quoted.slice(1, -1);
  if (quote === '`' && hasInterpolation(inner)) return undefined;
  if (inner.includes('{') || inner.includes('}')) return undefined;
  return inner.replace(/\\(.)/g, '$1');
}

function hasInterpolation(inner: string): boolean {
  for (let i = 0; i < inner.length - 1; i += 1) {
    if (inner[i] === '\\') {
      i += 1;
      continue;
    }
    if (inner[i] === '$' && inner[i + 1] === '{') return true;
  }
  return false;
}

/** A shell ${VAR:-...} value. `$` means another expansion, not a literal secret. */
function shellLiteral(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.includes('$') || trimmed.includes('`')) return undefined;
  const quoted = /^(['"])([\s\S]*)\1$/.exec(trimmed);
  if (quoted) {
    const inner = quoted[2] ?? '';
    if (inner.includes('$') || inner.includes('`') || inner.includes('{')) return undefined;
    return inner;
  }
  if (trimmed.includes('{') || trimmed.includes('}')) return undefined;
  return trimmed;
}

function evidenceFor(style: FallbackStyle, name: string, masked: string): string {
  switch (style) {
    case 'js':
      return `process.env.${name} || '${masked}'`;
    case 'py-default':
      return `os.getenv("${name}", "${masked}")`;
    case 'py-or':
      return `getenv("${name}") or "${masked}"`;
    case 'shell':
      return `\${${name}:-${masked}}`;
    default: {
      const neverStyle: never = style;
      return neverStyle;
    }
  }
}

function lineNumberAt(text: string, index: number): number {
  let line = 1;
  const end = Math.min(index, text.length);
  for (let i = 0; i < end; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

/** True when `index` sits in a `#`, `//`, or block comment. Strings are not comments. */
function inComment(text: string, index: number): boolean {
  let state: 'code' | 'line' | 'block' | 'squote' | 'dquote' | 'tick' = 'code';
  for (let i = 0; i < index; i += 1) {
    const ch = text[i] ?? '';
    const next = text[i + 1] ?? '';
    if (state === 'line') {
      if (ch === '\n') state = 'code';
      continue;
    }
    if (state === 'block') {
      if (ch === '*' && next === '/') {
        state = 'code';
        i += 1;
      }
      continue;
    }
    if (state === 'squote' || state === 'dquote' || state === 'tick') {
      if (ch === '\\') {
        i += 1;
        continue;
      }
      const end = state === 'squote' ? "'" : state === 'dquote' ? '"' : '`';
      if (ch === end) state = 'code';
      continue;
    }
    if (ch === '#') {
      state = 'line';
      continue;
    }
    if (ch === '/' && next === '/') {
      state = 'line';
      i += 1;
      continue;
    }
    if (ch === '/' && next === '*') {
      state = 'block';
      i += 1;
      continue;
    }
    if (ch === "'") state = 'squote';
    else if (ch === '"') state = 'dquote';
    else if (ch === '`') state = 'tick';
  }
  return state === 'line' || state === 'block';
}
