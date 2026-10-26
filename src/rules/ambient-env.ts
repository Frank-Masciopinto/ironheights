import type { Finding, Rule, ScannedFile, ScanContext } from '../core/types.ts';
import { createFinding } from './helpers.ts';

/**
 * IH-EXEC-005: a skill names a secret and starts a child with the parent
 * environment. Explicit full copies (`...process.env`, `os.environ.copy()`,
 * `env: process.env`) are flagged when any non-test file in the skill names a
 * secret. A spawn that omits `env` (the language default) is flagged only when
 * the same file names a secret, so one API-key mention does not mark every
 * helper in the skill. An env object or dict that lists keys, and is not built
 * from a full-environment copy, is quiet.
 *
 * One finding per file, on the strongest call (an explicit full copy wins over
 * a default inherit). Several spawns in one helper would otherwise add up past
 * the block threshold. Paths under test/, tests/, __tests__/, spec/, or
 * fixtures/ are skipped, same as IH-CRED-004 and IH-EXEC-004.
 */

const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?)\//i;

const LAUNCHER_SOURCE = [
  String.raw`(?:^|[^\w])(?:spawnSync|spawn|execFileSync|execFile|execSync|fork)\s*\(`,
  String.raw`(?:^|[^\w.])(?:(?:child_process|cp|proc|child)\.)?exec\s*\(`,
  String.raw`\b(?:new\s+)?StdioClientTransport\s*\(`,
  String.raw`\bnew\s+Deno\.Command\s*\(`,
  String.raw`\bsubprocess\.(?:check_output|check_call|Popen|run|call)\s*\(`,
  String.raw`\bos\.(?:system|popen)\s*\(`,
].join('|');

const SECRET_NAME =
  /api[_-]?key|apikey|secret|token|password|passwd|credential|private[_-]?key|access[_-]?key/i;

const ENV_READ_SOURCES = [
  String.raw`process\.env\.([A-Za-z_]\w*)`,
  String.raw`process\.env\[\s*['"]([A-Za-z_]\w*)['"]\s*\]`,
  String.raw`os\.environ\s*\[\s*['"]([A-Za-z_]\w*)['"]\s*\]`,
  String.raw`os\.environ\.get\s*\(\s*['"]([A-Za-z_]\w*)['"]`,
  String.raw`os\.getenv\s*\(\s*['"]([A-Za-z_]\w*)['"]`,
];

const FULL_MESSAGE =
  'A child process is started with the full parent environment, and this skill names a secret. The child can read every API key in the environment, not only the one it needs.';

const INHERIT_MESSAGE =
  'A child process is started without an env option, so it inherits the parent environment, and this file names a secret. The child can read every API key in the environment.';

export const exec005: Rule = {
  id: 'IH-EXEC-005',
  title: 'Child process inherits ambient credentials',
  category: 'exec',
  severity: 'medium',
  priority: 'P1',
  description:
    'A skill that names an API key, token, or other secret-shaped variable and starts a child process with the parent environment gives that child every secret in the environment. A spread of process.env (including an MCP client `{ ...process.env, ...config.env }`), env: process.env, os.environ.copy(), **os.environ, and a spawn, exec, fork, or subprocess call that omits env all count. The secret may sit in the same file, or, for an explicit full-environment copy, in another file of the skill. An explicit env object or dict that lists the keys the child needs, and is not built from a full-environment copy, is quiet. A spawn in a file that names no secret is quiet. Files under test/ or fixtures/ are skipped. One finding is reported per file.',
  remediation:
    'Build a minimal environment for the child: PATH, HOME, and only the keys that child needs. Pass that object as env. Do not spread process.env, pass process.env itself, copy os.environ, or leave env unset.',
  appliesTo: ['any'],
  examples: {
    matches: [
      'spawn("node", ["srv.js"], { env: { ...process.env, ...config.env } })',
      'subprocess.run(cmd, env=os.environ.copy())',
      'spawn("helper") when the same file reads process.env.OPENAI_API_KEY',
    ],
    nonMatches: [
      'spawn("helper", { env: { PATH: process.env.PATH, HOME: process.env.HOME, API_KEY: process.env.API_KEY } })',
      'env = {k: os.environ[k] for k in ("PATH", "HOME", "API_KEY")}',
      'spawn("helper", { env: { ...process.env } }) when the skill names no secret',
    ],
  },
  check: checkExec005,
};

interface SpawnHit {
  kind: 'full' | 'default';
  line: number;
  evidence: string;
}

type EnvPass = 'full' | 'allowlist' | 'default';

function isSecretName(name: string): boolean {
  return SECRET_NAME.test(name);
}

/** True when the file names a secret-shaped variable, env read, or "api key". */
function fileMentionsSecret(text: string): boolean {
  if (/\bapi[_ -]?key\b/i.test(text)) return true;
  if (/\b(?:private[_ -]?key|access[_ -]?key|client[_ -]?secret)\b/i.test(text)) return true;
  if (hasEnvSecret(text) || hasScreamingSecret(text) || hasShellSecret(text)) return true;
  return /\b[a-z][A-Za-z0-9]*?(?:ApiKey|Secret|Token|Password|Credential)\b/.test(text);
}

export function skillHoldsAmbientSecret(
  files: readonly { relativePath: string; text: string }[],
): boolean {
  return files.some((file) => !TEST_PATH.test(file.relativePath) && fileMentionsSecret(file.text));
}

function checkExec005(file: ScannedFile, ctx: ScanContext): Finding[] {
  if (TEST_PATH.test(file.relativePath) || file.text === '') return [];
  const localSecret = fileMentionsSecret(file.text);
  const skillSecret = localSecret || ctx.skillHoldsSecret === true;
  if (!localSecret && !skillSecret) return [];
  const fullNames = fullEnvNames(file.text);
  let picked: SpawnHit | undefined;
  for (const match of file.text.matchAll(new RegExp(LAUNCHER_SOURCE, 'g'))) {
    if (match.index === undefined) continue;
    const open = match.index + match[0].lastIndexOf('(');
    if (skippedMatch(file.text, open) || inString(file.text, open)) continue;
    const window = callWindow(file.text, open);
    const kind = classifyCall(window, fullNames);
    const at = lineAt(file.text, open);
    const hit: SpawnHit = { kind: kind === 'full' ? 'full' : 'default', ...at };
    picked = consider(kind, hit, picked, localSecret, skillSecret);
  }
  if (!picked) return [];
  return [
    createFinding(exec005, file, {
      line: picked.line,
      evidence: picked.evidence,
      message: picked.kind === 'full' ? FULL_MESSAGE : INHERIT_MESSAGE,
      confidence: picked.kind === 'full' ? 'high' : 'medium',
    }),
  ];
}

function consider(
  kind: EnvPass,
  hit: SpawnHit,
  picked: SpawnHit | undefined,
  localSecret: boolean,
  skillSecret: boolean,
): SpawnHit | undefined {
  switch (kind) {
    case 'full':
      if (!skillSecret) return picked;
      if (!picked || picked.kind !== 'full') return hit;
      return picked;
    case 'allowlist':
      return picked;
    case 'default':
      if (!localSecret) return picked;
      if (!picked) return hit;
      return picked;
    default: {
      const unexpected: never = kind;
      return unexpected;
    }
  }
}

function classifyCall(window: string, fullNames: ReadonlySet<string>): EnvPass {
  if (windowIsFull(window, fullNames)) return 'full';
  if (hasRestrictingEnv(window)) return 'allowlist';
  return 'default';
}

function windowIsFull(window: string, fullNames: ReadonlySet<string>): boolean {
  if (rhsIsFullEnv(window)) return true;
  for (const name of fullNames) {
    if (passesBinding(window, name)) return true;
  }
  return false;
}

/** An env option that is not the language default. `env=None` / `env: undefined` still inherits. */
function hasRestrictingEnv(window: string): boolean {
  if (/\benv\s*[:=]\s*(?:None|undefined|null)\b/.test(window)) return false;
  if (/\benv\s*[:=]/.test(window)) return true;
  return /\{\s*env\s*[,}]/.test(window);
}

function passesBinding(window: string, name: string): boolean {
  const id = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return (
    new RegExp(String.raw`\benv\s*[:=]\s*(?:\{[^}]{0,240})?\.\.\.\s*${id}\b`).test(window) ||
    new RegExp(String.raw`\benv\s*[:=]\s*${id}\b`).test(window) ||
    new RegExp(String.raw`\{\s*${id}\s*[,}]`).test(window) ||
    new RegExp(String.raw`(?:[(,]|^)\s*${id}\s*(?:[,)]|$)`).test(window)
  );
}

/**
 * Names assigned from a full parent environment in this file.
 * `env = os.environ.copy()` then `subprocess.run(cmd, env=env)` is a full copy.
 * `env = {k: os.environ[k] for k in ("PATH", "HOME")}` is not.
 */
function fullEnvNames(text: string): Set<string> {
  const names = new Set<string>();
  const assign =
    /(?:^|[^\w.])(?:(?:const|let|var|export)\s+)?([A-Za-z_]\w*)\s*(?<![=!<>])=(?!=)\s*/g;
  for (const match of text.matchAll(assign)) {
    const name = match[1];
    if (!name || match.index === undefined) continue;
    const rhsStart = match.index + match[0].length;
    const rhs = rhsSlice(text.slice(rhsStart, rhsStart + 500));
    if (rhsIsFullEnv(rhs)) names.add(name);
  }
  return names;
}

function rhsIsFullEnv(rhs: string): boolean {
  if (/\.\.\.\s*process\.env\b/.test(rhs)) return true;
  if (/\bDeno\.env\.toObject\s*\(/.test(rhs)) return true;
  if (/\*\*\s*os\.environ\b/.test(rhs)) return true;
  if (/\bos\.environ\.copy\s*\(/.test(rhs) || /\benviron\.copy\s*\(/.test(rhs)) return true;
  if (/\bdict\s*\(\s*os\.environ\s*\)/.test(rhs)) return true;
  // `{k: v for k, v in os.environ.items() if k in keep}` picks keys. No `if` copies all of them.
  if (/\bos\.environ\.items\s*\(/.test(rhs) && !/\bif\b/.test(rhs)) return true;
  if (/(?:^|[^.\w])process\.env\b(?!\s*[.[])/.test(rhs)) return true;
  if (/(?:^|[^.\w])os\.environ\b(?!\s*[.[(])/.test(rhs)) return true;
  return false;
}

function rhsSlice(rhs: string): string {
  const opener = rhs[0];
  if (opener !== '{' && opener !== '(') return rhs.split('\n')[0] ?? rhs;
  let depth = 0;
  let quote: string | undefined;
  const limit = Math.min(rhs.length, 500);
  for (let i = 0; i < limit; i += 1) {
    const ch = rhs[i] ?? '';
    if (quote) {
      if (ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '{' || ch === '(') depth += 1;
    else if (ch === '}' || ch === ')') {
      depth -= 1;
      if (depth === 0) return rhs.slice(0, i + 1);
    }
  }
  return rhs.slice(0, limit);
}

/** Bounded to 1200 characters so a huge call cannot pull in the next statement. */
function callWindow(text: string, openParen: number): string {
  const max = 1200;
  let depth = 0;
  let quote: string | undefined;
  const end = Math.min(text.length, openParen + max);
  for (let i = openParen; i < end; i += 1) {
    const ch = text[i] ?? '';
    if (quote) {
      if (ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return text.slice(openParen, i + 1);
    }
  }
  return text.slice(openParen, end);
}

function skippedMatch(text: string, openParen: number): boolean {
  const lineStart = text.lastIndexOf('\n', openParen - 1) + 1;
  const lineEnd = text.indexOf('\n', openParen);
  const line = text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd);
  if (/^\s*(?:\/\/|\/\*|\*|#)/.test(line)) return true;
  const before = text.slice(lineStart, openParen);
  const stripped = before.replace(/'(?:\\.|[^'\n])*'|"(?:\\.|[^"\n])*"|`(?:\\.|[^`\n])*`/g, '""');
  if (stripped.includes('//')) return true;
  return /\b(?:function|def|class|fn|async\s+function)\s+[A-Za-z_]\w*\s*$/.test(before);
}

function lineAt(text: string, index: number): { line: number; evidence: string } {
  const line = text.slice(0, index).split(/\r?\n/).length;
  const lines = text.split(/\r?\n/);
  return { line, evidence: lines[line - 1] ?? '' };
}

function hasEnvSecret(text: string): boolean {
  for (const source of ENV_READ_SOURCES) {
    for (const match of text.matchAll(new RegExp(source, 'g'))) {
      if (isSecretName(match[1] ?? '')) return true;
    }
  }
  return false;
}

/** True when `index` sits inside a quote or a Python triple-quoted string. */
function inString(text: string, index: number): boolean {
  let quote: string | undefined;
  for (let i = 0; i < index; i += 1) {
    const ch = text[i] ?? '';
    if (quote === '"""' || quote === "'''") {
      if (text.startsWith(quote, i)) {
        i += quote.length - 1;
        quote = undefined;
      }
      continue;
    }
    if (quote) {
      if (ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) quote = undefined;
      continue;
    }
    if (text.startsWith('"""', i) || text.startsWith("'''", i)) {
      quote = text.slice(i, i + 3);
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') quote = ch;
  }
  return quote !== undefined;
}

function hasScreamingSecret(text: string): boolean {
  for (const match of text.matchAll(/\b[A-Z][A-Z0-9_]{2,}\b/g)) {
    if (isSecretName(match[0] ?? '')) return true;
  }
  return false;
}

function hasShellSecret(text: string): boolean {
  for (const match of text.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)) {
    const name = match[1] ?? '';
    if (name.length >= 3 && isSecretName(name) && /[A-Z_]/.test(name)) return true;
  }
  return false;
}
