/**
 * Flattened config keys recorded at `drift approve` and compared by `drift check`.
 *
 * A ledger written before 0.22.0 has no `configKeys`. That is "no key baseline":
 * report that keys were not recorded, and never treat the absence as a block.
 * Secret-shaped values are stored and printed as `<redacted>`.
 */
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import YAML from 'yaml';
import { redactSecrets } from '../guard/redact.ts';

export const REDACTED = '<redacted>';

const SKIP_DIRS = new Set(['.git', 'node_modules']);
const CONFIG_EXT = new Set(['.json', '.yml', '.yaml']);
const SKIP_FILES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
]);
/** Config files larger than this are not parsed. */
const MAX_CONFIG = 262144;

const RESTRICTION_NAME =
  /timeout|limit|max|min|allow|allowlist|deny|denylist|block|scope|permission|readonly|sandbox|confirm|require|rate|quota|budget|ttl/i;
const BLOCK_SCOPE =
  /auth|token|key|secret|credential|password|oauth|host|url|endpoint|proxy|network|egress|domain|allow.*host|tool|tools|scope|permission|exec|shell|command/i;
const SECRET_KEY = /api[_-]?key|secret|token|password|passwd|credential|private/i;
const NUMERIC_LIMIT = /timeout|limit|quota|rate|budget|ttl|max/i;
const ALLOW_SCOPE = /allow|deny|scope|permission/i;
const BOOL_GUARD = /confirm|readonly|sandbox|require/i;

export type ConfigKeyChangeKind =
  | 'config-key-added'
  | 'restriction-removed'
  | 'restriction-loosened'
  | 'config-keys-unrecorded';

export interface ConfigKeyChange {
  source: string;
  key: string;
  change: ConfigKeyChangeKind;
  before?: string;
  after?: string;
  /** `block` is high (exit 2), `warn` is medium (exit 1), `info` does not fail. */
  severity: 'block' | 'warn' | 'info';
  reason: string;
}

export function isSecretKey(key: string): boolean {
  return SECRET_KEY.test(key);
}

export function isSecretValue(value: string): boolean {
  if (value.length < 8) return false;
  if (redactSecrets(value) !== value) return true;
  return /^(?:ghp_|github_pat_|gho_|xox[baprs]-|AKIA|sk-|sk_live_)/.test(value);
}

function parseStored(stored: string): unknown {
  try {
    return JSON.parse(stored) as unknown;
  } catch {
    return stored;
  }
}

function storedIsSecret(key: string, stored: string): boolean {
  if (isSecretKey(key)) return true;
  const parsed = parseStored(stored);
  return typeof parsed === 'string' ? isSecretValue(parsed) : isSecretValue(stored);
}

/** Replace secret values before they are written to a ledger or a hash. */
export function redactStored(key: string, stored: string): string {
  return storedIsSecret(key, stored) ? JSON.stringify(REDACTED) : stored;
}

function showValue(stored: string): string {
  const parsed = parseStored(stored);
  if (typeof parsed === 'string') return parsed;
  return JSON.stringify(parsed);
}

function flatten(value: unknown, prefix: string, out: Record<string, string>): void {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) {
      if (prefix) out[prefix] = '{}';
      return;
    }
    for (const [k, v] of entries) flatten(v, prefix ? `${prefix}.${k}` : k, out);
    return;
  }
  if (!prefix) return;
  out[prefix] = JSON.stringify(value ?? null);
}

function prefixKeys(rel: string, value: unknown, out: Record<string, string>): void {
  const flat: Record<string, string> = {};
  flatten(value, '', flat);
  for (const [k, v] of Object.entries(flat)) out[`${rel}:${k}`] = redactStored(`${rel}:${k}`, v);
}

function frontmatter(text: string): unknown {
  const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!fm) return undefined;
  return YAML.parse(fm[1] as string);
}

async function readConfigFile(abs: string): Promise<unknown | undefined> {
  let buf: Buffer;
  try {
    buf = await readFile(abs);
  } catch {
    return undefined;
  }
  if (buf.length > MAX_CONFIG || buf.subarray(0, 8000).includes(0)) return undefined;
  const text = buf.toString('utf8');
  try {
    return abs.endsWith('.json') ? (JSON.parse(text) as unknown) : (YAML.parse(text) as unknown);
  } catch {
    return undefined;
  }
}

/** Frontmatter plus JSON/YAML config files under a skill folder. Lockfiles are skipped. */
export async function collectConfigKeys(root: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop() as string;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(join(dir, e.name));
        continue;
      }
      if (!e.isFile()) continue;
      const abs = join(dir, e.name);
      const rel = relative(root, abs).split(sep).join('/');
      if (SKIP_FILES.has(e.name)) continue;
      if (e.name === 'SKILL.md') {
        try {
          const info = await lstat(abs);
          if (info.size > MAX_CONFIG) continue;
          const parsed = frontmatter(await readFile(abs, 'utf8'));
          if (parsed && typeof parsed === 'object') prefixKeys(rel, parsed, out);
        } catch {
          /* unreadable frontmatter: skip */
        }
        continue;
      }
      const dot = e.name.lastIndexOf('.');
      const ext = dot >= 0 ? e.name.slice(dot).toLowerCase() : '';
      if (!CONFIG_EXT.has(ext)) continue;
      try {
        const info = await lstat(abs);
        if (!info.isFile() || info.size > MAX_CONFIG) continue;
      } catch {
        continue;
      }
      const parsed = await readConfigFile(abs);
      if (parsed && typeof parsed === 'object') prefixKeys(rel, parsed, out);
    }
  }
  return out;
}

/** Env keys, long-option args, command and url for one MCP server entry. */
export function mcpServerConfigKeys(def: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!def || typeof def !== 'object') return out;
  const rec = def as Record<string, unknown>;
  if (typeof rec.command === 'string')
    out.command = redactStored('command', JSON.stringify(rec.command));
  if (typeof rec.url === 'string') out.url = redactStored('url', JSON.stringify(rec.url));
  if (rec.env && typeof rec.env === 'object' && !Array.isArray(rec.env)) {
    for (const [k, v] of Object.entries(rec.env as Record<string, unknown>)) {
      const key = `env.${k}`;
      out[key] = redactStored(key, JSON.stringify(v ?? null));
    }
  }
  if (Array.isArray(rec.args)) {
    const args = rec.args.map(String);
    for (let i = 0; i < args.length; i += 1) {
      const arg = args[i] ?? '';
      if (arg.startsWith('--')) {
        const body = arg.slice(2);
        const eq = body.indexOf('=');
        if (eq >= 0) {
          const key = `args.${body.slice(0, eq)}`;
          out[key] = redactStored(key, JSON.stringify(body.slice(eq + 1)));
        } else {
          const next = args[i + 1];
          const key = `args.${body}`;
          if (next !== undefined && !next.startsWith('-')) {
            out[key] = redactStored(key, JSON.stringify(next));
            i += 1;
          } else out[key] = 'true';
        }
      } else if (/^-[A-Za-z]$/.test(arg)) {
        out[`args.${arg.slice(1)}`] = 'true';
      }
    }
  }
  return out;
}

function isRestriction(key: string): boolean {
  return RESTRICTION_NAME.test(key);
}

function hasWildcard(value: unknown): boolean {
  if (value === '*') return true;
  if (typeof value === 'string') return value.includes('*');
  if (Array.isArray(value)) return value.some((item) => hasWildcard(item));
  return false;
}

function isDisabled(value: unknown): boolean {
  if (value === null || value === 0 || value === -1) return true;
  if (typeof value !== 'string') return false;
  const s = value.trim().toLowerCase();
  return s === '' || s === '0' || s === '-1' || s === 'unlimited' || s === 'none' || s === 'null';
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && /^-?\d+(?:\.\d+)?$/.test(value.trim())) return Number(value);
  return undefined;
}

function loosened(key: string, before: unknown, after: unknown): boolean {
  if (JSON.stringify(before) === JSON.stringify(after)) return false;
  if (BOOL_GUARD.test(key) && before === true && after === false) return true;
  if (ALLOW_SCOPE.test(key) && !hasWildcard(before) && hasWildcard(after)) return true;
  if (NUMERIC_LIMIT.test(key)) {
    if (isDisabled(after) && !isDisabled(before)) return true;
    const b = asNumber(before);
    const a = asNumber(after);
    if (b !== undefined && a !== undefined && a > b) return true;
  }
  return false;
}

function gainedWildcard(key: string, before: unknown, after: unknown): boolean {
  return ALLOW_SCOPE.test(key) && !hasWildcard(before) && hasWildcard(after);
}

function severityFor(key: string, wildcard: boolean): 'block' | 'warn' {
  return wildcard || BLOCK_SCOPE.test(key) ? 'block' : 'warn';
}

function pair(
  key: string,
  beforeStored: string | undefined,
  afterStored: string | undefined,
): { before?: string; after?: string; secret: boolean } {
  const secret =
    (beforeStored !== undefined && storedIsSecret(key, beforeStored)) ||
    (afterStored !== undefined && storedIsSecret(key, afterStored));
  if (secret || !isRestriction(key)) return { secret };
  return {
    secret,
    ...(beforeStored !== undefined ? { before: showValue(beforeStored) } : {}),
    ...(afterStored !== undefined ? { after: showValue(afterStored) } : {}),
  };
}

/**
 * Compare a recorded key map with the current one.
 * `before === undefined` means the ledger has no key baseline.
 */
export function diffConfigKeys(
  source: string,
  before: Record<string, string> | undefined,
  after: Record<string, string>,
): ConfigKeyChange[] {
  if (!before) {
    return [
      {
        source,
        key: '(unrecorded)',
        change: 'config-keys-unrecorded',
        severity: 'info',
        reason: 'config keys were not recorded at approval',
      },
    ];
  }
  const out: ConfigKeyChange[] = [];
  for (const [key, afterStored] of Object.entries(after)) {
    if (!(key in before)) {
      const wildcard = gainedWildcard(key, undefined, parseStored(afterStored));
      const shown = pair(key, undefined, afterStored);
      out.push({
        source,
        key,
        change: 'config-key-added',
        severity: severityFor(key, wildcard),
        ...(shown.after !== undefined ? { after: shown.after } : {}),
        reason: shown.secret ? `key added; value ${REDACTED}` : 'key was not set at approval',
      });
    }
  }
  for (const [key, beforeStored] of Object.entries(before)) {
    if (!(key in after)) {
      if (!isRestriction(key)) continue;
      const shown = pair(key, beforeStored, undefined);
      out.push({
        source,
        key,
        change: 'restriction-removed',
        severity: severityFor(key, false),
        ...(shown.before !== undefined ? { before: shown.before } : {}),
        reason: shown.secret ? `restriction removed; value ${REDACTED}` : 'restriction removed',
      });
      continue;
    }
    const afterStored = after[key] as string;
    if (beforeStored === afterStored) continue;
    const prev = parseStored(beforeStored);
    const next = parseStored(afterStored);
    if (!isRestriction(key) || !loosened(key, prev, next)) continue;
    const shown = pair(key, beforeStored, afterStored);
    out.push({
      source,
      key,
      change: 'restriction-loosened',
      severity: severityFor(key, gainedWildcard(key, prev, next)),
      ...(shown.before !== undefined ? { before: shown.before } : {}),
      ...(shown.after !== undefined ? { after: shown.after } : {}),
      reason: shown.secret ? `restriction loosened; value ${REDACTED}` : 'restriction loosened',
    });
  }
  return out.sort((a, b) => a.key.localeCompare(b.key) || a.change.localeCompare(b.change));
}

/** sha256 over config keys (secret values redacted), env names, and extra lines. */
export function fingerprintConfig(
  keys: Record<string, string>,
  envNames: readonly string[],
  extra: readonly string[] = [],
): string {
  const lines: string[] = [];
  for (const key of Object.keys(keys).sort()) {
    const stored = keys[key] ?? '';
    lines.push(`${key}=${storedIsSecret(key, stored) ? REDACTED : stored}`);
  }
  lines.push(`env:${[...envNames].sort().join(',')}`);
  lines.push(...[...extra].sort());
  return createHash('sha256').update(lines.join('\n')).digest('hex');
}
