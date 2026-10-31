/**
 * Approval ledger and drift (rug-pull) detection.
 *
 * `approve` records what you looked at: every file hash of each skill, the SKILL.md
 * description, the hosts the skill text names and the credential paths it names, plus
 * optional MCP server entries and MCP tool descriptions (`tools/list` output).
 * `check` compares the current state with that record. Local only: no network.
 */
import { createHash } from 'node:crypto';
import { readdir, readFile, lstat } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import { UsageError } from '../core/errors.ts';
import { isCredentialPath } from '../guard/signals.ts';
import { writeAtomic } from '../util/atomic.ts';
import { TOOL_VERSION } from '../version.ts';
import {
  collectConfigKeys,
  diffConfigKeys,
  mcpServerConfigKeys,
  type ConfigKeyChange,
} from './config-keys.ts';

const MAX_FILE = 1048576;
const SKIP_DIRS = new Set(['.git', 'node_modules']);

const SkillRecordSchema = z
  .object({
    root: z.string(),
    approvedAt: z.string(),
    files: z.record(z.string(), z.string()),
    description: z.string(),
    hosts: z.array(z.string()),
    credentialPaths: z.array(z.string()),
    /** Flattened config keys. Absent on ledgers written before 0.22.0. */
    configKeys: z.record(z.string(), z.string()).optional(),
  })
  .strict();

const ItemRecordSchema = z
  .object({
    key: z.string(),
    source: z.string(),
    approvedAt: z.string(),
    sha256: z.string(),
    /** Flattened MCP server keys. Absent on ledgers written before 0.22.0. */
    configKeys: z.record(z.string(), z.string()).optional(),
  })
  .strict();

export const LedgerSchema = z
  .object({
    version: z.literal(1),
    toolVersion: z.string(),
    skills: z.record(z.string(), SkillRecordSchema),
    mcpServers: z.record(z.string(), ItemRecordSchema),
    mcpTools: z.record(z.string(), ItemRecordSchema),
  })
  .strict();

export type Ledger = z.infer<typeof LedgerSchema>;
export type SkillRecord = z.infer<typeof SkillRecordSchema>;

export interface DriftChange {
  kind:
    | 'file-added'
    | 'file-removed'
    | 'file-changed'
    | 'description-changed'
    | 'new-host'
    | 'new-credential-path'
    | 'skill-unapproved'
    | 'skill-missing'
    | 'mcp-server-changed'
    | 'mcp-server-added'
    | 'mcp-tool-changed'
    | 'mcp-tool-added'
    | 'config-key-added'
    | 'restriction-removed'
    | 'restriction-loosened'
    | 'config-keys-unrecorded';
  severity: 'info' | 'medium' | 'high';
  target: string;
  detail: string;
}

export function emptyLedger(): Ledger {
  return { version: 1, toolVersion: TOOL_VERSION, skills: {}, mcpServers: {}, mcpTools: {} };
}

export async function readLedger(path: string): Promise<Ledger> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    return emptyLedger();
  }
  const parsed = LedgerSchema.safeParse(JSON.parse(raw));
  if (!parsed.success) throw new UsageError(`approval ledger is not valid: ${path}`);
  return parsed.data;
}

export async function writeLedger(path: string, ledger: Ledger): Promise<void> {
  await writeAtomic(path, JSON.stringify({ ...ledger, toolVersion: TOOL_VERSION }, null, 2) + '\n');
}

const sha = (data: string | Buffer): string => createHash('sha256').update(data).digest('hex');

async function walk(root: string, out: Record<string, string>, texts: string[]): Promise<void> {
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
      const abs = join(dir, e.name);
      const rel = relative(root, abs).split(sep).join('/');
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(abs);
        continue;
      }
      if (e.isSymbolicLink()) {
        out[rel] = 'symlink';
        continue;
      }
      if (!e.isFile()) continue;
      const info = await lstat(abs);
      if (info.size > MAX_FILE) {
        out[rel] = `oversize:${info.size}`;
        continue;
      }
      const buf = await readFile(abs);
      out[rel] = sha(buf);
      if (!buf.subarray(0, 8000).includes(0)) texts.push(buf.toString('utf8'));
    }
  }
}

export function extractHosts(text: string): string[] {
  const hosts = new Set<string>();
  for (const m of text.matchAll(/\b(?:https?|wss?|ftp):\/\/([a-z0-9.-]+|\[[0-9a-f:]+\])/gi)) {
    hosts.add((m[1] as string).toLowerCase().replace(/\.$/, ''));
  }
  return [...hosts].sort();
}

export function extractCredentialPaths(text: string): string[] {
  const found = new Set<string>();
  for (const raw of text.split(/[\s'"`()<>,;|=]+/)) {
    const token = raw.replace(/[.:]+$/, '');
    if (token.length < 3 || token.length > 200) continue;
    if (!/[/~]|^\.env/.test(token) || /^[a-z]+:\/\//i.test(token)) continue;
    if (isCredentialPath(token.replace(/^\$HOME/, '~'))) found.add(token);
  }
  return [...found].sort();
}

export function skillDescription(text: string): string {
  const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!fm) return '';
  const line = /^description:\s*(.*)$/m.exec(fm[1] as string);
  return line ? (line[1] as string).trim().replace(/^['"]|['"]$/g, '') : '';
}

export async function snapshotSkill(root: string, now = new Date()): Promise<SkillRecord> {
  const abs = resolve(root);
  const files: Record<string, string> = {};
  const texts: string[] = [];
  await walk(abs, files, texts);
  let description = '';
  try {
    description = skillDescription(await readFile(join(abs, 'SKILL.md'), 'utf8'));
  } catch {
    description = '';
  }
  const all = texts.join('\n');
  return {
    root: abs,
    approvedAt: now.toISOString(),
    files,
    description,
    hosts: extractHosts(all),
    credentialPaths: extractCredentialPaths(all),
    configKeys: await collectConfigKeys(abs),
  };
}

function itemsFromMcpConfig(path: string, data: unknown): Array<[string, string]> {
  const obj = (data ?? {}) as Record<string, unknown>;
  const servers = (obj.mcpServers ??
    obj.servers ??
    (obj.mcp as Record<string, unknown>)?.servers) as Record<string, unknown> | undefined;
  if (!servers || typeof servers !== 'object') return [];
  return Object.entries(servers).map(([name, def]) => [`${path}#${name}`, stable(def)]);
}

function itemsFromToolsList(path: string, data: unknown): Array<[string, string]> {
  const obj = data as { tools?: unknown; result?: { tools?: unknown } } | unknown[];
  const tools = (Array.isArray(obj) ? obj : (obj?.tools ?? obj?.result?.tools)) as unknown;
  if (!Array.isArray(tools)) return [];
  return tools
    .filter((t): t is { name: string } => typeof (t as { name?: unknown })?.name === 'string')
    .map((t) => [`${path}#${t.name}`, stable(t)]);
}

/** Key-order independent JSON, so reformatting a file is not drift. */
export function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stable((value as Record<string, unknown>)[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

export async function readJsonItems(
  path: string,
  kind: 'mcp' | 'tools',
): Promise<Array<[string, string]>> {
  const abs = resolve(path);
  let data: unknown;
  try {
    data = JSON.parse(await readFile(abs, 'utf8'));
  } catch {
    throw new UsageError(`cannot read JSON: ${path}`);
  }
  return kind === 'mcp' ? itemsFromMcpConfig(abs, data) : itemsFromToolsList(abs, data);
}

export interface McpDriftItem {
  key: string;
  body: string;
  configKeys: Record<string, string>;
}

/** MCP server entries with a stable body hash and flattened config keys. */
export async function readMcpDriftItems(path: string): Promise<McpDriftItem[]> {
  const abs = resolve(path);
  let data: unknown;
  try {
    data = JSON.parse(await readFile(abs, 'utf8'));
  } catch {
    throw new UsageError(`cannot read JSON: ${path}`);
  }
  const obj = (data ?? {}) as Record<string, unknown>;
  const servers = (obj.mcpServers ??
    obj.servers ??
    (obj.mcp as Record<string, unknown> | undefined)?.servers) as
    | Record<string, unknown>
    | undefined;
  if (!servers || typeof servers !== 'object') return [];
  return Object.entries(servers).map(([name, def]) => ({
    key: `${abs}#${name}`,
    body: stable(def),
    configKeys: mcpServerConfigKeys(def),
  }));
}

export function diffSkill(before: SkillRecord, after: SkillRecord): DriftChange[] {
  const changes: DriftChange[] = [];
  const t = before.root;
  for (const [file, hash] of Object.entries(after.files)) {
    if (!(file in before.files))
      changes.push({ kind: 'file-added', severity: 'medium', target: t, detail: file });
    else if (before.files[file] !== hash)
      changes.push({ kind: 'file-changed', severity: 'medium', target: t, detail: file });
  }
  for (const file of Object.keys(before.files)) {
    if (!(file in after.files))
      changes.push({ kind: 'file-removed', severity: 'info', target: t, detail: file });
  }
  if (before.description !== after.description) {
    changes.push({
      kind: 'description-changed',
      severity: 'high',
      target: t,
      detail: `"${before.description}" -> "${after.description}"`,
    });
  }
  const oldHosts = new Set(before.hosts);
  for (const h of after.hosts)
    if (!oldHosts.has(h))
      changes.push({ kind: 'new-host', severity: 'high', target: t, detail: h });
  const oldPaths = new Set(before.credentialPaths);
  for (const p of after.credentialPaths)
    if (!oldPaths.has(p))
      changes.push({ kind: 'new-credential-path', severity: 'high', target: t, detail: p });
  return changes;
}

export interface DriftReport {
  checkedAt: string;
  changes: DriftChange[];
  /** Config-key drift. Empty when nothing moved and a baseline was recorded. */
  configKeys: ConfigKeyChange[];
  /** Worst of `changes`: high is block, medium is warn, otherwise ok. */
  decision: 'block' | 'warn' | 'ok';
}

export function driftDecision(changes: DriftChange[]): DriftReport['decision'] {
  if (changes.some((c) => c.severity === 'high')) return 'block';
  if (changes.some((c) => c.severity === 'medium')) return 'warn';
  return 'ok';
}

const KEY_SEVERITY = { block: 'high', warn: 'medium', info: 'info' } as const;

export function configKeyChanges(items: ConfigKeyChange[]): DriftChange[] {
  return items.map((item) => ({
    kind: item.change,
    severity: KEY_SEVERITY[item.severity],
    target: item.source,
    detail: configKeyDetail(item),
  }));
}

function configKeyDetail(item: ConfigKeyChange): string {
  if (item.change === 'config-keys-unrecorded') return item.reason;
  const parts = [item.key, item.reason];
  if (item.before !== undefined) parts.push(`before ${item.before}`);
  if (item.after !== undefined) parts.push(`after ${item.after}`);
  return parts.join(' ');
}

export { diffConfigKeys, mcpServerConfigKeys };
export type { ConfigKeyChange };

export function exitCodeFor(changes: DriftChange[]): number {
  if (changes.some((c) => c.severity === 'high')) return 2;
  if (changes.some((c) => c.severity === 'medium')) return 1;
  return 0;
}
