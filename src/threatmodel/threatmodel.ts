/**
 * Agent threat model as code (`ironheights.threatmodel.yml`).
 *
 * The model lists the skills and MCP servers a repository trusts and what each one may
 * touch: network hosts, filesystem paths, environment variables, secrets (tokens), shell,
 * and a minimum Ironheights grade. `check` profiles what the skills in the repository
 * actually reference and reports everything outside the model. Local only: no network.
 */
import { readFile } from 'node:fs/promises';
import { basename, dirname, relative, resolve, sep } from 'node:path';
import picomatch from 'picomatch';
import YAML from 'yaml';
import { z } from 'zod';
import { UsageError } from '../core/errors.ts';
import { snapshotSkill, stable, type SkillRecord } from '../drift/drift.ts';

export const MODEL_FILE = 'ironheights.threatmodel.yml';
export const SCHEMA_URL = 'https://www.ironheights.dev/api/v1/threatmodel.schema.json';

const GRADES = ['A', 'B', 'C', 'D', 'F'] as const;
export type Letter = (typeof GRADES)[number];

const SkillEntry = z
  .object({
    path: z.string().min(1).describe('Skill directory, relative to the model file.'),
    owner: z.string().optional(),
    purpose: z.string().optional(),
    network: z.array(z.string()).default([]),
    filesystem: z.array(z.string()).default([]),
    env: z.array(z.string()).default([]),
    tokens: z.array(z.string()).default([]),
    shell: z.boolean().default(false),
    minGrade: z.enum(GRADES).optional(),
    dataBoundaries: z.array(z.string()).default([]),
    /** When true, the built-in remote-instructions claim allows IH-INJ-004. */
    remoteInstructions: z.boolean().optional(),
  })
  .strict();

const McpEntry = z
  .object({
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    url: z.string().optional(),
    env: z.array(z.string()).default([]),
    tools: z.array(z.string()).optional(),
    purpose: z.string().optional(),
  })
  .strict();

export const ThreatModelSchema = z
  .object({
    $schema: z.string().optional(),
    version: z.literal(1),
    name: z.string().optional(),
    skillDirs: z.array(z.string()).default(['skills']),
    mcpConfigs: z.array(z.string()).default([]),
    defaults: z
      .object({
        unknownSkill: z.enum(['deny', 'warn']).default('deny'),
        unknownMcpServer: z.enum(['deny', 'warn']).default('deny'),
        minGrade: z.enum(GRADES).optional(),
        /** `report` lists uncovered capabilities; `fail` makes them high violations. */
        uncovered: z.enum(['report', 'fail']).default('report'),
        /**
         * Built-in remote-instructions claim (IH-INJ-004).
         * `report` is info (exit unchanged), `warn` is medium, `deny` is high.
         */
        remoteInstructions: z.enum(['report', 'warn', 'deny']).default('report'),
      })
      .strict()
      .default({
        unknownSkill: 'deny',
        unknownMcpServer: 'deny',
        uncovered: 'report',
        remoteInstructions: 'report',
      }),
    skills: z.record(z.string(), SkillEntry).default({}),
    mcpServers: z.record(z.string(), McpEntry).default({}),
  })
  .strict();

export type ThreatModel = z.infer<typeof ThreatModelSchema>;
export type SkillEntryT = z.infer<typeof SkillEntry>;

export type ViolationKind =
  | 'unknown-skill'
  | 'skill-missing'
  | 'host-not-allowed'
  | 'path-not-allowed'
  | 'env-not-allowed'
  | 'token-not-allowed'
  | 'shell-not-allowed'
  | 'grade-below-minimum'
  | 'unknown-mcp-server'
  | 'mcp-command-changed'
  | 'mcp-env-not-allowed'
  | 'mcp-tool-not-allowed'
  | 'drift'
  | 'model-widened'
  | 'uncovered-capability'
  | 'remote-instructions';

export interface Violation {
  kind: ViolationKind;
  severity: 'info' | 'medium' | 'high';
  target: string;
  detail: string;
  /** Repository-relative file to point SARIF and PR comments at. */
  file?: string;
}

export interface SkillProfile {
  key: string;
  root: string;
  name: string;
  hosts: string[];
  paths: string[];
  env: string[];
  tokens: string[];
  shell: boolean;
  /** Webhook-shaped URL host/path values named in the skill text. */
  webhooks: string[];
  grade?: Letter | 'incomplete' | 'nothing-scanned';
  /** Set when the skill scan reports IH-INJ-004. */
  remoteInstructionsHit?: boolean;
}

export async function loadModel(path: string): Promise<ThreatModel> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    throw new UsageError(
      `threat model not found: ${path} (create one with: ironheights threatmodel init)`,
    );
  }
  return parseModel(raw, path);
}

export function parseModel(raw: string, label = MODEL_FILE): ThreatModel {
  let data: unknown;
  try {
    data = YAML.parse(raw);
  } catch (error) {
    throw new UsageError(`${label}: invalid YAML (${(error as Error).message})`);
  }
  const parsed = ThreatModelSchema.safeParse(data);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    throw new UsageError(
      `${label}: ${first ? `${first.path.join('.') || '(root)'}: ${first.message}` : 'invalid'}`,
    );
  }
  return parsed.data;
}

/* ---------------- profiling ---------------- */

const COMMON_ENV = new Set([
  'HOME',
  'PATH',
  'PWD',
  'USER',
  'SHELL',
  'TMPDIR',
  'TEMP',
  'TMP',
  'LANG',
  'TERM',
  'NODE_ENV',
  'CI',
  'LOGNAME',
  'HOSTNAME',
  'OLDPWD',
  'EDITOR',
  'XDG_CONFIG_HOME',
  'XDG_DATA_HOME',
]);
const SECRET_NAME = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|AUTH|CREDENTIAL|COOKIE|SESSION)/;

export function isSecretName(name: string): boolean {
  return SECRET_NAME.test(name);
}

export function extractEnv(text: string): string[] {
  const names = new Set<string>();
  const patterns = [
    /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
    /process\.env\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]/g,
    /os\.environ\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]/g,
    /os\.(?:getenv|environ\.get)\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g,
    /Deno\.env\.get\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g,
    /\$\{([A-Z][A-Z0-9_]{1,})(?::?[-=?+][^}]*)?\}/g,
    /(?<![\w$])\$([A-Z][A-Z0-9_]{2,})\b/g,
  ];
  for (const re of patterns) for (const m of text.matchAll(re)) names.add(m[1] as string);
  return [...names].filter((n) => !COMMON_ENV.has(n)).sort();
}

const SHELL_PATTERNS = [
  /\bchild_process\b/,
  /\b(?:execSync|execFileSync|spawnSync)\s*\(/,
  /\bsubprocess\.(?:run|call|Popen|check_output|check_call)\b/,
  /\bos\.(?:system|popen)\s*\(/,
  /\bRuntime\.getRuntime\(\)\.exec\b/,
  /\bBun\.spawn\b/,
  /\bDeno\.(?:run|Command)\b/,
  /```(?:bash|sh|shell|zsh|console)\b/,
  /\b(?:curl|wget)\s+[^\n|]*\|\s*(?:ba|z)?sh\b/,
];

export function usesShell(text: string): boolean {
  return SHELL_PATTERNS.some((re) => re.test(text));
}

const PATH_TOKEN =
  /(?:^|[\s'"`(=,])((?:~|\$HOME|\/(?:etc|var|home|Users|root|opt|private|tmp|proc|sys|dev))\/[^\s'"`),;|<>]*)/g;

export function extractPaths(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(PATH_TOKEN)) {
    const p = (m[1] as string).replace(/^\$HOME/, '~').replace(/[.:]+$/, '');
    if (p.length >= 3 && p.length <= 200 && !/^\/(?:dev\/null|tmp\/?$)/.test(p)) out.add(p);
  }
  return [...out].sort();
}

async function textsOf(record: SkillRecord): Promise<string> {
  const parts: string[] = [];
  for (const [rel, hash] of Object.entries(record.files)) {
    if (hash === 'symlink' || hash.startsWith('oversize:')) continue;
    try {
      const buf = await readFile(resolve(record.root, rel));
      if (!buf.subarray(0, 8000).includes(0)) parts.push(buf.toString('utf8'));
    } catch {
      /* unreadable: skip */
    }
  }
  return parts.join('\n');
}

function nameFromSkill(text: string, root: string): string {
  const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  const line = fm ? /^name:\s*(.*)$/m.exec(fm[1] as string) : null;
  return line ? (line[1] as string).trim().replace(/^['"]|['"]$/g, '') : basename(root);
}

export async function profileSkill(root: string, base: string): Promise<SkillProfile> {
  const record = await snapshotSkill(root);
  const all = await textsOf(record);
  let skillMd = '';
  try {
    skillMd = await readFile(resolve(record.root, 'SKILL.md'), 'utf8');
  } catch {
    /* no SKILL.md */
  }
  const env = extractEnv(all);
  const paths = new Set([
    ...extractPaths(all),
    ...record.credentialPaths.map((p) => p.replace(/^\$HOME/, '~')),
  ]);
  return {
    key: toPosix(relative(base, record.root)) || '.',
    root: record.root,
    name: nameFromSkill(skillMd, record.root),
    hosts: record.hosts,
    paths: [...paths].sort(),
    env: env.filter((n) => !isSecretName(n)),
    tokens: env.filter(isSecretName),
    shell: usesShell(all),
    webhooks: extractWebhooks(all),
  };
}

const WEBHOOK_URL = /https?:\/\/[^\s)'"`<>]+/gi;

/** Hosts and paths that look like a webhook: hooks.slack.com, discord.com/api/webhooks, or a webhook path. */
export function extractWebhooks(text: string): string[] {
  const out = new Set<string>();
  for (const raw of text.matchAll(WEBHOOK_URL)) {
    const cleaned = raw[0].replace(/[.,);]+$/, '');
    let url: URL;
    try {
      url = new URL(cleaned);
    } catch {
      continue;
    }
    const host = url.hostname.toLowerCase();
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const webhook =
      host === 'hooks.slack.com' ||
      ((host === 'discord.com' || host === 'discordapp.com') && path.includes('/api/webhooks')) ||
      /webhook/i.test(host) ||
      /\/webhooks?(?:\/|$)/i.test(path);
    if (!webhook) continue;
    out.add(path === '/' ? host : `${host}${path}`);
  }
  return [...out].sort();
}

export const toPosix = (p: string): string => p.split(sep).join('/');

/* ---------------- matching ---------------- */

export function hostAllowed(host: string, allowed: string[]): boolean {
  const h = host.toLowerCase();
  return allowed.some((a) => {
    const p = a.toLowerCase().trim();
    if (p === '*') return true;
    if (p.startsWith('*.')) return h === p.slice(2) || h.endsWith(p.slice(1));
    return h === p;
  });
}

export function pathAllowed(path: string, allowed: string[]): boolean {
  const norm = path.replace(/^\$HOME/, '~').replace(/\/+$/, '');
  return allowed.some((a) => {
    const g = a.replace(/^\$HOME/, '~').replace(/\/+$/, '');
    return norm === g || picomatch(g, { dot: true })(norm) || norm.startsWith(g + '/');
  });
}

export function nameAllowed(name: string, allowed: string[]): boolean {
  return allowed.some((a) => a === name || (a.includes('*') && picomatch(a)(name)));
}

const rank = (g: string): number => (GRADES as readonly string[]).indexOf(g);

/* ---------------- checking ---------------- */

export interface McpServerDef {
  key: string;
  file: string;
  name: string;
  command?: string;
  args?: string[];
  url?: string;
  env: string[];
}

export async function readMcpServers(file: string, base: string): Promise<McpServerDef[]> {
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
  } catch {
    return [];
  }
  const servers = (data.mcpServers ??
    data.servers ??
    (data.mcp as Record<string, unknown> | undefined)?.servers) as
    | Record<string, unknown>
    | undefined;
  if (!servers || typeof servers !== 'object') return [];
  return Object.entries(servers).map(([name, raw]) => {
    const def = (raw ?? {}) as Record<string, unknown>;
    return {
      key: name,
      file: toPosix(relative(base, file)),
      name,
      ...(typeof def.command === 'string' ? { command: def.command } : {}),
      ...(Array.isArray(def.args) ? { args: def.args.map(String) } : {}),
      ...(typeof def.url === 'string' ? { url: def.url } : {}),
      env: def.env && typeof def.env === 'object' ? Object.keys(def.env).sort() : [],
    };
  });
}

export interface CheckInput {
  model: ThreatModel;
  base: string;
  profiles: SkillProfile[];
  mcp: McpServerDef[];
  modelFile: string;
}

export function evaluate(input: CheckInput): Violation[] {
  const { model, profiles, mcp, modelFile } = input;
  const v: Violation[] = [];
  const byPath = new Map<string, [string, SkillEntryT]>();
  for (const [id, entry] of Object.entries(model.skills)) {
    byPath.set(toPosix(entry.path).replace(/^\.\//, '').replace(/\/+$/, ''), [id, entry]);
  }
  const seen = new Set<string>();
  for (const p of profiles) {
    const hit = byPath.get(p.key);
    const file = `${p.key}/SKILL.md`;
    if (!hit) {
      v.push({
        kind: 'unknown-skill',
        severity: model.defaults.unknownSkill === 'deny' ? 'high' : 'medium',
        target: p.key,
        detail: `skill "${p.name}" is not in ${modelFile}`,
        file,
      });
      continue;
    }
    const [id, e] = hit;
    seen.add(p.key);
    const t = `${id} (${p.key})`;
    for (const h of p.hosts)
      if (!hostAllowed(h, e.network))
        v.push({ kind: 'host-not-allowed', severity: 'high', target: t, detail: h, file });
    for (const fp of p.paths)
      if (!pathAllowed(fp, e.filesystem))
        v.push({ kind: 'path-not-allowed', severity: 'high', target: t, detail: fp, file });
    for (const n of p.env)
      if (!nameAllowed(n, e.env) && !nameAllowed(n, e.tokens))
        v.push({ kind: 'env-not-allowed', severity: 'medium', target: t, detail: n, file });
    for (const n of p.tokens)
      if (!nameAllowed(n, e.tokens))
        v.push({ kind: 'token-not-allowed', severity: 'high', target: t, detail: n, file });
    if (p.shell && !e.shell)
      v.push({
        kind: 'shell-not-allowed',
        severity: 'high',
        target: t,
        detail: 'skill runs shell commands or child processes',
        file,
      });
    const min = e.minGrade ?? model.defaults.minGrade;
    if (min && p.grade && p.grade !== 'nothing-scanned') {
      if (p.grade === 'incomplete' || rank(p.grade) > rank(min))
        v.push({
          kind: 'grade-below-minimum',
          severity: 'high',
          target: t,
          detail: `grade ${p.grade}, model requires ${min} or better`,
          file,
        });
    }
  }
  for (const [id, e] of Object.entries(model.skills)) {
    const key = toPosix(e.path).replace(/^\.\//, '').replace(/\/+$/, '');
    if (!seen.has(key) && !profiles.some((p) => p.key === key))
      v.push({
        kind: 'skill-missing',
        severity: 'info',
        target: id,
        detail: `listed in the model but not found at ${key}`,
        file: modelFile,
      });
  }
  for (const s of mcp) {
    const allowed = model.mcpServers[s.name];
    if (!allowed) {
      v.push({
        kind: 'unknown-mcp-server',
        severity: model.defaults.unknownMcpServer === 'deny' ? 'high' : 'medium',
        target: s.name,
        detail: `MCP server in ${s.file} is not in ${modelFile}`,
        file: s.file,
      });
      continue;
    }
    if (
      (allowed.command !== undefined && allowed.command !== s.command) ||
      (allowed.url !== undefined && allowed.url !== s.url) ||
      (allowed.args !== undefined && stable(allowed.args) !== stable(s.args ?? []))
    )
      v.push({
        kind: 'mcp-command-changed',
        severity: 'high',
        target: s.name,
        detail: `runs ${[s.command, ...(s.args ?? [])].filter(Boolean).join(' ') || s.url}, model allows ${[allowed.command, ...(allowed.args ?? [])].filter(Boolean).join(' ') || allowed.url}`,
        file: s.file,
      });
    for (const n of s.env)
      if (!nameAllowed(n, allowed.env))
        v.push({
          kind: 'mcp-env-not-allowed',
          severity: 'high',
          target: s.name,
          detail: n,
          file: s.file,
        });
  }
  return v;
}

/** Compare two models and report every permission the head model adds. */
export function widened(base: ThreatModel, head: ThreatModel, modelFile: string): Violation[] {
  const v: Violation[] = [];
  const add = (target: string, detail: string): void => {
    v.push({ kind: 'model-widened', severity: 'info', target, detail, file: modelFile });
  };
  for (const [id, h] of Object.entries(head.skills)) {
    const b = base.skills[id];
    if (!b) {
      add(id, `new trusted skill at ${h.path}`);
      continue;
    }
    for (const k of ['network', 'filesystem', 'env', 'tokens', 'dataBoundaries'] as const)
      for (const x of h[k]) if (!b[k].includes(x)) add(id, `${k} += ${x}`);
    if (h.shell && !b.shell) add(id, 'shell: false -> true');
    const bg = b.minGrade ?? base.defaults.minGrade;
    const hg = h.minGrade ?? head.defaults.minGrade;
    if (bg && (!hg || rank(hg) > rank(bg))) add(id, `minGrade ${bg} -> ${hg ?? 'none'}`);
  }
  for (const [id, h] of Object.entries(head.mcpServers)) {
    const b = base.mcpServers[id];
    if (!b) add(`mcp:${id}`, 'new trusted MCP server');
    else {
      for (const x of h.env) if (!b.env.includes(x)) add(`mcp:${id}`, `env += ${x}`);
      if (stable(b) !== stable(h) && h.command !== b.command)
        add(`mcp:${id}`, `command ${b.command} -> ${h.command}`);
    }
  }
  if (base.defaults.unknownSkill === 'deny' && head.defaults.unknownSkill === 'warn')
    add('defaults', 'unknownSkill deny -> warn');
  if (base.defaults.unknownMcpServer === 'deny' && head.defaults.unknownMcpServer === 'warn')
    add('defaults', 'unknownMcpServer deny -> warn');
  const remoteRank = { deny: 0, warn: 1, report: 2 } as const;
  const br = base.defaults.remoteInstructions;
  const hr = head.defaults.remoteInstructions;
  if (remoteRank[hr] > remoteRank[br]) add('defaults', `remoteInstructions ${br} -> ${hr}`);
  if (base.defaults.uncovered === 'fail' && head.defaults.uncovered === 'report')
    add('defaults', 'uncovered fail -> report');
  return v;
}

export function exitCodeFor(v: Violation[]): number {
  if (v.some((x) => x.severity === 'high')) return 2;
  if (v.some((x) => x.severity === 'medium')) return 1;
  return 0;
}

/* ---------------- init ---------------- */

export function modelFromProfiles(
  profiles: SkillProfile[],
  mcp: McpServerDef[],
  opts: { skillDirs: string[]; mcpConfigs: string[]; name?: string },
): ThreatModel {
  const skills: ThreatModel['skills'] = {};
  for (const p of profiles) {
    let id = p.name.replace(/[^A-Za-z0-9_.-]+/g, '-') || 'skill';
    while (skills[id]) id += '-2';
    skills[id] = {
      path: p.key,
      network: p.hosts,
      filesystem: p.paths,
      env: p.env,
      tokens: p.tokens,
      shell: p.shell,
      ...(p.grade && (GRADES as readonly string[]).includes(p.grade)
        ? { minGrade: p.grade as Letter }
        : {}),
      dataBoundaries: [],
    };
  }
  const mcpServers: ThreatModel['mcpServers'] = {};
  for (const s of mcp)
    mcpServers[s.name] = {
      ...(s.command ? { command: s.command } : {}),
      ...(s.args ? { args: s.args } : {}),
      ...(s.url ? { url: s.url } : {}),
      env: s.env,
    };
  return {
    $schema: SCHEMA_URL,
    version: 1,
    ...(opts.name ? { name: opts.name } : {}),
    skillDirs: opts.skillDirs,
    mcpConfigs: opts.mcpConfigs,
    defaults: {
      unknownSkill: 'deny',
      unknownMcpServer: 'deny',
      uncovered: 'report',
      remoteInstructions: 'report',
    },
    skills,
    mcpServers,
  };
}

export function renderModelYaml(model: ThreatModel): string {
  const header = [
    '# Ironheights agent threat model. Checked on every PR by `ironheights threatmodel check`.',
    '# Each skill and MCP server lists what it may touch. Anything else fails the check.',
    `# Schema: ${SCHEMA_URL}`,
    '# Docs: https://www.ironheights.dev/docs/threatmodel/',
    '',
  ].join('\n');
  return header + YAML.stringify(model, { lineWidth: 100 });
}

export function modelDir(modelPath: string): string {
  return dirname(resolve(modelPath));
}
