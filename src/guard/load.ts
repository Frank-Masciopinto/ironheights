import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import { z } from 'zod';
import { ironheightsHome, loadConfig } from '../core/config.ts';
import { BUILTIN_ALLOW_DOMAINS } from '../core/domains.ts';
import { locateOpenClaw } from '../openclaw/locate.ts';
import { parseSkillMarkdown } from '../openclaw/skill.ts';
import type { GuardAllow, GuardLogOptions, GuardMode, ResolvedGuardPolicy } from './types.ts';
import {
  DEFAULT_LOG_MAX_BYTES,
  DEFAULT_LOG_MAX_FILES,
  GUARD_LOG_NAME,
  GUARD_POLICY_NAME,
} from './types.ts';

const ruleSchema = z.enum(['IH-GUARD-CRED', 'IH-GUARD-EXEC', 'IH-GUARD-NET', 'IH-GUARD-WRITE']);

const allowSchema = z
  .object({
    id: z.string().min(1).max(80),
    reason: z.string().min(1).max(300),
    rule: ruleSchema.optional(),
    tool: z.string().min(1).max(80).optional(),
    skill: z.string().min(1).max(80).optional(),
    path: z.string().min(1).max(300).optional(),
    host: z.string().min(1).max(253).optional(),
  })
  .strict();

export const GuardPolicySchema = z
  .object({
    version: z.literal(1),
    mode: z.enum(['monitor', 'enforce']).optional(),
    allowDomains: z.array(z.string()).optional(),
    skills: z
      .record(z.string(), z.object({ allowDomains: z.array(z.string()) }).strict())
      .optional(),
    allow: z.array(allowSchema).optional(),
    log: z
      .object({
        maxBytes: z.number().int().min(4096).max(50_000_000).optional(),
        maxFiles: z.number().int().min(1).max(20).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export type GuardPolicyFile = z.infer<typeof GuardPolicySchema>;

export interface LoadedGuard {
  ok: boolean;
  message?: string;
  policy: ResolvedGuardPolicy;
  log: GuardLogOptions;
  modeSource: 'default' | 'policy' | 'override';
  policyPath: string;
  configWarning?: string;
}

export interface LoadGuardOptions {
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  policyPath?: string;
  configPath?: string;
  homeDir?: string;
  modeOverride?: GuardMode;
  skillDeclaredDomains?: Record<string, string[]>;
}

export async function loadGuardRuntime(options: LoadGuardOptions = {}): Promise<LoadedGuard> {
  const env = options.env ?? process.env;
  const policyPath =
    options.policyPath ??
    env.IRONHEIGHTS_GUARD_POLICY ??
    join(ironheightsHome(env), GUARD_POLICY_NAME);
  const parsed = await readPolicyFile(policyPath);
  const located = await safeLocate(env);
  const configured = await safeConfig(options);
  const file = parsed.file;
  const mode = resolveMode(file?.mode, options.modeOverride);
  const domains = uniqueHosts([
    ...BUILTIN_ALLOW_DOMAINS,
    ...(configured.allowDomains ?? [...BUILTIN_ALLOW_DOMAINS]),
    ...(file ? hostsFrom(file.allowDomains ?? []) : []),
  ]);
  const skills: Record<string, { allowDomains: string[] }> = {};
  if (file?.skills) {
    for (const [name, entry] of Object.entries(file.skills)) {
      skills[name] = { allowDomains: hostsFrom(entry.allowDomains) };
    }
  }
  const policy: ResolvedGuardPolicy = {
    mode: mode.mode,
    globalAllowDomains: domains,
    skills,
    skillDeclaredDomains: options.skillDeclaredDomains ?? {},
    allow: file ? normalizeAllows(file.allow ?? []) : [],
    protectedPaths: located.agentFiles,
    skillDirs: located.skillDirs,
    homeDir: options.homeDir ?? homedir(),
    stateDir: located.stateDir,
    workspaceDir: located.workspaceDir,
  };
  const log: GuardLogOptions = {
    path: join(ironheightsHome(env), GUARD_LOG_NAME),
    maxBytes: file?.log?.maxBytes ?? DEFAULT_LOG_MAX_BYTES,
    maxFiles: file?.log?.maxFiles ?? DEFAULT_LOG_MAX_FILES,
  };
  return {
    ok: parsed.ok && configured.ok && located.ok,
    ...(parsed.message || configured.message
      ? { message: [parsed.message, configured.message].filter(Boolean).join(' ') }
      : {}),
    policy,
    log,
    modeSource: mode.source,
    policyPath,
  };
}

export function parseGuardPolicy(
  value: unknown,
): { ok: true; file: GuardPolicyFile } | { ok: false; message: string } {
  const result = GuardPolicySchema.safeParse(value);
  if (!result.success) {
    const issue = result.error.issues[0];
    const path = issue?.path.join('.') || '(root)';
    return {
      ok: false,
      message: `invalid guard policy at ${path}: ${issue?.message ?? 'unknown error'}`,
    };
  }
  const file = result.data;
  const ids = new Set<string>();
  for (const entry of file.allow ?? []) {
    if (ids.has(entry.id)) {
      return { ok: false, message: `invalid guard policy: duplicate allow id ${entry.id}` };
    }
    ids.add(entry.id);
    if (!entry.rule && !entry.tool && !entry.skill && !entry.path && !entry.host) {
      return {
        ok: false,
        message: `invalid guard policy: allow ${entry.id} needs a rule, tool, skill, path, or host`,
      };
    }
    if (entry.host && !normalizeHost(entry.host)) {
      return {
        ok: false,
        message: `invalid guard policy: allow ${entry.id} host is not a hostname`,
      };
    }
    if (entry.skill && !isSkillName(entry.skill)) {
      return {
        ok: false,
        message: `invalid guard policy: allow ${entry.id} skill name is not safe to match`,
      };
    }
  }
  for (const host of file.allowDomains ?? []) {
    if (!normalizeHost(host)) {
      return {
        ok: false,
        message: `invalid guard policy: allowDomains entry "${host}" is not a hostname`,
      };
    }
  }
  for (const [name, entry] of Object.entries(file.skills ?? {})) {
    if (!isSkillName(name)) {
      return {
        ok: false,
        message: `invalid guard policy: skill name "${name}" is not safe to match`,
      };
    }
    for (const host of entry.allowDomains) {
      if (!normalizeHost(host)) {
        return {
          ok: false,
          message: `invalid guard policy: skill ${name} allowDomains entry "${host}" is not a hostname`,
        };
      }
    }
  }
  return { ok: true, file };
}

export async function skillDeclaredDomains(
  skill: string,
  skillDirs: readonly string[],
): Promise<string[]> {
  if (!isSkillName(skill)) return [];
  const hosts: string[] = [];
  for (const dir of skillDirs) {
    const candidates = [join(dir, skill, 'SKILL.md')];
    if (basename(dir) === skill) candidates.push(join(dir, 'SKILL.md'));
    for (const file of candidates) {
      let text = '';
      try {
        text = await readFile(file, 'utf8');
      } catch {
        continue;
      }
      const parsed = parseSkillMarkdown(text.slice(0, 65536));
      for (const host of parsed.allowDomains) {
        if (!hosts.includes(host)) hosts.push(host);
      }
    }
  }
  return hosts;
}

export function isSkillName(value: string): boolean {
  return /^[\w.-]{1,80}$/.test(value);
}

function resolveMode(
  fileMode: GuardMode | undefined,
  override: GuardMode | undefined,
): { mode: GuardMode; source: 'default' | 'policy' | 'override' } {
  if (override) return { mode: override, source: 'override' };
  if (fileMode) return { mode: fileMode, source: 'policy' };
  return { mode: 'monitor', source: 'default' };
}

async function readPolicyFile(
  policyPath: string,
): Promise<{ ok: boolean; file?: GuardPolicyFile; message?: string }> {
  let raw: string;
  try {
    raw = await readFile(policyPath, 'utf8');
  } catch {
    return { ok: true };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return { ok: false, message: `guard policy is not valid JSON: ${policyPath}` };
  }
  const result = parseGuardPolicy(parsed);
  if (!result.ok) return { ok: false, message: result.message };
  return { ok: true, file: result.file };
}

async function safeLocate(env: NodeJS.ProcessEnv): Promise<{
  ok: boolean;
  message?: string;
  stateDir: string;
  workspaceDir: string;
  agentFiles: string[];
  skillDirs: string[];
}> {
  try {
    const located = await locateOpenClaw(env);
    return {
      ok: true,
      stateDir: located.stateDir,
      workspaceDir: located.workspace ?? join(located.stateDir, 'workspace'),
      agentFiles: located.agentFiles,
      skillDirs: located.skillDirs.map((dir) => dir.path),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'could not locate OpenClaw paths';
    const stateDir = env.OPENCLAW_STATE_DIR ?? join(homedir(), '.openclaw');
    return {
      ok: false,
      message,
      stateDir,
      workspaceDir: join(stateDir, 'workspace'),
      agentFiles: [],
      skillDirs: [],
    };
  }
}

async function safeConfig(
  options: LoadGuardOptions,
): Promise<{ ok: boolean; allowDomains?: string[]; message?: string }> {
  try {
    const config = await loadConfig({
      ...(options.cwd ? { cwd: options.cwd } : {}),
      ...(options.configPath ? { explicitPath: options.configPath } : {}),
      ...(options.env ? { env: options.env } : {}),
    });
    return { ok: true, allowDomains: config.allowDomains };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'could not read ironheights config';
    return { ok: false, message };
  }
}

function normalizeAllows(entries: GuardPolicyFile['allow']): GuardAllow[] {
  if (!entries) return [];
  return entries.map((entry) => ({
    id: entry.id,
    reason: entry.reason,
    ...(entry.rule ? { rule: entry.rule } : {}),
    ...(entry.tool ? { tool: entry.tool } : {}),
    ...(entry.skill ? { skill: entry.skill } : {}),
    ...(entry.path ? { path: entry.path } : {}),
    ...(entry.host && normalizeHost(entry.host) ? { host: normalizeHost(entry.host) } : {}),
  }));
}

function hostsFrom(values: readonly string[]): string[] {
  const hosts: string[] = [];
  for (const value of values) {
    const host = normalizeHost(value);
    if (host && !hosts.includes(host)) hosts.push(host);
  }
  return hosts;
}

function uniqueHosts(values: readonly string[]): string[] {
  const hosts: string[] = [];
  for (const value of values) {
    const host = value.toLowerCase();
    if (!hosts.includes(host)) hosts.push(host);
  }
  return hosts;
}

export function normalizeHost(value: string): string | undefined {
  const host = value.trim().toLowerCase().replace(/\.$/, '');
  if (!host || host.length > 253) return undefined;
  if (host.includes('://') || host.includes('/') || host.includes(' ') || host.includes('@')) {
    return undefined;
  }
  if (!/^[a-z0-9._:-]+$/.test(host)) return undefined;
  return host;
}
