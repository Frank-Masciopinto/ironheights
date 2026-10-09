import { readdir, readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { BUILTIN_ALLOW_DOMAINS } from '../core/domains.ts';
import {
  custodianSkillsDir,
  looksLikeSkillsDir,
  resolveBundledSkillsDir,
  resolvePluginSkillDirs,
} from './bundled.ts';

/**
 * OpenClaw locations verified against:
 * https://docs.openclaw.ai/tools/skills
 * https://docs.openclaw.ai/tools/custodian-skills
 * https://docs.openclaw.ai/concepts/agent-workspace (workspace default)
 * https://docs.openclaw.ai/gateway/security/secrets-and-storage
 * https://docs.openclaw.ai/install/node-compatibility
 * OpenClaw 2026.9.3: bundled skills are `<package>/skills`, custodian skills are
 * the sibling `custodian-skills/` directory, and plugin skills are symlinks in
 * `<state>/plugin-skills` that point at each plugin's real skill directory.
 */

export const BOOTSTRAP_FILES = [
  'AGENTS.md',
  'SOUL.md',
  'IDENTITY.md',
  'USER.md',
  'TOOLS.md',
  'BOOTSTRAP.md',
  'MEMORY.md',
] as const;

export interface LocatedDir {
  path: string;
  source: string;
  exists: boolean;
}

export interface OpenClawLocations {
  stateDir: string;
  configPath: string;
  configFound: boolean;
  configParsed: boolean;
  workspace?: string;
  skillDirs: LocatedDir[];
  agentFiles: string[];
  notes: string[];
}

export function openclawStateDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.OPENCLAW_STATE_DIR ?? join(homedir(), '.openclaw');
}

export async function discoverDefaultPaths(env: NodeJS.ProcessEnv = process.env): Promise<{
  skillDirs: string[];
  agentFiles: string[];
  allowDomains: string[];
}> {
  const located = await locateOpenClaw(env);
  return {
    skillDirs: located.skillDirs.map((dir) => dir.path),
    agentFiles: located.agentFiles,
    allowDomains: [...BUILTIN_ALLOW_DOMAINS],
  };
}

export async function locateOpenClaw(
  env: NodeJS.ProcessEnv = process.env,
): Promise<OpenClawLocations> {
  const stateDir = openclawStateDir(env);
  const configPath = env.OPENCLAW_CONFIG_PATH ?? join(stateDir, 'openclaw.json');
  const notes: string[] = [];
  let configFound = false;
  let configParsed = false;
  let workspace = join(stateDir, 'workspace');
  const extraDirs: string[] = [];

  try {
    await stat(configPath);
    configFound = true;
    try {
      const parsed = parseJson5(await readFile(configPath, 'utf8'));
      const extracted = extractOpenClawPaths(parsed);
      if (extracted.workspace) workspace = expand(extracted.workspace);
      extraDirs.push(...extracted.extraDirs.map(expand));
      configParsed = true;
    } catch {
      configParsed = false;
      notes.push('OpenClaw config was found but could not be parsed. Using default workspace.');
    }
  } catch {
    notes.push('OpenClaw config was not found. Using default skill and workspace paths.');
  }

  const candidates: Array<{ path: string; source: string }> = [
    { path: join(workspace, 'skills'), source: 'workspace skills' },
    { path: join(workspace, '.agents', 'skills'), source: 'project agent skills' },
    { path: join(homedir(), '.agents', 'skills'), source: 'personal agent skills' },
    { path: join(stateDir, 'skills'), source: 'managed skills' },
  ];

  const bundled = await resolveBundledSkillsDir(env, stateDir);
  if (bundled) {
    candidates.push({ path: bundled, source: 'bundled skills' });
    const custodian = custodianSkillsDir(bundled);
    if (await looksLikeSkillsDir(custodian)) {
      candidates.push({ path: custodian, source: 'custodian skills' });
    }
  } else {
    notes.push(
      'Bundled skills were not found. Set OPENCLAW_BUNDLED_SKILLS_DIR to the OpenClaw package skills directory.',
    );
  }

  const pluginDirs = await resolvePluginSkillDirs(stateDir);
  if (pluginDirs.length === 0) {
    candidates.push({ path: join(stateDir, 'plugin-skills'), source: 'plugin skills' });
  } else {
    for (const dir of pluginDirs) candidates.push({ path: dir, source: 'plugin skills' });
  }

  const workshop = await workshopDirs(stateDir);
  for (const dir of workshop) candidates.push({ path: dir, source: 'workshop skills' });
  for (const dir of extraDirs) candidates.push({ path: dir, source: 'skills.load.extraDirs' });

  const skillDirs: LocatedDir[] = [];
  for (const candidate of candidates) {
    let exists = false;
    try {
      const info = await stat(candidate.path);
      exists = info.isDirectory();
    } catch {
      exists = false;
    }
    skillDirs.push({ ...candidate, exists });
  }

  const agentFiles = [
    ...BOOTSTRAP_FILES.map((name) => join(workspace, name)),
    join(workspace, 'memory'),
    configPath,
    join(stateDir, 'credentials'),
    join(stateDir, '.env'),
  ];

  return {
    stateDir,
    configPath,
    configFound,
    configParsed,
    workspace,
    skillDirs,
    agentFiles,
    notes,
  };
}

async function workshopDirs(stateDir: string): Promise<string[]> {
  const agentsDir = join(stateDir, 'agents');
  let entries;
  try {
    entries = await readdir(agentsDir, { withFileTypes: true });
  } catch {
    return [];
  }
  const dirs: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    dirs.push(join(agentsDir, entry.name, 'agent', 'workshop-skills'));
  }
  return dirs;
}

function extractOpenClawPaths(value: unknown): { workspace?: string; extraDirs: string[] } {
  if (!value || typeof value !== 'object') return { extraDirs: [] };
  const root = value as Record<string, unknown>;
  const agents = asRecord(root.agents);
  const defaults = asRecord(agents?.defaults);
  const workspace = typeof defaults?.workspace === 'string' ? defaults.workspace : undefined;
  const skills = asRecord(root.skills);
  const load = asRecord(skills?.load);
  const extra = Array.isArray(load?.extraDirs)
    ? load.extraDirs.filter((item): item is string => typeof item === 'string')
    : [];
  return { ...(workspace ? { workspace } : {}), extraDirs: extra };
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

/** Minimal JSON5 cleanup for the two fields we read. Not a full JSON5 parser. */
export function parseJson5(text: string): unknown {
  const withoutBlock = text.replace(/\/\*[\s\S]*?\*\//g, '');
  const withoutLine = withoutBlock.replace(/(^|[^:\\])\/\/.*$/gm, '$1');
  const withoutTrailing = withoutLine.replace(/,\s*([}\]])/g, '$1');
  const quotedKeys = withoutTrailing.replace(
    /([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*:)/g,
    '$1"$2"$3',
  );
  return JSON.parse(quotedKeys) as unknown;
}

function expand(value: string): string {
  if (value === '~') return homedir();
  if (value.startsWith('~/')) return join(homedir(), value.slice(2));
  return value;
}
