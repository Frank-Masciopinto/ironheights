import { lstat, readdir, readFile, realpath, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';

/**
 * Bundled skills ship in the OpenClaw package `skills/` directory.
 * OpenClaw 2026.9.3 resolves that directory from OPENCLAW_BUNDLED_SKILLS_DIR,
 * then from the package root (`resolveBundledSkillsDir` in bundled-dir.ts).
 * Custodian skills live in the sibling `custodian-skills/` directory
 * (https://docs.openclaw.ai/tools/custodian-skills).
 *
 * Plugin skills are published as symlinks in `<state>/plugin-skills`
 * (`resolveDefaultPluginSkillsDir` in OpenClaw's plugin-skills.ts). The links
 * point at the real skill directories declared by each plugin's
 * `openclaw.plugin.json`.
 */

const GLOBAL_PACKAGE_SKILLS = [
  '/opt/homebrew/lib/node_modules/openclaw/skills',
  '/usr/local/lib/node_modules/openclaw/skills',
  '/usr/lib/node_modules/openclaw/skills',
];

const WRAPPER_ENTRY = /["']([^"']+\/node_modules\/openclaw)\/dist\/entry\.js["']/;

export async function resolveBundledSkillsDir(
  env: NodeJS.ProcessEnv,
  stateDir: string,
): Promise<string | undefined> {
  const override = env.OPENCLAW_BUNDLED_SKILLS_DIR?.trim();
  if (override && (await looksLikeSkillsDir(override))) return override;

  const candidates: string[] = [];
  const fromWrapper = await packageRootFromWrapper(join(stateDir, 'bin', 'openclaw'));
  if (fromWrapper) candidates.push(join(fromWrapper, 'skills'));
  for (const root of await packageRootsFromTools(join(stateDir, 'tools'))) {
    candidates.push(join(root, 'skills'));
  }
  candidates.push(...GLOBAL_PACKAGE_SKILLS);

  for (const candidate of candidates) {
    if (await looksLikeSkillsDir(candidate)) return candidate;
  }
  return undefined;
}

export function custodianSkillsDir(bundledSkillsDir: string): string {
  return join(dirname(bundledSkillsDir), 'custodian-skills');
}

export async function resolvePluginSkillDirs(stateDir: string): Promise<string[]> {
  const published = join(stateDir, 'plugin-skills');
  let entries;
  try {
    entries = await readdir(published);
  } catch {
    return [];
  }
  const dirs: string[] = [];
  for (const name of entries) {
    if (name.startsWith('.')) continue;
    const abs = join(published, name);
    try {
      const info = await lstat(abs);
      const target = info.isSymbolicLink() ? await realpath(abs) : abs;
      const targetInfo = await stat(target);
      if (!targetInfo.isDirectory()) continue;
      if (!dirs.includes(target)) dirs.push(target);
    } catch {
      continue;
    }
  }
  return dirs;
}

export async function looksLikeSkillsDir(dir: string): Promise<boolean> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    if (entry.isFile() && entry.name.endsWith('.md')) return true;
    if (entry.isDirectory() || entry.isSymbolicLink()) {
      try {
        await stat(join(dir, entry.name, 'SKILL.md'));
        return true;
      } catch {
        continue;
      }
    }
  }
  return false;
}

async function packageRootFromWrapper(wrapperPath: string): Promise<string | undefined> {
  let text: string;
  try {
    text = await readFile(wrapperPath, 'utf8');
  } catch {
    return undefined;
  }
  if (text.length > 8192) text = text.slice(0, 8192);
  const match = WRAPPER_ENTRY.exec(text);
  const root = match?.[1];
  if (!root?.endsWith('/node_modules/openclaw')) return undefined;
  try {
    const info = await stat(root);
    return info.isDirectory() ? root : undefined;
  } catch {
    return undefined;
  }
}

async function packageRootsFromTools(toolsDir: string): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(toolsDir, { withFileTypes: true });
  } catch {
    return [];
  }
  const roots: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !entry.name.startsWith('node-v')) continue;
    const root = join(toolsDir, entry.name, 'lib', 'node_modules', 'openclaw');
    try {
      const info = await stat(root);
      if (info.isDirectory()) roots.push(root);
    } catch {
      continue;
    }
  }
  return roots;
}
