import { lstat, readdir, readFile, realpath, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homeDirectory, pathPlatform } from '../util/paths.ts';

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

const UNIX_GLOBAL_PACKAGE_SKILLS = [
  '/opt/homebrew/lib/node_modules/openclaw/skills',
  '/usr/local/lib/node_modules/openclaw/skills',
  '/usr/lib/node_modules/openclaw/skills',
];

const WRAPPER_ENTRY =
  /["']([^"']+[/\\]node_modules[/\\]openclaw)[/\\](?:dist[/\\]entry\.js|bin[/\\]openclaw\.js)["']/i;

export async function resolveBundledSkillsDir(
  env: NodeJS.ProcessEnv,
  stateDir: string,
): Promise<string | undefined> {
  const override = env.OPENCLAW_BUNDLED_SKILLS_DIR?.trim();
  if (override && (await looksLikeSkillsDir(override))) return override;

  const candidates: string[] = [];
  for (const wrapper of wrapperCandidates(stateDir, env)) {
    const fromWrapper = await packageRootFromWrapper(wrapper);
    if (fromWrapper) candidates.push(join(fromWrapper, 'skills'));
  }
  for (const root of await packageRootsFromTools(join(stateDir, 'tools'))) {
    candidates.push(join(root, 'skills'));
  }
  candidates.push(...globalPackageSkillDirs(env));

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
  const root = packageRootFromWrapperText(text);
  if (!root) return undefined;
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
    const layouts = [
      join(toolsDir, entry.name, 'lib', 'node_modules', 'openclaw'),
      join(toolsDir, entry.name, 'node_modules', 'openclaw'),
    ];
    for (const root of layouts) {
      try {
        const info = await stat(root);
        if (info.isDirectory()) roots.push(root);
      } catch {
        continue;
      }
    }
  }
  return roots;
}

/** Package root named in an OpenClaw or npm wrapper, or undefined when the text has none. */
export function packageRootFromWrapperText(text: string): string | undefined {
  const sample = text.length > 8192 ? text.slice(0, 8192) : text;
  const match = WRAPPER_ENTRY.exec(sample);
  const root = match?.[1];
  if (!root || !isOpenClawPackageRoot(root)) return undefined;
  return root;
}

export function isOpenClawPackageRoot(root: string): boolean {
  const normalized = root.replace(/\\/g, '/').replace(/\/+$/, '');
  return normalized.endsWith('/node_modules/openclaw');
}

export function globalPackageSkillDirs(
  env: NodeJS.ProcessEnv = process.env,
  os: NodeJS.Platform = process.platform,
): string[] {
  const lib = pathPlatform(os);
  const dirs = [...UNIX_GLOBAL_PACKAGE_SKILLS];
  const prefix = env.npm_config_prefix;
  if (prefix) dirs.push(lib.join(prefix, 'node_modules', 'openclaw', 'skills'));
  if (os !== 'win32') return dirs;
  const home = homeDirectory(env, os);
  const appData = env.APPDATA || lib.join(home, 'AppData', 'Roaming');
  const localAppData = env.LOCALAPPDATA || lib.join(home, 'AppData', 'Local');
  const programFiles = env.ProgramFiles || 'C:\\Program Files';
  dirs.push(
    lib.join(appData, 'npm', 'node_modules', 'openclaw', 'skills'),
    lib.join(localAppData, 'pnpm', 'global', 'node_modules', 'openclaw', 'skills'),
    lib.join(
      localAppData,
      'OpenClaw',
      'deps',
      'portable-node',
      'node_modules',
      'openclaw',
      'skills',
    ),
    lib.join(programFiles, 'nodejs', 'node_modules', 'openclaw', 'skills'),
  );
  return dirs;
}

export function wrapperCandidates(
  stateDir: string,
  env: NodeJS.ProcessEnv = process.env,
  os: NodeJS.Platform = process.platform,
): string[] {
  const lib = pathPlatform(os);
  const candidates = [
    lib.join(stateDir, 'bin', 'openclaw'),
    lib.join(stateDir, 'bin', 'openclaw.cmd'),
  ];
  if (os !== 'win32') return candidates;
  const home = homeDirectory(env, os);
  const appData = env.APPDATA || lib.join(home, 'AppData', 'Roaming');
  candidates.push(
    lib.join(home, '.local', 'bin', 'openclaw.cmd'),
    lib.join(appData, 'npm', 'openclaw.cmd'),
    lib.join(appData, 'npm', 'openclaw'),
  );
  return candidates;
}
