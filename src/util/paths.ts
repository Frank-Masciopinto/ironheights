import { homedir } from 'node:os';
import path from 'node:path';

/**
 * Path helpers shared by skill discovery, baselines, and the walker.
 * Windows accepts `~`, `~/`, `~\`, and `%USERPROFILE%` / `%APPDATA%` /
 * `%LOCALAPPDATA%`. Portable baseline keys use forward slashes after `~`.
 */

export function pathPlatform(os: NodeJS.Platform = process.platform): path.PlatformPath {
  return os === 'win32' ? path.win32 : path.posix;
}

/** Drop the `\\?\` prefix Node may return from realpath on Windows. */
export function stripLongPath(value: string): string {
  if (value.startsWith('\\\\?\\UNC\\')) return `\\\\${value.slice(8)}`;
  if (value.startsWith('\\\\?\\')) return value.slice(4);
  return value;
}

export function homeDirectory(
  env: NodeJS.ProcessEnv = process.env,
  os: NodeJS.Platform = process.platform,
): string {
  if (os === 'win32') return env.USERPROFILE || env.HOME || homedir();
  return env.HOME || env.USERPROFILE || homedir();
}

export function expandUserPath(
  value: string,
  env: NodeJS.ProcessEnv = process.env,
  os: NodeJS.Platform = process.platform,
): string {
  const lib = pathPlatform(os);
  let result = value.trim();
  let replaced = false;
  result = result.replace(/%([^%]+)%/g, (full, name: string) => {
    const found = Object.keys(env).find((key) => key.toLowerCase() === name.toLowerCase());
    const replacement = found ? env[found] : undefined;
    if (!replacement || replacement.length === 0) return full;
    replaced = true;
    return replacement;
  });
  const home = homeDirectory(env, os);
  if (result === '~') return home;
  if (result.startsWith('~/') || result.startsWith('~\\')) {
    const parts = result
      .slice(2)
      .split(/[\\/]/)
      .filter((part) => part.length > 0);
    return parts.length === 0 ? home : lib.join(home, ...parts);
  }
  if (os === 'win32' && (replaced || result.includes('\\'))) return lib.normalize(result);
  return result;
}

export function normalizeForCompare(value: string, os: NodeJS.Platform = process.platform): string {
  const lib = pathPlatform(os);
  const normalized = lib.normalize(stripLongPath(value));
  return os === 'win32' ? normalized.toLowerCase() : normalized;
}

export function toPortablePath(
  abs: string,
  env: NodeJS.ProcessEnv = process.env,
  os: NodeJS.Platform = process.platform,
): string {
  const lib = pathPlatform(os);
  const home = stripLongPath(homeDirectory(env, os));
  const value = stripLongPath(abs);
  const homeKey = normalizeForCompare(home, os);
  const valueKey = normalizeForCompare(value, os);
  if (valueKey === homeKey) return '~';
  const prefix = homeKey.endsWith(lib.sep) ? homeKey : `${homeKey}${lib.sep}`;
  if (!valueKey.startsWith(prefix)) return value;
  const rest = valueKey.slice(prefix.length).split(/[\\/]/).join('/');
  return `~/${rest}`;
}

export function fromPortablePath(
  portable: string,
  env: NodeJS.ProcessEnv = process.env,
  os: NodeJS.Platform = process.platform,
): string {
  const lib = pathPlatform(os);
  const home = homeDirectory(env, os);
  if (portable === '~') return home;
  if (portable.startsWith('~/') || portable.startsWith('~\\')) {
    const parts = portable
      .slice(2)
      .split(/[\\/]/)
      .filter((part) => part.length > 0 && part !== '.' && part !== '..');
    return parts.length === 0 ? home : lib.join(home, ...parts);
  }
  return portable;
}

/** True when `target` is `root` or a path inside it. Absolute relatives (other drives) are outside. */
export function isInsideRoot(
  root: string,
  target: string,
  os: NodeJS.Platform = process.platform,
): boolean {
  const lib = pathPlatform(os);
  const base = normalizeForCompare(lib.resolve(root), os);
  const child = normalizeForCompare(lib.resolve(target), os);
  if (base === child) return true;
  const rel = lib.relative(base, child);
  if (rel === '') return true;
  if (lib.isAbsolute(rel)) return false;
  return !rel.split(lib.sep).includes('..');
}

/**
 * True for a filesystem root or the home directory itself.
 * `~/Projects/skills` is not broad. `~`, `/`, and `C:\` are.
 */
export function isBroadPath(
  value: string,
  env: NodeJS.ProcessEnv = process.env,
  os: NodeJS.Platform = process.platform,
): boolean {
  const lib = pathPlatform(os);
  const expanded = expandUserPath(value, env, os);
  if (expanded === '~') return true;
  const home = homeDirectory(env, os);
  if (normalizeForCompare(expanded, os) === normalizeForCompare(home, os)) return true;
  if (expanded.split(/[\\/]/).includes('..')) return true;
  if (!lib.isAbsolute(expanded)) return false;
  const root = lib.parse(expanded).root;
  return normalizeForCompare(expanded, os) === normalizeForCompare(root, os);
}
