import { chmod, cp, mkdir, readFile, rename, rm, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { UsageError } from '../core/errors.ts';
import { writeAtomic } from '../util/atomic.ts';

export interface QuarantineManifest {
  id: string;
  skillName: string;
  originalPath: string;
  movedAt: string;
}

export function quarantineDir(home: string): string {
  return join(home, 'quarantine');
}

export async function quarantineSkill(
  skillPath: string,
  home: string,
  now = new Date(),
): Promise<QuarantineManifest> {
  let info;
  try {
    info = await stat(skillPath);
  } catch {
    throw new UsageError(`skill not found: ${skillPath}`);
  }
  if (!info.isDirectory()) throw new UsageError(`skill path is not a directory: ${skillPath}`);
  const dir = quarantineDir(home);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await chmodDir(dir);
  const stamp = now.toISOString().replace(/[:.]/g, '-');
  const safeName =
    basename(skillPath)
      .replace(/[^A-Za-z0-9._-]/g, '_')
      .slice(0, 80) || 'skill';
  const id = `${stamp}-${safeName}`;
  const dest = join(dir, id);
  await moveDir(skillPath, dest);
  const manifest: QuarantineManifest = {
    id,
    skillName: safeName,
    originalPath: skillPath,
    movedAt: now.toISOString(),
  };
  await writeAtomic(
    join(dir, `${id}.manifest.json`),
    `${JSON.stringify(manifest, null, 2)}\n`,
    0o600,
  );
  return manifest;
}

export async function restoreQuarantine(id: string, home: string): Promise<QuarantineManifest> {
  if (!/^[A-Za-z0-9._-]+$/.test(id) || id.includes('..'))
    throw new UsageError('invalid quarantine id');
  const dir = quarantineDir(home);
  const manifestPath = join(dir, `${id}.manifest.json`);
  let manifest: QuarantineManifest;
  try {
    manifest = JSON.parse(await readFile(manifestPath, 'utf8')) as QuarantineManifest;
  } catch {
    throw new UsageError(`quarantine id not found: ${id}`);
  }
  const source = join(dir, id);
  try {
    await stat(source);
  } catch {
    throw new UsageError(`quarantine folder missing: ${id}`);
  }
  try {
    await stat(manifest.originalPath);
    throw new UsageError(`restore target already exists: ${manifest.originalPath}`);
  } catch (error) {
    if (error instanceof UsageError) throw error;
  }
  await moveDir(source, manifest.originalPath);
  await rm(manifestPath, { force: true });
  return manifest;
}

async function moveDir(from: string, to: string): Promise<void> {
  try {
    await rename(from, to);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== 'EXDEV') throw error;
    await cp(from, to, { recursive: true, verbatimSymlinks: true });
    await rm(from, { recursive: true, force: true });
  }
}

async function chmodDir(dir: string): Promise<void> {
  await chmod(dir, 0o700);
}
