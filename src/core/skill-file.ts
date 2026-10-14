import { readdir } from 'node:fs/promises';
import { join } from 'node:path';

/** True for a top-level skill file name in any case: SKILL.md, skill.md, Skill.md. */
export function isSkillFileName(relativePath: string): boolean {
  return relativePath.toLowerCase() === 'skill.md';
}

/**
 * Path of the skill file in `dir`, matched case-insensitively. `SKILL.md` wins when several
 * spellings exist. Some publishers (for example Moltbook) ship a lowercase `skill.md`.
 */
export async function findSkillFile(dir: string): Promise<string | undefined> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return undefined;
  }
  const names = entries.filter((e) => e.isFile() && isSkillFileName(e.name)).map((e) => e.name);
  if (names.length === 0) return undefined;
  const name = names.includes('SKILL.md') ? 'SKILL.md' : names.sort()[0];
  return name ? join(dir, name) : undefined;
}
