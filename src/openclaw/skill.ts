import { parse as parseYaml } from 'yaml';

export interface SkillFrontmatter {
  name?: string;
  description?: string;
  malformed: boolean;
  missing: boolean;
}

export function parseSkillMarkdown(text: string): SkillFrontmatter {
  if (!text.startsWith('---')) return { malformed: false, missing: true };
  const match = /^---\r?\n([\s\S]{0,65536}?)\r?\n---/.exec(text);
  if (!match) return { malformed: true, missing: false };
  const raw = match[1] ?? '';
  try {
    const parsed = parseYaml(raw, { maxAliasCount: 10 }) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { malformed: true, missing: false };
    }
    const record = parsed as Record<string, unknown>;
    const name = typeof record.name === 'string' ? record.name.trim() : undefined;
    const description =
      typeof record.description === 'string' ? record.description.trim() : undefined;
    return {
      malformed: false,
      missing: false,
      ...(name ? { name } : {}),
      ...(description ? { description } : {}),
    };
  } catch {
    return { malformed: true, missing: false };
  }
}
