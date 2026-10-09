import { parse as parseYaml } from 'yaml';

export interface SkillFrontmatter {
  name?: string;
  description?: string;
  allowDomains: string[];
  malformed: boolean;
  missing: boolean;
}

export function parseSkillMarkdown(text: string): SkillFrontmatter {
  if (!text.startsWith('---')) return { allowDomains: [], malformed: false, missing: true };
  const match = /^---\r?\n([\s\S]{0,65536}?)\r?\n---/.exec(text);
  if (!match) return { allowDomains: [], malformed: true, missing: false };
  const raw = match[1] ?? '';
  try {
    const parsed = parseYaml(raw, { maxAliasCount: 10 }) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { allowDomains: [], malformed: true, missing: false };
    }
    const record = parsed as Record<string, unknown>;
    const name = typeof record.name === 'string' ? record.name.trim() : undefined;
    const description =
      typeof record.description === 'string' ? record.description.trim() : undefined;
    return {
      allowDomains: allowDomainsFrom(record),
      malformed: false,
      missing: false,
      ...(name ? { name } : {}),
      ...(description ? { description } : {}),
    };
  } catch {
    return { allowDomains: [], malformed: true, missing: false };
  }
}

function allowDomainsFrom(record: Record<string, unknown>): string[] {
  const metadata = asRecord(record.metadata);
  const ironheights = asRecord(metadata?.ironheights);
  const list = ironheights?.allowDomains;
  if (!Array.isArray(list)) return [];
  const domains: string[] = [];
  for (const item of list) {
    if (typeof item !== 'string') continue;
    const host = item.trim().toLowerCase().replace(/\.$/, '');
    if (!host || host.includes('://') || host.includes('/') || host.includes(' ')) continue;
    if (!domains.includes(host)) domains.push(host);
  }
  return domains;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}
