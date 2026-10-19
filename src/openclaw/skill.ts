import { parse as parseYaml } from 'yaml';
import { dependenciesFromFrontmatter, type UnscannedDependency } from '../core/dependencies.ts';

export interface SkillFrontmatter {
  name?: string;
  description?: string;
  version?: string;
  allowDomains: string[];
  /** Hosts the skill declares as its own: `homepage`, plus homepage/api_base/url/network values in `metadata`. */
  declaredHosts?: string[];
  /** Packages from `metadata.<agent>.install` entries. */
  installDependencies?: UnscannedDependency[];
  malformed: boolean;
  missing: boolean;
}

export function parseSkillMarkdown(text: string, file = 'SKILL.md'): SkillFrontmatter {
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
    const version = typeof record.version === 'string' ? record.version.trim() : undefined;
    return {
      allowDomains: allowDomainsFrom(record),
      declaredHosts: declaredHostsFrom(record),
      installDependencies: dependenciesFromFrontmatter(record, file),
      malformed: false,
      missing: false,
      ...(name ? { name } : {}),
      ...(description ? { description } : {}),
      ...(version ? { version } : {}),
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

const DECLARED_KEYS = new Set([
  'homepage',
  'website',
  'url',
  'api_base',
  'apibase',
  'api',
  'network',
  'repository',
  'source',
]);

/**
 * The skill's own hosts. Only `homepage` at the top level and the listed keys
 * inside `metadata` count; prose URLs never do.
 */
function declaredHostsFrom(record: Record<string, unknown>): string[] {
  const hosts: string[] = [];
  const add = (value: unknown): void => {
    if (typeof value === 'string') {
      const host = declaredHostOf(value);
      if (host && !hosts.includes(host)) hosts.push(host);
    } else if (Array.isArray(value)) {
      for (const item of value.slice(0, 50)) add(item);
    }
  };
  add(record.homepage);
  const walk = (value: unknown, depth: number): void => {
    const node = asRecord(value);
    if (!node || depth > 4) return;
    for (const [key, child] of Object.entries(node)) {
      if (DECLARED_KEYS.has(key.toLowerCase())) add(child);
      else walk(child, depth + 1);
    }
  };
  walk(record.metadata, 0);
  return hosts;
}

function declaredHostOf(value: string): string | undefined {
  const trimmed = value.trim();
  if (!/^https?:\/\//i.test(trimmed)) return undefined;
  try {
    const host = new URL(trimmed).hostname.toLowerCase().replace(/\.$/, '');
    return host.includes('.') ? host : undefined;
  } catch {
    return undefined;
  }
}
