import { access, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { z } from 'zod';
import { UsageError } from './errors.ts';
import type { ResolvedConfig, Severity } from './types.ts';
import { BUILTIN_ALLOW_DOMAINS } from './domains.ts';
import { discoverDefaultPaths } from '../openclaw/locate.ts';

const severitySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);

export const ConfigSchema = z
  .object({
    skillDirs: z.array(z.string()).optional(),
    agentFiles: z.array(z.string()).optional(),
    allowDomains: z.array(z.string()).optional(),
    ignoreGlobs: z.array(z.string()).optional(),
    ruleOverrides: z
      .record(
        z.string(),
        z
          .object({
            enabled: z.boolean().optional(),
            severity: severitySchema.optional(),
          })
          .strict(),
      )
      .optional(),
    failOn: severitySchema.optional(),
    limits: z
      .object({
        maxFileBytes: z.number().int().positive().optional(),
        maxFiles: z.number().int().positive().optional(),
        maxDepth: z.number().int().positive().optional(),
      })
      .strict()
      .optional(),
    thresholds: z
      .object({
        block: z.number().nonnegative().optional(),
        review: z.number().nonnegative().optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export type ConfigInput = z.infer<typeof ConfigSchema>;

export const DEFAULT_LIMITS = {
  maxFileBytes: 1024 * 1024,
  maxFiles: 2000,
  maxDepth: 10,
} as const;

export const DEFAULT_THRESHOLDS = { block: 80, review: 15 } as const;

export const DEFAULT_IGNORE = ['**/.git/**', '**/node_modules/**', '**/dist/**'] as const;

export interface LoadConfigOptions {
  cwd?: string;
  explicitPath?: string;
  env?: NodeJS.ProcessEnv;
}

export function ironheightsHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.IRONHEIGHTS_HOME ?? join(homedir(), '.ironheights');
}

export async function loadConfig(options: LoadConfigOptions = {}): Promise<ResolvedConfig> {
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const home = ironheightsHome(env);
  const discovered = options.explicitPath
    ? options.explicitPath
    : await firstExisting([
        join(cwd, 'ironheights.config.json'),
        join(home, 'ironheights.config.json'),
      ]);

  let input: ConfigInput = {};
  if (options.explicitPath) {
    input = await readConfigFile(options.explicitPath);
  } else if (discovered) {
    input = await readConfigFile(discovered);
  }

  const defaults = await discoverDefaultPaths(env);
  const allowExtra = input.allowDomains ?? [];
  return {
    skillDirs: (input.skillDirs ?? defaults.skillDirs).map((dir) => expandHome(dir)),
    agentFiles: (input.agentFiles ?? defaults.agentFiles).map((file) => expandHome(file)),
    allowDomains: [...defaults.allowDomains, ...allowExtra],
    ignoreGlobs: input.ignoreGlobs ?? [...DEFAULT_IGNORE],
    ruleOverrides: input.ruleOverrides ?? {},
    ...(input.failOn ? { failOn: input.failOn } : {}),
    limits: {
      maxFileBytes: input.limits?.maxFileBytes ?? DEFAULT_LIMITS.maxFileBytes,
      maxFiles: input.limits?.maxFiles ?? DEFAULT_LIMITS.maxFiles,
      maxDepth: input.limits?.maxDepth ?? DEFAULT_LIMITS.maxDepth,
    },
    thresholds: {
      block: input.thresholds?.block ?? DEFAULT_THRESHOLDS.block,
      review: input.thresholds?.review ?? DEFAULT_THRESHOLDS.review,
    },
    ...(discovered ? { configPath: discovered } : {}),
  };
}

export function emptyConfig(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    skillDirs: [],
    agentFiles: [],
    allowDomains: [...BUILTIN_ALLOW_DOMAINS],
    ignoreGlobs: [...DEFAULT_IGNORE],
    ruleOverrides: {},
    limits: { ...DEFAULT_LIMITS },
    thresholds: { ...DEFAULT_THRESHOLDS },
    ...overrides,
  };
}

async function readConfigFile(filePath: string): Promise<ConfigInput> {
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf8');
  } catch {
    throw new UsageError(`cannot read config file: ${filePath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new UsageError(`config file is not valid JSON: ${filePath}`);
  }
  const result = ConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issue = result.error.issues[0];
    const path = issue?.path.join('.') || '(root)';
    throw new UsageError(`invalid config at ${path}: ${issue?.message ?? 'unknown error'}`);
  }
  return result.data;
}

async function firstExisting(paths: string[]): Promise<string | undefined> {
  for (const filePath of paths) {
    try {
      await access(filePath);
      return filePath;
    } catch {
      continue;
    }
  }
  return undefined;
}

function expandHome(value: string): string {
  if (value === '~') return homedir();
  if (value.startsWith('~/')) return join(homedir(), value.slice(2));
  return isAbsolute(value) ? value : resolve(value);
}

export function isSeverity(value: string): value is Severity {
  return severitySchema.safeParse(value).success;
}
