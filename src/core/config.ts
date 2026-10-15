import { access, readFile } from 'node:fs/promises';
import { isAbsolute, join, resolve, win32 } from 'node:path';
import { expandUserPath, homeDirectory } from '../util/paths.ts';
import { z } from 'zod';
import { UsageError } from './errors.ts';
import type { ResolvedConfig, ResolvedLlmConfig, Severity } from './types.ts';
import { BUILTIN_ALLOW_DOMAINS } from './domains.ts';
import { discoverDefaultPaths } from '../openclaw/locate.ts';
import {
  LLM_DEFAULT_MAX_INPUT_CHARS,
  LLM_DEFAULT_MODEL,
  LLM_DEFAULT_TIMEOUT_MS,
  LLM_DEFAULT_URL,
} from '../llm/constants.ts';

const severitySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);

export const ConfigSchema = z
  .object({
    skillDirs: z.array(z.string()).optional(),
    agentFiles: z.array(z.string()).optional(),
    allowDomains: z.array(z.string()).optional(),
    ignoreGlobs: z.array(z.string()).optional(),
    ignoreDirs: z
      .array(
        z
          .object({
            path: z.string().trim().min(1),
            reason: z.string().trim().min(8),
          })
          .strict(),
      )
      .optional(),
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
    suppressions: z
      .array(
        z
          .object({
            ruleId: z.string().regex(/^IH-[A-Z]+-\d{3}$/),
            path: z.string().min(1).optional(),
            line: z.number().int().positive().optional(),
            evidence: z.string().min(1).optional(),
            reason: z.string().trim().min(8),
          })
          .strict(),
      )
      .optional(),
    suppressCritical: z.boolean().optional(),
    suppressIntegrity: z.boolean().optional(),
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
    llm: z
      .object({
        url: z.string().min(1).max(2000).optional(),
        model: z.string().min(1).max(200).optional(),
        api: z.enum(['ollama', 'openai']).optional(),
        timeoutMs: z.number().int().min(1000).max(120_000).optional(),
        maxInputChars: z.number().int().min(1000).max(100_000).optional(),
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

/**
 * Extra path filters. Empty by default.
 * `.git` and `node_modules` are reported as skipped directories.
 * `dist` is scanned like any other directory.
 */
export const DEFAULT_IGNORE = [] as const;

export interface LoadConfigOptions {
  cwd?: string;
  explicitPath?: string;
  env?: NodeJS.ProcessEnv;
}

export function ironheightsHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.IRONHEIGHTS_HOME ?? join(homeDirectory(env), '.ironheights');
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
    skillDirs: (input.skillDirs ?? defaults.skillDirs).map((dir) => expandHome(dir, env)),
    agentFiles: (input.agentFiles ?? defaults.agentFiles).map((file) => expandHome(file, env)),
    allowDomains: [...defaults.allowDomains, ...allowExtra],
    ignoreGlobs: input.ignoreGlobs ?? [...DEFAULT_IGNORE],
    ignoreDirs: input.ignoreDirs ?? [],
    ruleOverrides: input.ruleOverrides ?? {},
    suppressions: input.suppressions ?? [],
    suppressCritical: input.suppressCritical ?? false,
    suppressIntegrity: input.suppressIntegrity ?? false,
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
    llm: resolveLlmConfig(input.llm),
    ...(discovered ? { configPath: discovered } : {}),
  };
}

export function resolveLlmConfig(input: ConfigInput['llm']): ResolvedLlmConfig {
  return {
    url: input?.url ?? LLM_DEFAULT_URL,
    model: input?.model ?? LLM_DEFAULT_MODEL,
    ...(input?.api ? { api: input.api } : {}),
    timeoutMs: input?.timeoutMs ?? LLM_DEFAULT_TIMEOUT_MS,
    maxInputChars: input?.maxInputChars ?? LLM_DEFAULT_MAX_INPUT_CHARS,
  };
}

export function emptyConfig(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    skillDirs: [],
    agentFiles: [],
    allowDomains: [...BUILTIN_ALLOW_DOMAINS],
    ignoreGlobs: [...DEFAULT_IGNORE],
    ignoreDirs: [],
    ruleOverrides: {},
    suppressions: [],
    suppressCritical: false,
    suppressIntegrity: false,
    limits: { ...DEFAULT_LIMITS },
    thresholds: { ...DEFAULT_THRESHOLDS },
    llm: resolveLlmConfig(undefined),
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

function expandHome(value: string, env: NodeJS.ProcessEnv): string {
  const expanded = expandUserPath(value, env);
  if (isAbsolute(expanded) || win32.isAbsolute(expanded)) return expanded;
  return resolve(expanded);
}

export function isSeverity(value: string): value is Severity {
  return severitySchema.safeParse(value).success;
}
