import { realpathSync } from 'node:fs';
import { stat } from 'node:fs/promises';
import { errorDecision, evaluateToolCall } from './policy.ts';
import { appendAuditEvent } from './audit.ts';
import {
  loadGuardRuntime,
  skillDeclaredDomains,
  type LoadGuardOptions,
  type LoadedGuard,
} from './load.ts';
import { resolveToolPath } from './signals.ts';
import type { AuditEvent, GuardDecision, GuardMode, ToolCall } from './types.ts';

export interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
}

export interface GuardHookEvent {
  toolName?: unknown;
  params?: unknown;
  derivedPaths?: unknown;
  toolKind?: unknown;
  toolInputKind?: unknown;
}

export interface GuardHookDeps {
  load?: (options: LoadGuardOptions) => Promise<LoadedGuard>;
  append?: typeof appendAuditEvent;
  declaredDomains?: (skill: string, skillDirs: readonly string[]) => Promise<string[]>;
  now?: () => Date;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  policyPath?: string;
  configPath?: string;
  pluginConfig?: unknown;
  /** Skip symlink resolution. Tests that do not touch the filesystem use this. */
  resolveLinks?: boolean;
}

const RECORDED_TOOLS = new Set([
  'exec',
  'bash',
  'shell',
  'code_execution',
  'process',
  'web_fetch',
  'browser',
  'write',
  'edit',
  'apply_patch',
]);

/**
 * OpenClaw before_tool_call adapter. It never throws. Monitor mode never
 * returns a block. Enforce mode blocks only when the decision says so, or
 * when the guard itself fails while that mode is active. A failure in
 * monitor mode is logged and the tool call is left alone.
 */
export function createGuardHook(
  deps: GuardHookDeps = {},
): (event: GuardHookEvent, ctx?: unknown) => Promise<BeforeToolCallResult | undefined> {
  const load = deps.load ?? loadGuardRuntime;
  const append = deps.append ?? appendAuditEvent;
  const declared = deps.declaredDomains ?? skillDeclaredDomains;
  const now = deps.now ?? (() => new Date());
  const seenPolicyErrors = new Set<string>();
  let cache: { stamp: string; loaded: LoadedGuard } | undefined;
  let lastMode: GuardMode = 'monitor';

  return async (event) => {
    const override = modeFromConfig(deps.pluginConfig);
    if (override) lastMode = override;
    try {
      const loaded = await cachedLoad(cache, load, deps, override);
      cache = loaded.cache;
      lastMode = loaded.loaded.policy.mode;
      const prepared = await prepareCall(
        event,
        loaded.loaded,
        declared,
        deps.resolveLinks !== false,
      );
      loaded.loaded = prepared.loaded;
      cache = { stamp: loaded.cache.stamp, loaded: prepared.loaded };
      if (
        !prepared.loaded.ok &&
        prepared.loaded.message &&
        !seenPolicyErrors.has(prepared.loaded.message)
      ) {
        seenPolicyErrors.add(prepared.loaded.message);
        await writeBounded(() =>
          append(policyErrorEvent(prepared.loaded, now().toISOString()), prepared.loaded.log),
        );
      }
      const decision = evaluateToolCall(prepared.call, prepared.loaded.policy);
      if (shouldRecord(prepared.call, decision)) {
        await writeBounded(() =>
          append(decisionEvent(prepared.call, decision, now().toISOString()), prepared.loaded.log),
        );
      }
      return resultFrom(decision);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      const decision = errorDecision(lastMode, message);
      try {
        const loaded = cache?.loaded;
        if (loaded) {
          await writeBounded(() =>
            append(
              {
                ...decisionEvent(
                  { toolName: toolNameOf(event), params: {}, derivedPaths: [] },
                  decision,
                  now().toISOString(),
                ),
                kind: 'guard-error',
              },
              loaded.log,
            ),
          );
        }
      } catch {
        // Logging failed. The decision below still stands.
      }
      return resultFrom(decision);
    }
  };
}

export function resultFrom(decision: GuardDecision): BeforeToolCallResult | undefined {
  if (decision.action !== 'block') return undefined;
  return { block: true, blockReason: decision.reason };
}

export function normalizeToolCall(event: GuardHookEvent): ToolCall {
  const params = isRecord(event.params) ? event.params : {};
  const skill = skillFrom(params);
  const derived = stringList(event.derivedPaths);
  return {
    toolName: toolNameOf(event),
    params,
    derivedPaths: derived,
    ...(skill ? { skill } : {}),
    ...(typeof event.toolKind === 'string' ? { toolKind: event.toolKind } : {}),
    ...(typeof event.toolInputKind === 'string' ? { toolInputKind: event.toolInputKind } : {}),
  };
}

export function modeFromConfig(config: unknown): GuardMode | undefined {
  if (!isRecord(config)) return undefined;
  const mode = config.mode;
  if (mode === 'monitor' || mode === 'enforce') return mode;
  return undefined;
}

export function policyPathFromConfig(config: unknown): string | undefined {
  if (!isRecord(config)) return undefined;
  const path = config.policyPath;
  return typeof path === 'string' && path.length > 0 ? path : undefined;
}

function decisionEvent(call: ToolCall, decision: GuardDecision, time: string): AuditEvent {
  const guardError =
    decision.reason.includes('could not evaluate') ||
    decision.reason.includes('guard evaluation failed');
  return {
    schemaVersion: 1,
    time,
    kind: guardError ? 'guard-error' : 'decision',
    mode: decision.mode,
    action: decision.action,
    wouldBlock: decision.wouldBlock,
    tool: call.toolName,
    ...(call.skill ? { skill: call.skill } : {}),
    ruleIds: decision.violations.map((item) => item.ruleId),
    allowIds: decision.allowed.map((item) => item.allowId),
    reason: decision.reason,
  };
}

function policyErrorEvent(loaded: LoadedGuard, time: string): AuditEvent {
  return {
    schemaVersion: 1,
    time,
    kind: 'policy-error',
    mode: loaded.policy.mode,
    action: 'allow',
    wouldBlock: false,
    tool: '',
    ruleIds: [],
    allowIds: [],
    reason: loaded.message ?? 'guard policy could not be loaded',
  };
}

function shouldRecord(call: ToolCall, decision: GuardDecision): boolean {
  if (
    decision.reason.includes('could not evaluate') ||
    decision.reason.includes('guard evaluation failed')
  ) {
    return true;
  }
  if (decision.wouldBlock || decision.action === 'block' || decision.allowed.length > 0)
    return true;
  if (call.toolKind === 'code_mode_exec') return true;
  return RECORDED_TOOLS.has(call.toolName);
}

async function prepareCall(
  event: GuardHookEvent,
  loaded: LoadedGuard,
  declared: (skill: string, skillDirs: readonly string[]) => Promise<string[]>,
  resolveLinks: boolean,
): Promise<{ call: ToolCall; loaded: LoadedGuard }> {
  const normalized = normalizeToolCall(event);
  const linked = resolveLinks ? linkTargets(normalized, loaded.policy) : [];
  const call: ToolCall = {
    ...normalized,
    derivedPaths: [...normalized.derivedPaths, ...linked],
  };
  let policy = loaded.policy;
  if (call.skill && !policy.skillDeclaredDomains[call.skill]) {
    try {
      const hosts = await declared(call.skill, policy.skillDirs);
      policy = {
        ...policy,
        skillDeclaredDomains: { ...policy.skillDeclaredDomains, [call.skill]: hosts },
      };
    } catch {
      // Missing skill metadata only means no extra hosts. The call stays stricter.
    }
  }
  return { call, loaded: { ...loaded, policy } };
}

function isResolvedAbsolute(value: string): boolean {
  return value.startsWith('/') || /^[A-Za-z]:\//.test(value);
}

function linkTargets(call: ToolCall, policy: LoadedGuard['policy']): string[] {
  const extra: string[] = [];
  const seeds = [
    ...stringList(call.params.path),
    ...stringList(call.params.file_path),
    ...call.derivedPaths,
  ];
  for (const seed of seeds.slice(0, 32)) {
    const resolved = resolveToolPath(seed, policy);
    if (!isResolvedAbsolute(resolved)) continue;
    try {
      const real = realpathSync.native(resolved);
      if (real && real !== resolved && !extra.includes(real)) extra.push(real);
    } catch {
      // The path does not exist yet, or cannot be resolved. Lexical checks still run.
    }
  }
  return extra;
}

async function cachedLoad(
  cache: { stamp: string; loaded: LoadedGuard } | undefined,
  load: (options: LoadGuardOptions) => Promise<LoadedGuard>,
  deps: GuardHookDeps,
  override: GuardMode | undefined,
): Promise<{ cache: { stamp: string; loaded: LoadedGuard }; loaded: LoadedGuard }> {
  const policyPath = deps.policyPath ?? policyPathFromConfig(deps.pluginConfig);
  const stamp = await policyStamp(policyPath);
  const key = `${stamp}|${override ?? ''}|${deps.configPath ?? ''}`;
  if (cache && cache.stamp === key) return { cache, loaded: cache.loaded };
  const loaded = await load({
    ...(deps.env ? { env: deps.env } : {}),
    ...(deps.cwd ? { cwd: deps.cwd } : {}),
    ...(policyPath ? { policyPath } : {}),
    ...(deps.configPath ? { configPath: deps.configPath } : {}),
    ...(override ? { modeOverride: override } : {}),
  });
  const next = { stamp: key, loaded };
  return { cache: next, loaded };
}

async function policyStamp(policyPath: string | undefined): Promise<string> {
  if (!policyPath) return 'default';
  try {
    const info = await stat(policyPath);
    return `${policyPath}:${info.mtimeMs}:${info.size}`;
  } catch {
    return `${policyPath}:missing`;
  }
}

async function writeBounded(write: () => Promise<void>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      write(),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, 250);
      }),
    ]);
  } catch {
    // The audit log is best effort. A disk error must not change into a throw.
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function toolNameOf(event: GuardHookEvent): string {
  if (typeof event.toolName !== 'string') return '';
  return event.toolName.trim().toLowerCase();
}

function skillFrom(params: Record<string, unknown>): string | undefined {
  for (const key of ['skill', 'skillName', 'skill_name']) {
    const value = params[key];
    if (typeof value !== 'string') continue;
    const skill = value.trim();
    if (/^[\w.-]{1,80}$/.test(skill)) return skill;
  }
  return undefined;
}

function stringList(value: unknown): string[] {
  if (typeof value === 'string' && value.length > 0) return [value];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string' && item.length > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
