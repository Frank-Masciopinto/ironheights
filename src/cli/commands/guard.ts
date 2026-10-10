import { readFile, stat } from 'node:fs/promises';
import { UsageError } from '../../core/errors.ts';
import { readAuditTail } from '../../guard/audit.ts';
import { loadGuardRuntime } from '../../guard/load.ts';
import { evaluateToolCall } from '../../guard/policy.ts';
import { normalizeToolCall } from '../../guard/hook.ts';
import { GUARD_PLUGIN_ID } from '../../guard/types.ts';
import { locateOpenClaw, parseJson5 } from '../../openclaw/locate.ts';
import { TOOL_NAME, TOOL_VERSION } from '../../version.ts';

export interface GuardCommandOptions {
  policy?: string;
  config?: string;
  json?: boolean;
  call?: string;
  callFile?: string;
  tail?: string;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  stdout?: (text: string) => void;
}

export async function runGuardStatus(options: GuardCommandOptions = {}): Promise<number> {
  const write = writer(options);
  const loaded = await loadGuardRuntime(loadOptions(options));
  const plugin = await pluginState(options.env);
  const logStat = await fileStat(loaded.log.path);
  if (options.json) {
    write(
      `${JSON.stringify({
        schemaVersion: 1,
        tool: { name: TOOL_NAME, version: TOOL_VERSION },
        mode: loaded.policy.mode,
        modeSource: loaded.modeSource,
        policyPath: loaded.policyPath,
        policyOk: loaded.ok,
        ...(loaded.message ? { message: loaded.message } : {}),
        allowDomainCount: loaded.policy.globalAllowDomains.length,
        allowEntryCount: loaded.policy.allow.length,
        protectedPathCount: loaded.policy.protectedPaths.length,
        skillDirCount: loaded.policy.skillDirs.length,
        logPath: loaded.log.path,
        logBytes: logStat?.size ?? 0,
        logExists: Boolean(logStat),
        plugin,
      })}\n`,
    );
    return 0;
  }
  write(`Mode: ${loaded.policy.mode} (${loaded.modeSource})\n`);
  write(
    `Policy: ${loaded.ok ? 'ok' : 'invalid'} ${loaded.policyPath}${loaded.message ? ` (${loaded.message})` : ''}\n`,
  );
  write(`Allow domains: ${loaded.policy.globalAllowDomains.length}\n`);
  write(`Allow entries: ${loaded.policy.allow.length}\n`);
  write(`Protected paths: ${loaded.policy.protectedPaths.length}\n`);
  write(`Skill directories: ${loaded.policy.skillDirs.length}\n`);
  write(
    `Audit log: ${logStat ? `${logStat.size} bytes` : 'missing'} ${loaded.log.path} (max ${loaded.log.maxBytes} bytes, ${loaded.log.maxFiles} files)\n`,
  );
  write(`OpenClaw plugin ${GUARD_PLUGIN_ID}: ${plugin.summary}\n`);
  if (!loaded.ok) {
    write('An invalid policy falls back to monitor unless the plugin config sets enforce.\n');
  }
  write('The hook runs inside OpenClaw. It is not a separate sandbox. See docs/guard.md.\n');
  return 0;
}

export async function runGuardPolicyCheck(options: GuardCommandOptions = {}): Promise<number> {
  const write = writer(options);
  if (options.call && options.callFile) {
    throw new UsageError('pass either --call or --call-file');
  }
  const loaded = await loadGuardRuntime(loadOptions(options));
  if (!loaded.ok) {
    write(`${loaded.message ?? 'invalid guard policy'}\n`);
    return 64;
  }
  if (!options.call && !options.callFile) {
    if (options.json) {
      write(
        `${JSON.stringify({
          schemaVersion: 1,
          ok: true,
          mode: loaded.policy.mode,
          modeSource: loaded.modeSource,
          policyPath: loaded.policyPath,
          allowDomainCount: loaded.policy.globalAllowDomains.length,
          allowEntryCount: loaded.policy.allow.length,
        })}\n`,
      );
    } else {
      write(`Policy ok: ${loaded.policyPath}\n`);
      write(`Mode: ${loaded.policy.mode} (${loaded.modeSource})\n`);
      write(`Allow domains: ${loaded.policy.globalAllowDomains.length}\n`);
      write(`Allow entries: ${loaded.policy.allow.length}\n`);
    }
    return 0;
  }
  const raw = options.call ?? (await readFile(options.callFile ?? '', 'utf8'));
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new UsageError('tool call is not valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new UsageError('tool call must be a JSON object');
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.toolName !== 'string' || record.toolName.length === 0) {
    throw new UsageError('tool call needs a toolName string');
  }
  const params = isRecord(record.params) ? { ...record.params } : {};
  if (typeof record.skill === 'string') params.skill = record.skill;
  const call = normalizeToolCall({
    toolName: record.toolName,
    params,
    derivedPaths: record.derivedPaths,
    toolKind: record.toolKind,
    toolInputKind: record.toolInputKind,
  });
  const decision = evaluateToolCall(call, loaded.policy);
  if (options.json) {
    write(
      `${JSON.stringify({
        schemaVersion: 1,
        tool: { name: TOOL_NAME, version: TOOL_VERSION },
        policyPath: loaded.policyPath,
        ...decision,
      })}\n`,
    );
  } else {
    write(`action: ${decision.action}\n`);
    write(`wouldBlock: ${decision.wouldBlock ? 'yes' : 'no'}\n`);
    write(`${decision.reason}\n`);
  }
  return decision.wouldBlock ? 1 : 0;
}

export async function runGuardLog(options: GuardCommandOptions = {}): Promise<number> {
  const write = writer(options);
  const tail = options.tail === undefined ? 20 : Number(options.tail);
  if (!Number.isInteger(tail) || tail < 0 || tail > 1000) {
    throw new UsageError('--tail must be an integer from 0 to 1000');
  }
  const loaded = await loadGuardRuntime(loadOptions(options));
  let events;
  try {
    events = await readAuditTail(loaded.log.path, tail);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'could not read the audit log';
    throw new UsageError(message);
  }
  if (options.json) {
    write(`${JSON.stringify({ schemaVersion: 1, path: loaded.log.path, events })}\n`);
    return 0;
  }
  if (events.length === 0) {
    write(`No audit events in ${loaded.log.path}\n`);
    return 0;
  }
  for (const event of events) {
    const rules = event.ruleIds.length > 0 ? ` ${event.ruleIds.join(',')}` : '';
    write(
      `${event.time} ${event.kind} ${event.mode} ${event.action}${event.wouldBlock ? ' would-block' : ''} ${event.tool}${rules} ${event.reason}\n`,
    );
  }
  return 0;
}

function loadOptions(options: GuardCommandOptions) {
  return {
    ...(options.env ? { env: options.env } : {}),
    ...(options.cwd ? { cwd: options.cwd } : {}),
    ...(options.policy ? { policyPath: options.policy } : {}),
    ...(options.config ? { configPath: options.config } : {}),
  };
}

function writer(options: GuardCommandOptions): (text: string) => void {
  return options.stdout ?? ((text: string) => process.stdout.write(text));
}

async function fileStat(path: string): Promise<{ size: number } | undefined> {
  try {
    const info = await stat(path);
    return { size: info.size };
  } catch {
    return undefined;
  }
}

async function pluginState(env: NodeJS.ProcessEnv | undefined): Promise<{
  enabled: boolean | 'unknown';
  mode?: string;
  summary: string;
}> {
  try {
    const located = await locateOpenClaw(env);
    if (!located.configFound || !located.configParsed) {
      return {
        enabled: 'unknown',
        summary: located.configFound
          ? 'OpenClaw config was found but could not be parsed'
          : 'OpenClaw config was not found',
      };
    }
    const text = await readFile(located.configPath, 'utf8');
    const parsed = parseJson5(text);
    const root = isRecord(parsed) ? parsed : undefined;
    const plugins = isRecord(root?.plugins) ? root.plugins : undefined;
    const entries = isRecord(plugins?.entries) ? plugins.entries : undefined;
    const entry = isRecord(entries?.[GUARD_PLUGIN_ID]) ? entries[GUARD_PLUGIN_ID] : undefined;
    if (!entry) return { enabled: false, summary: 'not enabled' };
    const enabled = entry.enabled === true;
    const config = isRecord(entry.config) ? entry.config : undefined;
    const mode = typeof config?.mode === 'string' ? config.mode : undefined;
    const summary = enabled
      ? `enabled${mode ? `, plugin mode ${mode}` : ''}`
      : 'present but not enabled';
    return { enabled, ...(mode ? { mode } : {}), summary };
  } catch {
    return { enabled: 'unknown', summary: 'could not read the OpenClaw plugin entry' };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
