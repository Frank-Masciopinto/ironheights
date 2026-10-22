import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import { TOOL_VERSION, REPOSITORY_URL } from '../version.ts';

/**
 * Update check. Scans never touch the network; this is the only call made
 * without a flag, and it only reads two version numbers. Disable with
 * IRONHEIGHTS_NO_UPDATE=1 or `ironheights update --disable`.
 */

export const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
export const CHECK_TIMEOUT_MS = 3000;
export const NPM_LATEST_URL = 'https://registry.npmjs.org/ironheights/latest';
export const CLAWHUB_SKILL_URL = 'https://clawhub.ai/api/v1/skills/ironheights';
export const SLSA_PROVENANCE = 'https://slsa.dev/provenance/v1';
const MAX_BODY = 512 * 1024;
const VERSION_RE = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export interface UpdateState {
  lastCheck?: number;
  npmLatest?: string;
  skillLatest?: string;
  skillInstalled?: string;
}

export interface UpdateEnv {
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  fetchImpl?: typeof fetch;
}

/** Parse a strict semver string. Returns undefined when it is not one. */
export function parseVersion(v: string): [number, number, number, string | undefined] | undefined {
  const m = VERSION_RE.exec(v.trim());
  if (!m) return undefined;
  return [Number(m[1]), Number(m[2]), Number(m[3]), m[4]];
}

/** -1, 0, 1. Throws on non-semver input so callers never act on garbage. */
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) throw new Error(`not a version: ${pa ? b : a}`);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] as number) - (pb[i] as number);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (pa[3] === pb[3]) return 0;
  if (pa[3] === undefined) return 1;
  if (pb[3] === undefined) return -1;
  return pa[3] < pb[3] ? -1 : 1;
}

/** True only when candidate is a valid stable version strictly newer than current. */
export function isNewer(candidate: string | undefined, current: string | undefined): boolean {
  if (!candidate || !current) return false;
  const p = parseVersion(candidate);
  if (!p || p[3] !== undefined) return false;
  try {
    return compareVersions(candidate, current) > 0;
  } catch {
    return false;
  }
}

function statePath(env: NodeJS.ProcessEnv): string {
  return join(ironheightsHome(env), 'update-check.json');
}
function configPath(env: NodeJS.ProcessEnv): string {
  return join(ironheightsHome(env), 'update-config.json');
}

export function readState(env: NodeJS.ProcessEnv = process.env): UpdateState {
  try {
    const raw = JSON.parse(readFileSync(statePath(env), 'utf8')) as unknown;
    return raw && typeof raw === 'object' ? (raw as UpdateState) : {};
  } catch {
    return {};
  }
}

export function writeState(state: UpdateState, env: NodeJS.ProcessEnv = process.env): void {
  try {
    mkdirSync(ironheightsHome(env), { recursive: true });
    writeFileSync(statePath(env), `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  } catch {
    // A read-only home must never break a scan.
  }
}

export function autoUpdateConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  try {
    const raw = JSON.parse(readFileSync(configPath(env), 'utf8')) as { autoUpdate?: unknown };
    return raw.autoUpdate !== false;
  } catch {
    return true;
  }
}

export function setAutoUpdate(enabled: boolean, env: NodeJS.ProcessEnv = process.env): string {
  mkdirSync(ironheightsHome(env), { recursive: true });
  const file = configPath(env);
  writeFileSync(file, `${JSON.stringify({ autoUpdate: enabled }, null, 2)}\n`);
  return file;
}

function truthy(v: string | undefined): boolean {
  return v !== undefined && v !== '' && v !== '0' && v.toLowerCase() !== 'false';
}

/** Why automatic checks are off, or undefined when they are on. */
export function autoCheckDisabledReason(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (truthy(env.IRONHEIGHTS_NO_UPDATE)) return 'IRONHEIGHTS_NO_UPDATE is set';
  if (truthy(env.CI)) return 'CI is set';
  if (!autoUpdateConfigured(env)) return 'autoUpdate is false in update-config.json';
  return undefined;
}

/** Throttle: true when no check ran in the last 6 hours. Clock skew into the future counts as due. */
export function checkIsDue(state: UpdateState, now: number): boolean {
  const last = state.lastCheck;
  if (typeof last !== 'number' || !Number.isFinite(last)) return true;
  if (last > now) return true;
  return now - last >= CHECK_INTERVAL_MS;
}

async function getJson(url: string, fetchImpl: typeof fetch): Promise<unknown> {
  const res = await fetchImpl(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
    headers: {
      accept: 'application/json',
      'user-agent': `ironheights/${TOOL_VERSION} (+${REPOSITORY_URL})`,
    },
  });
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_BODY) throw new Error(`${url} response too large`);
  return JSON.parse(text) as unknown;
}

export interface NpmRelease {
  version: string;
  integrity?: string;
  provenance: boolean;
}

export async function fetchNpmLatest(
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<NpmRelease> {
  const body = (await getJson(NPM_LATEST_URL, fetchImpl)) as {
    name?: unknown;
    version?: unknown;
    dist?: { integrity?: unknown; attestations?: { provenance?: { predicateType?: unknown } } };
  };
  if (
    body.name !== 'ironheights' ||
    typeof body.version !== 'string' ||
    !parseVersion(body.version)
  ) {
    throw new Error('unexpected npm registry response');
  }
  const integrity = typeof body.dist?.integrity === 'string' ? body.dist.integrity : undefined;
  return {
    version: body.version,
    ...(integrity ? { integrity } : {}),
    provenance: body.dist?.attestations?.provenance?.predicateType === SLSA_PROVENANCE,
  };
}

export async function fetchSkillLatest(
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<string> {
  const body = (await getJson(CLAWHUB_SKILL_URL, fetchImpl)) as {
    skill?: { slug?: unknown };
    latestVersion?: { version?: unknown };
  };
  const v = body.latestVersion?.version;
  if (body.skill?.slug !== 'ironheights' || typeof v !== 'string' || !parseVersion(v)) {
    throw new Error('unexpected ClawHub response');
  }
  return v;
}

export interface CheckResult {
  current: string;
  npmLatest?: string;
  npmProvenance?: boolean;
  npmIntegrity?: string;
  skillLatest?: string;
  skillInstalled?: string;
  cliUpdate: boolean;
  skillUpdate: boolean;
  errors: string[];
}

/** Read both versions. Never throws: network failures land in `errors`. */
export async function checkVersions(opts: UpdateEnv = {}): Promise<CheckResult> {
  const env = opts.env ?? process.env;
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  const now = (opts.now ?? Date.now)();
  const state = readState(env);
  const errors: string[] = [];
  const [npm, skill] = await Promise.allSettled([
    fetchNpmLatest(fetchImpl),
    fetchSkillLatest(fetchImpl),
  ]);
  const result: CheckResult = {
    current: TOOL_VERSION,
    cliUpdate: false,
    skillUpdate: false,
    errors,
  };
  if (npm.status === 'fulfilled') {
    result.npmLatest = npm.value.version;
    result.npmProvenance = npm.value.provenance;
    if (npm.value.integrity) result.npmIntegrity = npm.value.integrity;
    result.cliUpdate = isNewer(npm.value.version, TOOL_VERSION);
  } else errors.push(`npm: ${String((npm.reason as Error)?.message ?? npm.reason)}`);
  if (skill.status === 'fulfilled') {
    result.skillLatest = skill.value;
    if (state.skillInstalled) result.skillInstalled = state.skillInstalled;
    result.skillUpdate = state.skillInstalled ? isNewer(skill.value, state.skillInstalled) : true; // unknown local version: let clawhub decide, it never downgrades a tracked skill
  } else errors.push(`clawhub: ${String((skill.reason as Error)?.message ?? skill.reason)}`);
  writeState(
    {
      ...state,
      lastCheck: now,
      ...(result.npmLatest ? { npmLatest: result.npmLatest } : {}),
      ...(result.skillLatest ? { skillLatest: result.skillLatest } : {}),
    },
    env,
  );
  return result;
}

export interface OfferOptions {
  log: (line: string) => void;
}

/**
 * Report updates found by checkVersions and print the commands the user can
 * run. Offer-only: this never installs, updates or runs anything. Never
 * offers a downgrade, and only offers a CLI version that npm reports with
 * SLSA provenance and an sha512 integrity. Returns the offered commands.
 */
export function offerUpdates(check: CheckResult, opts: OfferOptions): string[] {
  const commands: string[] = [];
  if (check.cliUpdate && check.npmLatest && isNewer(check.npmLatest, TOOL_VERSION)) {
    if (!check.npmProvenance || !check.npmIntegrity?.startsWith('sha512-')) {
      opts.log(
        `ironheights ${check.npmLatest} is on npm but has no npm provenance or sha512 integrity; not offering it.`,
      );
    } else {
      const cmd = `npm install -g ironheights@${check.npmLatest}`;
      commands.push(cmd);
      opts.log(
        `ironheights ${check.npmLatest} is available (you have ${TOOL_VERSION}, npm provenance verified). To update, run: ${cmd} (or npx ironheights@${check.npmLatest})`,
      );
    }
  }
  if (check.skillUpdate && check.skillLatest) {
    const cmd = 'clawhub update ironheights';
    commands.push(cmd);
    opts.log(`ClawHub skill ironheights ${check.skillLatest} is available. To update, run: ${cmd}`);
  }
  if (commands.length) opts.log('Nothing was changed. Ironheights never updates itself.');
  return commands;
}

export interface AutoCheckHooks {
  env?: NodeJS.ProcessEnv;
  now?: () => number;
  spawnImpl?: (args: string[]) => void;
}

/**
 * Called on every command. Local work only: reads a timestamp and, when a
 * check is due, starts a detached background `update --auto` and returns at
 * once. Never throws.
 */
export function maybeStartBackgroundCheck(argv: string[], hooks: AutoCheckHooks = {}): boolean {
  try {
    const env = hooks.env ?? process.env;
    if (argv[0] === 'update') return false;
    if (argv.some((a) => ['--help', '-h', '--version', '-V'].includes(a))) return false;
    if (autoCheckDisabledReason(env)) return false;
    const now = (hooks.now ?? Date.now)();
    const state = readState(env);
    if (!checkIsDue(state, now)) return false;
    writeState({ ...state, lastCheck: now }, env); // claim the slot so parallel runs do not all check
    const args = ['update', '--auto'];
    if (hooks.spawnImpl) hooks.spawnImpl(args);
    else {
      const entry = process.argv[1];
      if (!entry) return false;
      const child = spawn(process.execPath, [entry, ...args], {
        detached: true,
        stdio: 'ignore',
        env: { ...env, IRONHEIGHTS_UPDATE_CHILD: '1' },
      });
      child.on('error', () => undefined);
      child.unref();
    }
    return true;
  } catch {
    return false;
  }
}

export function updateLogPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(ironheightsHome(env), 'update.log');
}
