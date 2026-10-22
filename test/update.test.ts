import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runUpdate } from '../src/cli/commands/update.ts';
import { main } from '../src/cli/index.ts';
import {
  CHECK_INTERVAL_MS,
  autoCheckDisabledReason,
  checkIsDue,
  checkVersions,
  compareVersions,
  isNewer,
  maybeStartBackgroundCheck,
  offerUpdates,
  readState,
  setAutoUpdate,
  writeState,
  type CheckResult,
} from '../src/update/update.ts';
import { TOOL_VERSION } from '../src/version.ts';

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});
async function home(): Promise<NodeJS.ProcessEnv> {
  const d = await mkdtemp(join(tmpdir(), 'ih-upd-'));
  dirs.push(d);
  return { IRONHEIGHTS_HOME: d };
}

function fakeFetch(npm: unknown, skill: unknown): typeof fetch {
  return (async (url: string | URL) => {
    const body = String(url).includes('npmjs') ? npm : skill;
    if (body instanceof Error) throw body;
    return new Response(JSON.stringify(body), { status: 200 });
  }) as typeof fetch;
}
const npmBody = (version: string, provenance = true) => ({
  name: 'ironheights',
  version,
  dist: {
    integrity: 'sha512-abc',
    ...(provenance
      ? { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } }
      : {}),
  },
});
const skillBody = (version: string) => ({
  skill: { slug: 'ironheights' },
  latestVersion: { version },
});

describe('version compare', () => {
  it('orders versions numerically', () => {
    expect(compareVersions('0.10.0', '0.9.9')).toBe(1);
    expect(compareVersions('1.0.0', '1.0.0')).toBe(0);
    expect(compareVersions('1.0.0-rc.1', '1.0.0')).toBe(-1);
    expect(compareVersions('0.6.0', '0.7.0')).toBe(-1);
  });
  it('never treats older, equal, prerelease or garbage as newer', () => {
    expect(isNewer('0.8.0', '0.7.0')).toBe(true);
    expect(isNewer('0.6.0', '0.7.0')).toBe(false);
    expect(isNewer('0.7.0', '0.7.0')).toBe(false);
    expect(isNewer('0.8.0-beta.1', '0.7.0')).toBe(false);
    expect(isNewer('latest', '0.7.0')).toBe(false);
    expect(isNewer('9.9.9; rm -rf /', '0.7.0')).toBe(false);
  });
});

describe('throttle', () => {
  it('is due with no state, not due within 6h, due after 6h', () => {
    const now = 1_000_000_000_000;
    expect(checkIsDue({}, now)).toBe(true);
    expect(checkIsDue({ lastCheck: now - CHECK_INTERVAL_MS + 1000 }, now)).toBe(false);
    expect(checkIsDue({ lastCheck: now - CHECK_INTERVAL_MS }, now)).toBe(true);
    expect(checkIsDue({ lastCheck: now + 60_000 }, now)).toBe(true);
  });
  it('starts at most one background check per 6 hours', async () => {
    const env = await home();
    const spawned: string[][] = [];
    let t = 1_000_000_000_000;
    const hooks = { env, now: () => t, spawnImpl: (a: string[]) => spawned.push(a) };
    expect(maybeStartBackgroundCheck(['scan', '.'], hooks)).toBe(true);
    expect(maybeStartBackgroundCheck(['scan', '.'], hooks)).toBe(false);
    t += CHECK_INTERVAL_MS - 1;
    expect(maybeStartBackgroundCheck(['scan', '.'], hooks)).toBe(false);
    t += 1;
    expect(maybeStartBackgroundCheck(['rules'], hooks)).toBe(true);
    expect(spawned).toEqual([
      ['update', '--auto'],
      ['update', '--auto'],
    ]);
  });
  it('main() starts the check without blocking the command', async () => {
    const env = await home();
    const spawned: string[][] = [];
    const code = await main(['rules', 'list'], {
      autoCheck: { env, spawnImpl: (a) => spawned.push(a) },
    });
    expect(code).toBe(0);
    expect(spawned).toHaveLength(1);
  });
});

describe('opt-out and CI', () => {
  it('honours IRONHEIGHTS_NO_UPDATE, CI and the config flag', async () => {
    const env = await home();
    expect(autoCheckDisabledReason(env)).toBeUndefined();
    expect(autoCheckDisabledReason({ ...env, IRONHEIGHTS_NO_UPDATE: '1' })).toMatch(/NO_UPDATE/);
    expect(autoCheckDisabledReason({ ...env, CI: 'true' })).toMatch(/CI/);
    expect(autoCheckDisabledReason({ ...env, CI: 'false' })).toBeUndefined();
    setAutoUpdate(false, env);
    expect(autoCheckDisabledReason(env)).toMatch(/autoUpdate/);
    setAutoUpdate(true, env);
    expect(autoCheckDisabledReason(env)).toBeUndefined();
  });
  it('spawns nothing when opted out or in CI', async () => {
    const env = await home();
    const spawned: string[][] = [];
    const s = (a: string[]) => spawned.push(a);
    maybeStartBackgroundCheck(['scan'], {
      env: { ...env, IRONHEIGHTS_NO_UPDATE: '1' },
      spawnImpl: s,
    });
    maybeStartBackgroundCheck(['scan'], { env: { ...env, CI: 'true' }, spawnImpl: s });
    expect(spawned).toHaveLength(0);
    expect(readState(env).lastCheck).toBeUndefined();
  });
  it('the background child does nothing when opted out', async () => {
    const env = { ...(await home()), CI: '1' };
    let fetched = false;
    const fetchImpl = (async () => {
      fetched = true;
      throw new Error('x');
    }) as typeof fetch;
    expect(await runUpdate({ auto: true, env, fetchImpl })).toBe(0);
    expect(fetched).toBe(false);
  });
});

describe('network failure', () => {
  it('records errors, changes nothing and returns 0 for --check', async () => {
    const env = await home();
    const out: string[] = [];
    const code = await runUpdate({
      env,
      fetchImpl: fakeFetch(new Error('offline'), new Error('offline')),
      stdout: (t) => out.push(t),
    });
    expect(code).toBe(0);
    expect(out.join('')).toMatch(/Scans are unaffected/);
  });
  it('checkVersions never throws on bad JSON', async () => {
    const env = await home();
    const r = await checkVersions({ env, fetchImpl: fakeFetch({ nope: 1 }, { nope: 1 }) });
    expect(r.errors).toHaveLength(2);
    expect(r.cliUpdate).toBe(false);
  });
});

describe('offer-only updates', () => {
  const base = (over: Partial<CheckResult>): CheckResult => ({
    current: TOOL_VERSION,
    cliUpdate: false,
    skillUpdate: false,
    errors: [],
    ...over,
  });
  it('never offers a CLI downgrade', async () => {
    const env = await home();
    const r = await checkVersions({
      env,
      fetchImpl: fakeFetch(npmBody('0.1.0'), skillBody('1.0.0')),
    });
    expect(r.cliUpdate).toBe(false);
    expect(
      offerUpdates({ ...r, cliUpdate: true, skillUpdate: false }, { log: () => undefined }),
    ).toEqual([]);
  });
  it('never offers a skill downgrade once its version is known', async () => {
    const env = await home();
    writeState({ skillInstalled: '1.2.0' }, env);
    const r = await checkVersions({
      env,
      fetchImpl: fakeFetch(npmBody(TOOL_VERSION), skillBody('1.1.0')),
    });
    expect(r.skillUpdate).toBe(false);
  });
  it('offers the exact pinned CLI version only with provenance', () => {
    const logs: string[] = [];
    expect(
      offerUpdates(
        base({
          cliUpdate: true,
          npmLatest: '99.0.0',
          npmProvenance: false,
          npmIntegrity: 'sha512-x',
        }),
        { log: (l) => logs.push(l) },
      ),
    ).toEqual([]);
    expect(logs.join()).toMatch(/provenance/);
    expect(
      offerUpdates(
        base({
          cliUpdate: true,
          npmLatest: '99.0.0',
          npmProvenance: true,
          npmIntegrity: 'sha512-x',
        }),
        { log: () => undefined },
      ),
    ).toEqual(['npm install -g ironheights@99.0.0']);
  });
  it('offers clawhub update for the skill without recording it as installed', async () => {
    const env = await home();
    const logs: string[] = [];
    expect(
      offerUpdates(base({ skillUpdate: true, skillLatest: '1.2.0' }), { log: (l) => logs.push(l) }),
    ).toEqual(['clawhub update ironheights']);
    expect(logs.join('\n')).toMatch(/Nothing was changed/);
    expect(readState(env).skillInstalled).toBeUndefined();
  });
  it('update reports, offers commands, returns 0 and installs nothing', async () => {
    const env = await home();
    const out: string[] = [];
    const code = await runUpdate({
      env,
      fetchImpl: fakeFetch(npmBody('99.0.0'), skillBody('9.0.0')),
      stdout: (t) => out.push(t),
    });
    expect(code).toBe(0);
    const text = out.join('');
    expect(text).toMatch(/99\.0\.0 on npm \(update available\)/);
    expect(text).toMatch(/run: npm install -g ironheights@99\.0\.0/);
    expect(text).toMatch(/run: clawhub update ironheights/);
    expect(text).toMatch(/never updates itself/);
    expect(
      JSON.parse(await readFile(join(env.IRONHEIGHTS_HOME ?? '', 'update-check.json'), 'utf8'))
        .npmLatest,
    ).toBe('99.0.0');
  });
  it('the source has no code path that spawns npm or clawhub', async () => {
    const src = await readFile(join(process.cwd(), 'src/update/update.ts'), 'utf8');
    expect(src).not.toMatch(/spawnSync|'install', '-g'|'update', 'ironheights'/);
  });
});
