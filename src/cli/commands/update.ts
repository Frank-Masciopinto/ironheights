import { appendFileSync, mkdirSync } from 'node:fs';
import { ironheightsHome } from '../../core/config.ts';
import { TOOL_VERSION } from '../../version.ts';
import {
  autoCheckDisabledReason,
  checkVersions,
  setAutoUpdate,
  offerUpdates,
  updateLogPath,
} from '../../update/update.ts';

export interface UpdateFlags {
  check?: boolean;
  auto?: boolean;
  json?: boolean;
  disable?: boolean;
  enable?: boolean;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
  stdout?: (t: string) => void;
}

export async function runUpdate(flags: UpdateFlags): Promise<number> {
  const env = flags.env ?? process.env;
  const out = flags.stdout ?? ((t: string) => process.stdout.write(t));
  if (flags.disable || flags.enable) {
    const file = setAutoUpdate(Boolean(flags.enable), env);
    out(`Automatic update checks ${flags.enable ? 'enabled' : 'disabled'} (${file}).\n`);
    return 0;
  }
  let log = (line: string) => out(`${line}\n`);
  if (flags.auto) {
    // Background child: silent, and only when still allowed.
    if (autoCheckDisabledReason(env)) return 0;
    log = (line: string) => {
      try {
        mkdirSync(ironheightsHome(env), { recursive: true });
        appendFileSync(updateLogPath(env), `${new Date().toISOString()} ${line}\n`);
      } catch {
        /* ignore */
      }
    };
  }
  const check = await checkVersions({
    env,
    ...(flags.fetchImpl ? { fetchImpl: flags.fetchImpl } : {}),
  });
  if (flags.json) {
    out(`${JSON.stringify(check, null, 2)}\n`);
  } else if (!flags.auto) {
    log(
      `ironheights CLI: ${TOOL_VERSION} installed, ${check.npmLatest ?? 'unknown'} on npm${check.cliUpdate ? ' (update available)' : ''}`,
    );
    log(
      `ClawHub skill: ${check.skillLatest ?? 'unknown'} latest${check.skillInstalled ? `, ${check.skillInstalled} last installed by ironheights` : ''}`,
    );
    for (const e of check.errors) log(`Could not check ${e}`);
  }
  if (check.errors.length === 2 && !flags.auto && !flags.json) {
    log('Version check failed; nothing was changed. Scans are unaffected.');
  }
  if (flags.check) return 0;
  if (!check.cliUpdate && !check.skillUpdate) {
    if (!flags.auto && !flags.json) log('Up to date.');
    return 0;
  }
  offerUpdates(check, { log });
  return 0;
}
