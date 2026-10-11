import { stat } from 'node:fs/promises';
import { UsageError } from '../../core/errors.ts';
import { SEVERITY_RANK } from '../../core/verdict.ts';
import { buildCoexistReport, renderCoexistText } from '../../coexist/report.ts';
import { colorEnabled } from '../../util/terminal.ts';
import { parseFailOn } from '../options.ts';

export interface CoexistFlags {
  json?: boolean;
  failOn?: string;
  openclawConfig?: string;
  repo?: string;
  config?: string;
  noColor?: boolean;
  quiet?: boolean;
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
  now?: Date;
}

/** Read-only. Exit 0, or 1 when a finding reaches --fail-on. Usage errors exit 64. */
export async function runCoexist(flags: CoexistFlags): Promise<number> {
  const env = flags.env ?? process.env;
  const failOn = flags.failOn ? parseFailOn(flags.failOn) : undefined;
  if (flags.openclawConfig) {
    const info = await stat(flags.openclawConfig).catch(() => undefined);
    if (!info) throw new UsageError(`OpenClaw config not found: ${flags.openclawConfig}`);
    if (!info.isFile())
      throw new UsageError(`OpenClaw config is not a file: ${flags.openclawConfig}`);
  }
  if (flags.repo) {
    const info = await stat(flags.repo).catch(() => undefined);
    if (!info?.isDirectory()) throw new UsageError(`--repo is not a folder: ${flags.repo}`);
  }
  const report = await buildCoexistReport({
    env,
    ...(flags.openclawConfig ? { openclawConfig: flags.openclawConfig } : {}),
    ...(flags.repo ? { repoDir: flags.repo } : {}),
    ...(flags.config ? { config: flags.config } : {}),
    ...(flags.now ? { now: flags.now } : {}),
  });
  const write = flags.stdout ?? ((text: string) => process.stdout.write(text));
  if (flags.json) {
    write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    write(
      `${renderCoexistText(report, colorEnabled(Boolean(flags.noColor), env) && !flags.quiet)}\n`,
    );
  }
  if (failOn && report.findings.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn])) {
    return 1;
  }
  return 0;
}
