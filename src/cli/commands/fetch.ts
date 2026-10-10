import type { ScanFlags } from './scan.ts';
import { executeScan } from './scan.ts';
import { downloadSkill, parseSkillRef, type DownloadResult } from '../../net/clawhub.ts';
import { loadConfig } from '../../core/config.ts';

export interface FetchFlags {
  skill: string;
  out?: string;
  json?: boolean;
  sarif?: string;
  md?: string;
  failOn?: string;
  config?: string;
  noColor?: boolean;
  quiet?: boolean;
  allowSkipped?: boolean;
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
  stderr?: (text: string) => void;
  fetchImpl?: typeof fetch;
  advisoryPublicKey?: Uint8Array | null;
  now?: Date;
}

export async function runFetch(flags: FetchFlags): Promise<number> {
  const staged = await stageSkill(flags);
  const scan = await executeScan(scanFlags(flags, staged.dir));
  const log = planLogger(flags);
  log(`Staged ${staged.fileCount} files at ${staged.dir}\n`);
  return scan.code;
}

export async function stageSkill(flags: FetchFlags): Promise<DownloadResult> {
  const ref = parseSkillRef(flags.skill);
  const env = flags.env ?? process.env;
  const config = await loadConfig({
    ...(flags.config ? { explicitPath: flags.config } : {}),
    env,
  });
  return downloadSkill({
    ref,
    limits: config.limits,
    ...(flags.out ? { outDir: flags.out } : {}),
    log: planLogger(flags),
    ...(flags.fetchImpl ? { fetchImpl: flags.fetchImpl } : {}),
  });
}

export function scanFlags(flags: FetchFlags, dir: string): ScanFlags {
  const ref = parseSkillRef(flags.skill);
  return {
    paths: [dir],
    ...(flags.json ? { json: true } : {}),
    ...(flags.sarif ? { sarif: flags.sarif } : {}),
    ...(flags.md ? { md: flags.md } : {}),
    ...(flags.failOn ? { failOn: flags.failOn } : {}),
    ...(flags.config ? { config: flags.config } : {}),
    ...(flags.noColor ? { noColor: true } : {}),
    ...(flags.quiet ? { quiet: true } : {}),
    ...(flags.allowSkipped ? { allowSkipped: true } : {}),
    ...(flags.env ? { env: flags.env } : {}),
    ...(flags.stdout ? { stdout: flags.stdout } : {}),
    ...(flags.now ? { now: flags.now } : {}),
    ...(flags.advisoryPublicKey !== undefined
      ? { advisoryPublicKey: flags.advisoryPublicKey }
      : {}),
    skillOwner: ref.owner,
  };
}

export function planLogger(flags: FetchFlags): (text: string) => void {
  if (flags.json) return flags.stderr ?? ((text: string) => process.stderr.write(text));
  return flags.stdout ?? ((text: string) => process.stdout.write(text));
}
