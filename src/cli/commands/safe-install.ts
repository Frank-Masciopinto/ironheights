import { rm } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { ironheightsHome } from '../../core/config.ts';
import type { Verdict } from '../../core/types.ts';
import { UsageError } from '../../core/errors.ts';
import { installStagedSkill } from '../../net/install.ts';
import { parseSkillRef } from '../../net/clawhub.ts';
import { locateOpenClaw } from '../../openclaw/locate.ts';
import { planLogger, stageSkill, scanFlags, type FetchFlags } from './fetch.ts';
import { executeScan } from './scan.ts';

export interface SafeInstallFlags extends FetchFlags {
  dir?: string;
  acceptReview?: boolean;
}

export async function runSafeInstall(flags: SafeInstallFlags): Promise<number> {
  const staged = await stageSkill(flags);
  const scan = await executeScan({ ...scanFlags(flags, staged.dir), allowSkipped: false });
  const log = planLogger(flags);
  const decision = installDecision(scan.verdict, flags.acceptReview === true);
  if (decision === 'refuse') {
    log(`Not installed. Staged ${staged.fileCount} files at ${staged.dir}\n`);
    if (scan.verdict === 'review') {
      log(
        'Pass --accept-review to install a review verdict. Block and incomplete are never installed.\n',
      );
    }
    return scan.code;
  }
  const ref = parseSkillRef(flags.skill);
  const env = flags.env ?? process.env;
  const parent = await skillsParent(flags.dir, env);
  log(`Installing into ${join(parent, ref.slug)}\n`);
  let installed;
  try {
    installed = await installStagedSkill({
      stagedDir: staged.dir,
      destParent: parent,
      slug: ref.slug,
      backupRoot: join(ironheightsHome(env), 'install-backup'),
      ...(flags.now ? { now: flags.now } : {}),
    });
  } catch (error) {
    log(`Not installed. Staged ${staged.fileCount} files at ${staged.dir}\n`);
    throw error;
  }
  log(`Installed: ${installed.dest}\n`);
  if (installed.backup) log(`Backup: ${installed.backup}\n`);
  if (scan.verdict === 'review') log('Accepted review because --accept-review was set.\n');
  await removeStaging(staged.dir);
  return 0;
}

function installDecision(verdict: Verdict, acceptReview: boolean): 'install' | 'refuse' {
  switch (verdict) {
    case 'no-findings':
      return 'install';
    case 'review':
      return acceptReview ? 'install' : 'refuse';
    case 'block':
    case 'incomplete':
      return 'refuse';
    default: {
      const neverVerdict: never = verdict;
      return neverVerdict;
    }
  }
}

async function removeStaging(dir: string): Promise<void> {
  const parent = dirname(dir);
  if (basename(parent).startsWith('ironheights-fetch-')) {
    await rm(parent, { recursive: true, force: true });
    return;
  }
  await rm(dir, { recursive: true, force: true });
}

async function skillsParent(dir: string | undefined, env: NodeJS.ProcessEnv): Promise<string> {
  if (dir) return dir;
  const located = await locateOpenClaw(env);
  const workspace = located.skillDirs.find((item) => item.source === 'workspace skills');
  if (!workspace) throw new UsageError('pass --dir <skills-directory>');
  return workspace.path;
}
