import { UsageError } from '../../core/errors.ts';
import { executeScan, type ScanFlags } from './scan.ts';

export interface WatchFlags extends Omit<ScanFlags, 'changed'> {
  interval?: string;
  once?: boolean;
  /** Test seam. Production waits with setTimeout. */
  sleep?: (ms: number) => Promise<void>;
  /** Test seam: stop after this many rounds. */
  maxRounds?: number;
}

/**
 * Rescan installed skills whenever one is added, updated, or edited.
 * Each round runs `scan --changed`; a skill is scanned again when its content hash or
 * SKILL.md version differs from the last scan. Exit code is the worst code seen.
 */
export async function runWatch(flags: WatchFlags): Promise<number> {
  const seconds = Number(flags.interval ?? '60');
  if (!Number.isFinite(seconds) || seconds < 5) {
    throw new UsageError('--interval must be a number of seconds, 5 or more');
  }
  if (!flags.all && flags.paths.length === 0)
    throw new UsageError('watch requires a path or --all');
  const sleep = flags.sleep ?? ((ms: number) => new Promise<void>((done) => setTimeout(done, ms)));
  const rounds = flags.once ? 1 : (flags.maxRounds ?? Number.POSITIVE_INFINITY);
  let worst = 0;
  for (let round = 0; round < rounds; round += 1) {
    if (round > 0) await sleep(seconds * 1000);
    const result = await executeScan({
      ...scanFlags(flags),
      changed: true,
      quiet: round > 0 || flags.quiet,
    });
    worst = Math.max(worst, result.code);
  }
  return worst;
}

function scanFlags(flags: WatchFlags): ScanFlags {
  const copy: Partial<WatchFlags> = { ...flags };
  delete copy.interval;
  delete copy.once;
  delete copy.sleep;
  delete copy.maxRounds;
  return copy as ScanFlags;
}
