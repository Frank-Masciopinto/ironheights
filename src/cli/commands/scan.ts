import { stat, writeFile } from 'node:fs/promises';
import { UsageError } from '../../core/errors.ts';
import { loadConfig } from '../../core/config.ts';
import { scanPath } from '../../core/scanner.ts';
import { exitCodeFor, worstVerdict } from '../../core/verdict.ts';
import type { Severity } from '../../core/types.ts';
import { colorEnabled } from '../../util/terminal.ts';
import { renderHuman } from '../output/human.ts';
import { renderJson } from '../output/json.ts';
import { renderMarkdown } from '../output/markdown.ts';
import { renderSarif } from '../output/sarif.ts';

export interface ScanFlags {
  all?: boolean;
  json?: boolean;
  sarif?: string;
  md?: string;
  failOn?: string;
  config?: string;
  noColor?: boolean;
  quiet?: boolean;
  allowSkipped?: boolean;
  paths: string[];
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
  now?: Date;
}

export async function runScan(flags: ScanFlags): Promise<number> {
  const env = flags.env ?? process.env;
  const config = await loadConfig({
    ...(flags.config ? { explicitPath: flags.config } : {}),
    env,
  });
  if (flags.failOn) config.failOn = parseFailOn(flags.failOn);
  const targets = flags.all ? config.skillDirs : flags.paths;
  if (!flags.all && targets.length === 0) throw new UsageError('scan requires a path or --all');
  const skills = [];
  let scannedAt = (flags.now ?? new Date()).toISOString();
  for (const target of targets) {
    if (!flags.all) {
      try {
        await stat(target);
      } catch {
        throw new UsageError(`path not found: ${target}`);
      }
    }
    const result = await scanPath(target, config, {
      ...(flags.now ? { now: flags.now } : {}),
      allowSkipped: flags.allowSkipped === true,
    });
    scannedAt = result.scannedAt;
    skills.push(...result.skills);
  }
  const verdict = worstVerdict(skills.map((skill) => skill.verdict));
  const write = flags.stdout ?? ((text: string) => process.stdout.write(text));
  if (flags.json) write(renderJson(skills, verdict, scannedAt));
  else
    write(
      `${renderHuman(skills, verdict, colorEnabled(Boolean(flags.noColor), env) && !flags.quiet)}\n`,
    );
  if (flags.sarif) await writeFile(flags.sarif, renderSarif(skills));
  if (flags.md) await writeFile(flags.md, renderMarkdown(skills, verdict));
  const findings = skills.flatMap((skill) => skill.findings);
  const filesSkipped = skills.reduce((sum, skill) => sum + skill.filesSkipped.length, 0);
  return exitCodeFor(verdict, findings, config.failOn, {
    filesSkipped,
    allowSkipped: flags.allowSkipped === true,
  });
}

function parseFailOn(value: string): Severity {
  switch (value) {
    case 'info':
    case 'low':
    case 'medium':
    case 'high':
    case 'critical':
      return value;
    default:
      throw new UsageError('--fail-on must be info, low, medium, high, or critical');
  }
}
