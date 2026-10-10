import { stat, writeFile } from 'node:fs/promises';
import { annotateSkillReports } from '../../advisories/match.ts';
import { readAdvisoryCache } from '../../advisories/cache.ts';
import { pinnedAdvisoryPublicKey } from '../../advisories/pinned-key.ts';
import type { AdvisoryFeedNote } from '../../core/types.ts';
import { UsageError, NetworkError } from '../../core/errors.ts';
import { ironheightsHome, loadConfig } from '../../core/config.ts';
import { TEXT_SCAN_LIMIT } from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import { scanPath, scanText } from '../../core/scanner.ts';
import { applySinceBaseline } from '../../core/since-baseline.ts';
import { exitCodeFor, worstVerdict } from '../../core/verdict.ts';
import type { SkillReport, Verdict } from '../../core/types.ts';
import { baselinePath } from '../../integrity/baseline.ts';
import { parseFailOn } from '../options.ts';
import { colorEnabled } from '../../util/terminal.ts';
import { renderHtml } from '../output/html.ts';
import { renderHuman } from '../output/human.ts';
import { renderJson } from '../output/json.ts';
import { renderMarkdown } from '../output/markdown.ts';
import { renderSarif } from '../output/sarif.ts';

export interface ScanFlags {
  all?: boolean;
  json?: boolean;
  sarif?: string;
  md?: string;
  html?: string;
  format?: string;
  failOn?: string;
  config?: string;
  noColor?: boolean;
  quiet?: boolean;
  allowSkipped?: boolean;
  sinceBaseline?: string | true;
  stdin?: boolean;
  stdinText?: string;
  text?: string;
  paths: string[];
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
  now?: Date;
  /** Test hook. The CLI does not accept an alternate advisory key. */
  advisoryPublicKey?: Uint8Array | null;
  /** Publisher handle, set by fetch and safe-install. */
  skillOwner?: string;
}

export interface ScanExecution {
  code: number;
  verdict: Verdict;
  skills: SkillReport[];
}

export async function runScan(flags: ScanFlags): Promise<number> {
  return (await executeScan(flags)).code;
}

export async function executeScan(flags: ScanFlags): Promise<ScanExecution> {
  const env = flags.env ?? process.env;
  const config = await loadConfig({
    ...(flags.config ? { explicitPath: flags.config } : {}),
    env,
  });
  if (flags.failOn) config.failOn = parseFailOn(flags.failOn);
  const format = resolveFormat(flags);
  const scanMode = resolveScanMode(flags);
  let skills: SkillReport[] = [];
  let scannedAt = (flags.now ?? new Date()).toISOString();

  if (scanMode === 'text') {
    const text = flags.stdin ? await stdinText(flags) : (flags.text ?? '');
    const result = await scanText(text, config, {
      label: flags.stdin ? 'stdin' : 'text',
      ...(flags.now ? { now: flags.now } : {}),
      allowSkipped: flags.allowSkipped === true,
    });
    scannedAt = result.scannedAt;
    skills = result.skills;
  } else {
    const targets = flags.all ? config.skillDirs : flags.paths;
    if (!flags.all && targets.length === 0) throw new UsageError('scan requires a path or --all');
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
  }

  const advisory = await applyAdvisoryCache(skills, config, env, flags);
  skills = advisory.skills;

  if (flags.sinceBaseline !== undefined) {
    const source =
      flags.sinceBaseline === true ? baselinePath(ironheightsHome(env)) : flags.sinceBaseline;
    skills = await applySinceBaseline(skills, source, {
      thresholds: config.thresholds,
      allowSkipped: flags.allowSkipped === true,
      scanMode,
    });
  }

  const verdict = worstVerdict(skills.map((skill) => skill.verdict));
  const limitNote = scanMode === 'text' ? TEXT_SCAN_LIMIT : undefined;
  const write = flags.stdout ?? ((text: string) => process.stdout.write(text));
  const renderContext = {
    scanMode,
    ...(limitNote ? { limitNote } : {}),
    ...(advisory.note ? { advisory: advisory.note } : {}),
  };
  if (format === 'json') {
    write(renderJson(skills, verdict, scannedAt, renderContext));
  } else if (format === 'html') {
    write(`${renderHtml(skills, verdict, scannedAt, scanMode, advisory.note)}\n`);
  } else {
    write(
      `${renderHuman(
        skills,
        verdict,
        colorEnabled(Boolean(flags.noColor), env) && !flags.quiet,
        scanMode,
        advisory.note,
      )}\n`,
    );
  }
  if (flags.sarif) await writeFile(flags.sarif, renderSarif(skills, scanMode));
  if (flags.md) await writeFile(flags.md, renderMarkdown(skills, verdict, scanMode, advisory.note));
  if (flags.html)
    await writeFile(flags.html, renderHtml(skills, verdict, scannedAt, scanMode, advisory.note));
  const findings = skills.flatMap((skill) => skill.findings);
  const filesSkipped = skills.reduce((sum, skill) => sum + skill.filesSkipped.length, 0);
  return {
    skills,
    verdict,
    code: exitCodeFor(verdict, findings, config.failOn, {
      filesSkipped,
      allowSkipped: flags.allowSkipped === true,
    }),
  };
}

function resolveScanMode(flags: ScanFlags): ScanMode {
  const textMode = flags.stdin === true || flags.text !== undefined;
  if (flags.stdin && flags.text !== undefined) {
    throw new UsageError('pass either --stdin or --text');
  }
  if (textMode && (flags.all || flags.paths.length > 0)) {
    throw new UsageError('a text scan does not take a path or --all');
  }
  if (!textMode && !flags.all && flags.paths.length === 0) {
    throw new UsageError('scan requires a path, --all, --stdin, or --text');
  }
  return textMode ? 'text' : 'directory';
}

function resolveFormat(flags: ScanFlags): 'text' | 'json' | 'html' {
  if (flags.json && flags.format && flags.format !== 'json') {
    throw new UsageError('pass either --json or --format');
  }
  if (flags.json) return 'json';
  if (!flags.format) return 'text';
  switch (flags.format) {
    case 'text':
    case 'json':
    case 'html':
      return flags.format;
    default:
      throw new UsageError('--format must be text, json, or html');
  }
}

async function stdinText(flags: ScanFlags): Promise<string> {
  if (flags.stdinText !== undefined) return flags.stdinText;
  if (process.stdin.isTTY) throw new UsageError('scan --stdin reads text from a pipe');
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}
async function applyAdvisoryCache(
  skills: SkillReport[],
  config: Awaited<ReturnType<typeof loadConfig>>,
  env: NodeJS.ProcessEnv,
  flags: ScanFlags,
): Promise<{ skills: SkillReport[]; note?: AdvisoryFeedNote }> {
  const publicKey =
    flags.advisoryPublicKey !== undefined ? flags.advisoryPublicKey : pinnedAdvisoryPublicKey();
  const cache = await readAdvisoryCache(ironheightsHome(env), publicKey);
  if (cache.status === 'missing') return { skills };
  if (cache.status === 'rejected') throw new NetworkError(cache.message);
  const annotated = await annotateSkillReports(skills, cache.document, config, {
    allowSkipped: flags.allowSkipped === true,
    ...(flags.skillOwner ? { owner: flags.skillOwner } : {}),
  });
  return {
    skills: annotated,
    note: { entries: cache.document.advisories.length, generatedAt: cache.document.generatedAt },
  };
}
