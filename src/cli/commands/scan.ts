import { stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { annotateKnownSecurityTools } from '../../coexist/annotate.ts';
import { annotateSkillReports } from '../../advisories/match.ts';
import { readAdvisoryCache } from '../../advisories/cache.ts';
import { pinnedAdvisoryPublicKey } from '../../advisories/pinned-key.ts';
import type { AdvisoryFeedNote, Finding, SkillReport, Verdict } from '../../core/types.ts';
import { UsageError, NetworkError } from '../../core/errors.ts';
import { ironheightsHome, loadConfig } from '../../core/config.ts';
import { TEXT_SCAN_LIMIT } from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import { discoverSkillRoots, scanPath, scanText } from '../../core/scanner.ts';
import { gradeFromSkills } from '../../core/grade.ts';
import type { Grade } from '../../core/types.ts';
import {
  findChangedSkills,
  readScanState,
  recordScans,
  scanStatePath,
  writeScanState,
  type ChangeCheck,
  type ScanState,
  type SkillFingerprint,
} from '../../core/scan-state.ts';
import { applySinceBaseline } from '../../core/since-baseline.ts';
import {
  renderSuppressionConfig,
  SUPPRESSION_REASON_PLACEHOLDER,
  reconcileEvidenceDrift,
} from '../../core/suppress.ts';
import { blockingSkipCount, exitCodeFor, worstVerdict } from '../../core/verdict.ts';
import { baselinePath } from '../../integrity/baseline.ts';
import { LLM_RULE_ID, skipNote } from '../../llm/constants.ts';
import type { PostOptions, PostResult } from '../../llm/client.ts';
import { parseLlmApi } from '../../llm/endpoint.ts';
import { reviewSkills, type LlmReviewReport, type LlmSkillReview } from '../../llm/review.ts';
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
  llm?: boolean;
  llmUrl?: string;
  llmModel?: string;
  llmApi?: string;
  llmConsent?: boolean;
  dryRun?: boolean;
  /** Scan only skills whose content hash or version changed since their last scan. */
  changed?: boolean;
  /** Print pasteable evidence-bound suppression entries instead of the report. */
  printSuppressions?: boolean;
  /** Ask npm and PyPI whether install names exist (network). */
  checkRegistry?: boolean;
  /** Test seam for --check-registry. */
  registryFetch?: typeof fetch;
  paths: string[];
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
  stderr?: (text: string) => void;
  /** Test seam. Production uses the built-in HTTP client. */
  post?: (options: PostOptions) => Promise<PostResult>;
  now?: Date;
  /** Test hook. The CLI does not accept an alternate advisory key. */
  advisoryPublicKey?: Uint8Array | null;
  /** Publisher handle, set by fetch and safe-install. */
  skillOwner?: string;
  /** Test seam for the terminal check. Production reads process.stdout/stderr.isTTY. */
  isTTY?: boolean;
}

export interface ScanExecution {
  code: number;
  verdict: Verdict;
  skills: SkillReport[];
}

export const CLAWHUB_URL = 'https://clawhub.ai/frank-masciopinto/skills/ironheights';
export const STAR_HINT = `If Ironheights is useful, a star on ClawHub helps others find it: ${CLAWHUB_URL} (hide: IRONHEIGHTS_NO_STAR_HINT=1 or --quiet)`;

function envFlag(value: string | undefined): boolean {
  return value !== undefined && value !== '' && value !== '0' && value.toLowerCase() !== 'false';
}

/**
 * One line after a clean, human-readable scan in an interactive terminal. Never shown in CI,
 * in pipes, with --quiet, for JSON/HTML output, or when IRONHEIGHTS_NO_STAR_HINT is set.
 */
export function shouldShowStarHint(
  flags: ScanFlags,
  verdict: Verdict,
  env: NodeJS.ProcessEnv,
  isTTY: boolean,
): boolean {
  if (verdict !== 'no-findings' || !isTTY) return false;
  if (
    flags.quiet ||
    flags.dryRun ||
    flags.json ||
    flags.printSuppressions ||
    (flags.format && flags.format !== 'text')
  ) {
    return false;
  }
  if (envFlag(env.IRONHEIGHTS_NO_STAR_HINT) || envFlag(env.CI)) return false;
  return true;
}

export async function runScan(flags: ScanFlags): Promise<number> {
  const result = await executeScan(flags);
  const env = flags.env ?? process.env;
  const isTTY = flags.isTTY ?? Boolean(process.stdout.isTTY && process.stderr.isTTY);
  if (shouldShowStarHint(flags, result.verdict, env, isTTY)) {
    const emit = flags.stderr ?? ((text: string) => process.stderr.write(text));
    emit(`${STAR_HINT}\n`);
  }
  return result.code;
}

export async function executeScan(flags: ScanFlags): Promise<ScanExecution> {
  const api = parseLlmApi(flags.llmApi);
  if (flags.dryRun && !flags.llm) {
    throw new UsageError('--dry-run requires --llm or the review command');
  }
  const env = flags.env ?? process.env;
  const config = await loadConfig({
    ...(flags.config ? { explicitPath: flags.config } : {}),
    env,
  });
  if (flags.failOn) config.failOn = parseFailOn(flags.failOn);
  const format = resolveFormat(flags);
  const scanMode = resolveScanMode(flags);
  let skills: SkillReport[] = [];
  let changedState: ScanState | undefined;
  const changedFingerprints: SkillFingerprint[] = [];
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
    if (flags.changed) {
      for (const target of targets) {
        if (flags.all) continue;
        try {
          await stat(target);
        } catch {
          throw new UsageError(`path not found: ${target}`);
        }
      }
      const roots: string[] = [];
      for (const target of targets) roots.push(...(await discoverSkillRoots(target)));
      changedState = await readScanState(scanStatePath(ironheightsHome(env)));
      const check = await findChangedSkills(roots, changedState);
      const emit = flags.stderr ?? ((text: string) => process.stderr.write(text));
      if (check.changed.length === 0) {
        if (!flags.quiet) {
          emit(
            `No skill changed since its last scan (${roots.length} checked). Nothing to rescan.\n`,
          );
        }
        if (format === 'json') {
          (flags.stdout ?? ((text: string) => process.stdout.write(text)))(
            renderJson([], 'no-findings', scannedAt, { scanMode }),
          );
        }
        return { code: 0, verdict: 'no-findings', skills: [] };
      }
      for (const item of check.changed) {
        changedFingerprints.push(item.fingerprint);
        emit(`Rescanning ${item.fingerprint.root}: ${describeChange(item)}\n`);
      }
    }
    const scanTargets = flags.changed ? changedFingerprints.map((item) => item.root) : targets;
    for (const target of scanTargets) {
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
        ...(flags.checkRegistry ? { checkRegistry: true } : {}),
        ...(flags.registryFetch ? { fetchImpl: flags.registryFetch } : {}),
      });
      scannedAt = result.scannedAt;
      skills.push(...result.skills);
    }
  }

  const advisory = await applyAdvisoryCache(skills, config, env, flags);
  skills = advisory.skills;
  if (scanMode === 'directory') skills = annotateKnownSecurityTools(skills);

  if (flags.sinceBaseline !== undefined) {
    const source =
      flags.sinceBaseline === true ? baselinePath(ironheightsHome(env)) : flags.sinceBaseline;
    skills = await applySinceBaseline(skills, source, {
      thresholds: config.thresholds,
      allowSkipped: flags.allowSkipped === true,
      scanMode,
    });
  }
  skills = reconcileEvidenceDrift(skills, config.suppressions);

  const verdict = worstVerdict(skills.map((skill) => skill.verdict));
  const limitNote = scanMode === 'text' ? TEXT_SCAN_LIMIT : undefined;
  const write = flags.stdout ?? ((text: string) => process.stdout.write(text));
  const emitNotice = flags.stderr ?? ((text: string) => process.stderr.write(text));
  let reported = skills;
  let llmReport: LlmReviewReport | undefined;
  if (flags.llm && !flags.printSuppressions) {
    if (flags.dryRun) {
      write(`Deterministic verdict: ${verdict}\nDry-run did not contact the model server.\n\n`);
    }
    if (scanMode === 'text') {
      const reason = 'a text scan has no skill directory to send';
      (flags.dryRun ? write : emitNotice)(`${skipNote(reason)}\n`);
      llmReport = {
        enabled: true,
        advisory: true,
        status: 'skipped',
        reviews: skills.map((skill) => textSkip(skill.skillName, reason)),
      };
    } else {
      const reviewed = await reviewSkills({
        skills,
        config,
        ...(flags.llmUrl ? { url: flags.llmUrl } : {}),
        ...(flags.llmModel ? { model: flags.llmModel } : {}),
        ...(api ? { api } : {}),
        consent: flags.llmConsent === true,
        dryRun: flags.dryRun === true,
        env,
        emit: flags.dryRun ? write : emitNotice,
        ...(flags.post ? { post: flags.post } : {}),
      });
      reported = reviewed.skills;
      llmReport = reviewed.report;
    }
  }
  const code = exitCodeFor(verdict, deterministicFindings(skills), config.failOn, {
    filesSkipped: skills.reduce((sum, skill) => sum + blockingSkipCount(skill), 0),
    allowSkipped: flags.allowSkipped === true,
  });
  if (flags.dryRun) return { skills, verdict, code };
  if (flags.changed && changedState) {
    const grades = new Map<string, Grade>();
    for (const skill of skills) grades.set(resolve(skill.root), gradeFromSkills([skill]));
    await writeScanState(
      scanStatePath(ironheightsHome(env)),
      recordScans(changedState, changedFingerprints, skills, grades, flags.now ?? new Date()),
    );
  }
  const color = colorEnabled(Boolean(flags.noColor), env) && !flags.quiet;
  const renderContext = {
    scanMode,
    ...(limitNote ? { limitNote } : {}),
    ...(advisory.note ? { advisory: advisory.note } : {}),
    ...(llmReport ? { llmReview: llmReport } : {}),
  };
  if (flags.printSuppressions) {
    write(renderSuppressionConfig(reported.flatMap((skill) => skill.findings)));
    emitNotice(
      `Replace "${SUPPRESSION_REASON_PLACEHOLDER}" with a reason of at least 8 characters. The placeholder does not suppress a finding.\n`,
    );
  } else if (format === 'json') {
    write(renderJson(reported, verdict, scannedAt, renderContext));
  } else if (format === 'html') {
    write(`${renderHtml(reported, verdict, scannedAt, scanMode, advisory.note, llmReport)}\n`);
  } else {
    write(`${renderHuman(reported, verdict, color, scanMode, advisory.note, llmReport)}\n`);
  }
  if (flags.sarif) await writeFile(flags.sarif, renderSarif(reported, scanMode));
  if (flags.md)
    await writeFile(
      flags.md,
      renderMarkdown(reported, verdict, scanMode, advisory.note, llmReport),
    );
  if (flags.html)
    await writeFile(
      flags.html,
      renderHtml(reported, verdict, scannedAt, scanMode, advisory.note, llmReport),
    );
  return { skills: reported, verdict, code };
}

function describeChange(item: ChangeCheck): string {
  if (item.reason === 'new') return 'not scanned before';
  if (item.reason === 'version') {
    return `version changed (${item.previous?.version ?? 'none'} -> ${item.fingerprint.version ?? 'none'})`;
  }
  return 'content changed since the last scan';
}

function textSkip(skillName: string, reason: string): LlmSkillReview {
  return {
    skillName,
    status: 'skipped',
    endpoint: 'unset',
    model: 'unset',
    api: 'ollama',
    redactedSecrets: 0,
    reason,
  };
}

function deterministicFindings(skills: SkillReport[]): Finding[] {
  return skills.flatMap((skill) =>
    skill.findings.filter((finding) => finding.ruleId !== LLM_RULE_ID),
  );
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
