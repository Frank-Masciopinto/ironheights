import { readFile } from 'node:fs/promises';
import { ironheightsHome, loadConfig } from '../../core/config.ts';
import { formatGrade, gradeFor } from '../../core/grade.ts';
import { applySuppressions } from '../../core/suppress.ts';
import { exitCodeFor, scoreFindings, verdictFor } from '../../core/verdict.ts';
import { SAFETY_REMINDER } from '../../version.ts';
import { UsageError } from '../../core/errors.ts';
import { baselinePath } from '../../integrity/baseline.ts';
import { saveBaseline, verifyBaseline } from '../../integrity/verify.ts';

export async function runBaseline(
  action: string | undefined,
  options: {
    config?: string;
    key?: string;
    env?: NodeJS.ProcessEnv;
    stdout?: (text: string) => void;
  },
): Promise<number> {
  if (action !== 'create' && action !== 'update' && action !== 'show') {
    throw new UsageError('baseline requires create, update, or show');
  }
  const env = options.env ?? process.env;
  const home = ironheightsHome(env);
  const write = options.stdout ?? ((text: string) => process.stdout.write(text));
  if (action === 'show') {
    const raw = await readFile(baselinePath(home), 'utf8').catch(() => {
      throw new UsageError('no baseline found');
    });
    const baseline = JSON.parse(raw) as {
      createdAt?: string;
      toolVersion?: string;
      roots?: string[];
      treeHash?: string;
      files?: object;
    };
    write(
      `createdAt: ${baseline.createdAt ?? ''}\ntoolVersion: ${baseline.toolVersion ?? ''}\nroots: ${(baseline.roots ?? []).length}\nfiles: ${Object.keys(baseline.files ?? {}).length}\ntreeHash: ${baseline.treeHash ?? ''}\n`,
    );
    return 0;
  }
  const config = await loadConfig({
    ...(options.config ? { explicitPath: options.config } : {}),
    env,
  });
  const keyPath = options.key ?? env.IRONHEIGHTS_BASELINE_KEY;
  const baseline = await saveBaseline(config, home, new Date(), keyPath ? { keyPath } : {});
  write(`wrote ${baselinePath(home)} (${Object.keys(baseline.files).length} files)\n`);
  if (keyPath) write(`signed ${baselinePath(home)}.sig\n`);
  return 0;
}

export async function runVerify(options: {
  config?: string;
  key?: string;
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
}): Promise<number> {
  const env = options.env ?? process.env;
  const home = ironheightsHome(env);
  const config = await loadConfig({
    ...(options.config ? { explicitPath: options.config } : {}),
    env,
  });
  const keyPath = options.key ?? env.IRONHEIGHTS_BASELINE_KEY;
  const result = await verifyBaseline(config, home, keyPath ? { keyPath } : {});
  const write = options.stdout ?? ((text: string) => process.stdout.write(text));
  write(
    `added: ${result.added.length}\nmodified: ${result.modified.length}\nremoved: ${result.removed.length}\nmodeChanged: ${result.modeChanged.length}\n`,
  );
  if (result.treeHashMismatch) write('baseline: treeHash mismatch\n');
  if (result.signatureMismatch) write('baseline: signature mismatch\n');
  if (result.signatureChecked && !result.signatureMismatch) write('baseline: signature ok\n');
  for (const finding of result.findings) {
    write(`${finding.ruleId} ${finding.file} ${finding.message}\n`);
  }
  const outcome = applySuppressions(result.findings, [], config);
  for (const item of outcome.suppressed) {
    write(`suppressed ${item.ruleId} ${item.file} reason=${item.reason}\n`);
  }
  for (const item of outcome.refused) {
    write(`suppression refused ${item.ruleId} ${item.file} ${item.detail}\n`);
  }
  for (const item of outcome.stale) {
    write(
      `stale suppression ${item.ruleId} ${item.path ?? '*'} evidence=${item.evidence} reason=${item.reason}\n`,
    );
  }
  for (const finding of outcome.active) {
    if (!finding.acceptance) continue;
    write(`${finding.acceptance} ${finding.ruleId} ${finding.file}\n`);
  }
  const score = scoreFindings(outcome.active);
  const verdict = verdictFor(outcome.active, config.thresholds);
  const grade = gradeFor(score, 0);
  write(`score: ${score}\nVerdict: ${verdict}\nGrade: ${formatGrade(grade)}\n${SAFETY_REMINDER}\n`);
  return exitCodeFor(verdict, outcome.active, config.failOn);
}
