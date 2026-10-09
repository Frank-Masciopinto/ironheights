import { readFile } from 'node:fs/promises';
import { ironheightsHome, loadConfig } from '../../core/config.ts';
import { exitCodeFor, scoreFindings, verdictFor } from '../../core/verdict.ts';
import { UsageError } from '../../core/errors.ts';
import { baselinePath } from '../../integrity/baseline.ts';
import { saveBaseline, verifyBaseline } from '../../integrity/verify.ts';

export async function runBaseline(
  action: string | undefined,
  options: { config?: string; env?: NodeJS.ProcessEnv; stdout?: (text: string) => void },
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
  const baseline = await saveBaseline(config, home);
  write(`wrote ${baselinePath(home)} (${Object.keys(baseline.files).length} files)\n`);
  return 0;
}

export async function runVerify(options: {
  config?: string;
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
}): Promise<number> {
  const env = options.env ?? process.env;
  const home = ironheightsHome(env);
  const config = await loadConfig({
    ...(options.config ? { explicitPath: options.config } : {}),
    env,
  });
  const result = await verifyBaseline(config, home);
  const write = options.stdout ?? ((text: string) => process.stdout.write(text));
  write(
    `added: ${result.added.length}\nmodified: ${result.modified.length}\nremoved: ${result.removed.length}\nmodeChanged: ${result.modeChanged.length}\n`,
  );
  if (result.baselineTampered) write('baseline: treeHash mismatch\n');
  for (const finding of result.findings) {
    write(`${finding.ruleId} ${finding.file} ${finding.message}\n`);
  }
  const score = scoreFindings(result.findings);
  const verdict = verdictFor(result.findings, config.thresholds);
  write(`score: ${score}\nVerdict: ${verdict}\nAbsence of findings is not proof of safety.\n`);
  return exitCodeFor(verdict, result.findings, config.failOn);
}
