import { stat, writeFile } from 'node:fs/promises';
import { auditOpenClawConfig } from '../../audit/audit-config.ts';
import { UsageError } from '../../core/errors.ts';
import { blockingSkipCount, exitCodeFor } from '../../core/verdict.ts';
import { colorEnabled } from '../../util/terminal.ts';
import { renderHuman } from '../output/human.ts';
import { renderJson } from '../output/json.ts';
import { renderMarkdown } from '../output/markdown.ts';
import { renderSarif } from '../output/sarif.ts';
import { parseFailOn } from '../options.ts';

export interface AuditConfigFlags {
  json?: boolean;
  sarif?: string;
  md?: string;
  failOn?: string;
  openclawConfig?: string;
  noColor?: boolean;
  quiet?: boolean;
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
  now?: Date;
}

export async function runAuditConfig(flags: AuditConfigFlags): Promise<number> {
  const env: NodeJS.ProcessEnv = { ...(flags.env ?? process.env) };
  if (flags.openclawConfig) {
    try {
      const info = await stat(flags.openclawConfig);
      if (!info.isFile())
        throw new UsageError(`OpenClaw config is not a file: ${flags.openclawConfig}`);
    } catch (error) {
      if (error instanceof UsageError) throw error;
      throw new UsageError(`OpenClaw config not found: ${flags.openclawConfig}`);
    }
    env.OPENCLAW_CONFIG_PATH = flags.openclawConfig;
  }
  const failOn = flags.failOn ? parseFailOn(flags.failOn) : undefined;
  const result = await auditOpenClawConfig(env);
  const scannedAt = (flags.now ?? new Date()).toISOString();
  const write = flags.stdout ?? ((text: string) => process.stdout.write(text));
  if (flags.json) {
    const payload = JSON.parse(renderJson(result.skills, result.verdict, scannedAt)) as Record<
      string,
      unknown
    >;
    payload.command = 'audit-config';
    payload.configPath = result.configPath;
    payload.configFound = result.configFound;
    payload.configParsed = result.configParsed;
    payload.nativeAudit = 'openclaw security audit';
    payload.limits = result.limits;
    write(`${JSON.stringify(payload, null, 2)}\n`);
  } else {
    const header = [
      `OpenClaw config: ${result.configFound ? 'found' : 'missing'} ${result.configPath}`,
      'Static config read. Does not replace `openclaw security audit`.',
    ];
    if (!result.configFound) {
      header.push('The file is missing, so OpenClaw safe defaults were not re-checked here.');
    }
    const body = renderHuman(
      result.skills,
      result.verdict,
      colorEnabled(Boolean(flags.noColor), env) && !flags.quiet,
    );
    write(`${header.join('\n')}\n${body}\n`);
  }
  if (flags.sarif) await writeFile(flags.sarif, renderSarif(result.skills));
  if (flags.md) await writeFile(flags.md, renderMarkdown(result.skills, result.verdict));
  const findings = result.skills.flatMap((skill) => skill.findings);
  const filesSkipped = result.skills.reduce((sum, skill) => sum + blockingSkipCount(skill), 0);
  return exitCodeFor(result.verdict, findings, failOn, { filesSkipped });
}
