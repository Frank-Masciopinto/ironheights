import { Command, CommanderError } from 'commander';
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runAdvisories } from './commands/advisories.ts';
import { runAuditConfig } from './commands/audit-config.ts';
import { runBaseline, runVerify } from './commands/baseline.ts';
import { runBenchCommand } from './commands/bench.ts';
import { runCoexist } from './commands/coexist.ts';
import { runDoctor } from './commands/doctor.ts';
import { runFetch } from './commands/fetch.ts';
import { runGuardLog, runGuardPolicyCheck, runGuardStatus } from './commands/guard.ts';
import { runQuarantine } from './commands/quarantine.ts';
import { runRules } from './commands/rules.ts';
import { runSafeInstall } from './commands/safe-install.ts';
import { runScan } from './commands/scan.ts';
import { runWatch } from './commands/watch.ts';
import { runUpdate } from './commands/update.ts';
import { maybeStartBackgroundCheck, type AutoCheckHooks } from '../update/update.ts';
import { IronheightsError, UsageError } from '../core/errors.ts';
import { finishCommand } from '../util/flush.ts';
import { TOOL_VERSION } from '../version.ts';

export interface MainHooks {
  /** Test hook. Production calls global fetch. */
  fetchImpl?: typeof fetch;
  /** Test hook. Production uses the pinned advisory public key. */
  advisoryPublicKey?: Uint8Array | null;
  /** Test hook for the 6-hourly background update check. */
  autoCheck?: AutoCheckHooks | false;
}

export async function main(argv: string[], hooks: MainHooks = {}): Promise<number> {
  if (hooks.autoCheck !== undefined ? hooks.autoCheck !== false : !process.env.VITEST) {
    maybeStartBackgroundCheck(argv, hooks.autoCheck || {});
  }
  const online = argv.includes('--online');
  const rest = argv.filter((arg) => arg !== '--online');
  const helpOrVersion = rest.some(
    (arg) => arg === '--help' || arg === '-h' || arg === '--version' || arg === '-V',
  );
  const updatesFeed = rest[0] === 'advisories' && rest[1] === 'update';
  if (online && !helpOrVersion && !updatesFeed) {
    try {
      const code = await runAdvisories('update', {
        ...(hooks.fetchImpl ? { fetchImpl: hooks.fetchImpl } : {}),
        ...(hooks.advisoryPublicKey !== undefined ? { publicKey: hooks.advisoryPublicKey } : {}),
      });
      if (code !== 0) return code;
    } catch (error) {
      if (error instanceof IronheightsError) {
        process.stderr.write(`${error.message}\n`);
        return error.exitCode;
      }
      throw error;
    }
    if (rest.length === 0) return 0;
  }
  process.exitCode = undefined;
  const program = new Command();
  program
    .name('ironheights')
    .description(
      'Local-first security scanner for OpenClaw skills. Scans are local. Network is used only by fetch, safe-install, advisories update, --online, scan --llm, scan --check-registry, review, and the 6-hourly version check, which only reports new versions (off with IRONHEIGHTS_NO_UPDATE=1).',
    )
    .version(TOOL_VERSION)
    .exitOverride();

  registerScan(program, 'scan', hooks);
  registerScan(program, 'review', hooks);

  program
    .command('watch [paths...]')
    .description(
      'rescan skills automatically when one is installed, updated, or edited (content hash or version change)',
    )
    .option('--all', 'watch every configured skill directory')
    .option('--interval <seconds>', 'seconds between checks', '60')
    .option('--once', 'check once, rescan what changed, and exit')
    .option('--json', 'print JSON to stdout')
    .option('--fail-on <severity>', 'minimum severity that returns a non-zero exit code')
    .option('--config <file>', 'config file')
    .option('--no-color', 'disable color')
    .option('--quiet', 'disable color and extra emphasis')
    .action(async (paths: string[], opts: Record<string, string | boolean | undefined>) => {
      process.exitCode = await runWatch({
        paths,
        all: Boolean(opts.all),
        json: Boolean(opts.json),
        once: Boolean(opts.once),
        ...(typeof opts.interval === 'string' ? { interval: opts.interval } : {}),
        ...(typeof opts.failOn === 'string' ? { failOn: opts.failOn } : {}),
        ...(typeof opts.config === 'string' ? { config: opts.config } : {}),
        noColor: Boolean(opts.color === false || opts.noColor),
        quiet: Boolean(opts.quiet),
      });
    });

  program
    .command('baseline [action]')
    .option('--config <file>', 'config file')
    .option('--key <file>', 'sign baseline.json with this key file')
    .action(async (action: string | undefined, opts: { config?: string; key?: string }) => {
      const code = await runBaseline(action, {
        ...(opts.config ? { config: opts.config } : {}),
        ...(opts.key ? { key: opts.key } : {}),
      });
      process.exitCode = code;
    });

  program
    .command('verify')
    .option('--config <file>', 'config file')
    .option('--key <file>', 'check baseline.json.sig with this key file')
    .action(async (opts: { config?: string; key?: string }) => {
      const code = await runVerify({
        ...(opts.config ? { config: opts.config } : {}),
        ...(opts.key ? { key: opts.key } : {}),
      });
      process.exitCode = code;
    });

  program
    .command('quarantine')
    .argument('<skillOrRestore>')
    .argument('[id]')
    .action(async (skillOrRestore: string, id: string | undefined) => {
      if (skillOrRestore === 'restore') {
        process.exitCode = await runQuarantine(undefined, id, { restore: true });
        return;
      }
      process.exitCode = await runQuarantine(skillOrRestore, undefined, {});
    });

  program
    .command('rules [action] [id]')
    .action((action: string | undefined, id: string | undefined) => {
      process.exitCode = runRules(action, id);
    });

  const guard = program.command('guard').description('Runtime guard for OpenClaw tool calls');

  guard
    .command('status')
    .description('Show guard mode, policy, audit log, and whether the OpenClaw plugin is enabled')
    .option('--policy <file>', 'guard policy file')
    .option('--config <file>', 'ironheights config file')
    .option('--json', 'print JSON')
    .action(async (opts: { policy?: string; config?: string; json?: boolean }) => {
      process.exitCode = await runGuardStatus({
        ...(opts.policy ? { policy: opts.policy } : {}),
        ...(opts.config ? { config: opts.config } : {}),
        json: Boolean(opts.json),
      });
    });

  const policy = guard.command('policy').description('Check the guard policy file');
  policy
    .command('check')
    .description('Validate the policy and, with --call, evaluate one tool call')
    .option('--policy <file>', 'guard policy file')
    .option('--config <file>', 'ironheights config file')
    .option('--call <json>', 'tool call JSON')
    .option('--call-file <file>', 'file containing tool call JSON')
    .option('--json', 'print JSON')
    .action(
      async (opts: {
        policy?: string;
        config?: string;
        call?: string;
        callFile?: string;
        json?: boolean;
      }) => {
        process.exitCode = await runGuardPolicyCheck({
          ...(opts.policy ? { policy: opts.policy } : {}),
          ...(opts.config ? { config: opts.config } : {}),
          ...(opts.call ? { call: opts.call } : {}),
          ...(opts.callFile ? { callFile: opts.callFile } : {}),
          json: Boolean(opts.json),
        });
      },
    );

  guard
    .command('log')
    .description('Print recent audit log events')
    .option('--policy <file>', 'guard policy file')
    .option('--tail <n>', 'number of events to print', '20')
    .option('--json', 'print JSON')
    .action(async (opts: { policy?: string; tail?: string; json?: boolean }) => {
      process.exitCode = await runGuardLog({
        ...(opts.policy ? { policy: opts.policy } : {}),
        ...(opts.tail ? { tail: opts.tail } : {}),
        json: Boolean(opts.json),
      });
    });

  const audit = program
    .command('audit-config')
    .description(
      'Read the local OpenClaw config and report high-risk settings. Offline and read-only.',
    )
    .option('--json', 'print JSON to stdout')
    .option('--sarif <file>', 'write SARIF 2.1.0')
    .option('--md <file>', 'write a markdown report')
    .option('--fail-on <severity>', 'minimum severity that returns a non-zero exit code')
    .option('--openclaw-config <file>', 'OpenClaw config file to read')
    .option('--no-color', 'disable color')
    .option('--quiet', 'disable color and extra emphasis');
  audit.action(async (opts: AuditCommandOptions) => {
    process.exitCode = await runAuditConfig(auditFlags(opts));
  });

  const coexistOptions = (command: Command): Command =>
    command
      .option('--json', 'print JSON to stdout')
      .option('--fail-on <severity>', 'minimum severity that returns exit code 1')
      .option('--openclaw-config <file>', 'OpenClaw config file to read')
      .option('--repo <dir>', 'project folder whose pre-commit and CI files are read')
      .option('--config <file>', 'ironheights config file')
      .option('--no-color', 'disable color')
      .option('--quiet', 'disable color and extra emphasis');
  coexistOptions(
    program
      .command('coexist')
      .description(
        'Detect other security tools next to Ironheights and report conflicts. Read-only and offline.',
      ),
  ).action(async (opts: CoexistCommandOptions) => {
    process.exitCode = await runCoexist(coexistFlags(opts));
  });

  const doctor = program
    .command('doctor [action]')
    .description(
      'Show OpenClaw locations. `doctor audit` is an alias of audit-config, `doctor coexist` of coexist.',
    )
    .option('--config <file>', 'ironheights config file')
    .option('--json', 'with audit or coexist, print JSON')
    .option(
      '--fail-on <severity>',
      'with audit or coexist, minimum severity that returns a non-zero exit code',
    )
    .option('--repo <dir>', 'with coexist, project folder whose CI files are read')
    .option('--sarif <file>', 'with audit, write SARIF 2.1.0')
    .option('--md <file>', 'with audit, write a markdown report')
    .option('--openclaw-config <file>', 'with audit or coexist, OpenClaw config file to read')
    .option('--no-color', 'disable color')
    .option('--quiet', 'disable color and extra emphasis');
  doctor.action(
    async (
      action: string | undefined,
      opts: AuditCommandOptions & CoexistCommandOptions & { config?: string },
    ) => {
      if (action === 'audit') {
        process.exitCode = await runAuditConfig(auditFlags(opts));
        return;
      }
      if (action === 'coexist') {
        process.exitCode = await runCoexist(coexistFlags(opts));
        return;
      }
      if (action) throw new UsageError('doctor actions: audit, coexist');
      process.exitCode = await runDoctor(opts.config ? { config: opts.config } : {});
    },
  );

  program
    .command('bench [corpusDir]')
    .option('--external <file>', 'another tool JSON verdict file')
    .option('--corpus <dir>', 'corpus directory')
    .action(async (corpusDir: string | undefined, opts: { external?: string; corpus?: string }) => {
      process.exitCode = await runBenchCommand({
        ...((opts.corpus ?? corpusDir) ? { corpusDir: opts.corpus ?? corpusDir } : {}),
        ...(opts.external ? { external: opts.external } : {}),
      });
    });

  program
    .command('fetch')
    .argument('<skill>', 'owner/slug or owner/slug@version')
    .option('--out <dir>', 'staging directory')
    .option('--json', 'print JSON to stdout')
    .option('--sarif <file>', 'write SARIF 2.1.0')
    .option('--md <file>', 'write a markdown report')
    .option('--fail-on <severity>', 'minimum severity that returns a non-zero exit code')
    .option('--config <file>', 'config file')
    .option('--no-color', 'disable color')
    .option('--quiet', 'disable color and extra emphasis')
    .option(
      '--allow-skipped',
      'accept skipped files and directories and return the finding verdict',
    )
    .action(async (skill: string, opts: Record<string, string | boolean | undefined>) => {
      process.exitCode = await runFetch({
        skill,
        ...(typeof opts.out === 'string' ? { out: opts.out } : {}),
        json: Boolean(opts.json),
        ...(typeof opts.sarif === 'string' ? { sarif: opts.sarif } : {}),
        ...(typeof opts.md === 'string' ? { md: opts.md } : {}),
        ...(typeof opts.failOn === 'string' ? { failOn: opts.failOn } : {}),
        ...(typeof opts.config === 'string' ? { config: opts.config } : {}),
        noColor: Boolean(opts.color === false || opts.noColor),
        quiet: Boolean(opts.quiet),
        allowSkipped: Boolean(opts.allowSkipped),
        ...(hooks.fetchImpl ? { fetchImpl: hooks.fetchImpl } : {}),
        ...(hooks.advisoryPublicKey !== undefined
          ? { advisoryPublicKey: hooks.advisoryPublicKey }
          : {}),
      });
    });

  program
    .command('safe-install')
    .argument('<skill>', 'owner/slug or owner/slug@version')
    .option('--dir <dir>', 'skills directory to install into')
    .option('--accept-review', 'install when the verdict is review')
    .option('--out <dir>', 'staging directory')
    .option('--json', 'print JSON to stdout')
    .option('--config <file>', 'config file')
    .option('--no-color', 'disable color')
    .option('--quiet', 'disable color and extra emphasis')
    .action(async (skill: string, opts: Record<string, string | boolean | undefined>) => {
      process.exitCode = await runSafeInstall({
        skill,
        ...(typeof opts.dir === 'string' ? { dir: opts.dir } : {}),
        acceptReview: Boolean(opts.acceptReview),
        ...(typeof opts.out === 'string' ? { out: opts.out } : {}),
        json: Boolean(opts.json),
        ...(typeof opts.config === 'string' ? { config: opts.config } : {}),
        noColor: Boolean(opts.color === false || opts.noColor),
        quiet: Boolean(opts.quiet),
        ...(hooks.fetchImpl ? { fetchImpl: hooks.fetchImpl } : {}),
        ...(hooks.advisoryPublicKey !== undefined
          ? { advisoryPublicKey: hooks.advisoryPublicKey }
          : {}),
      });
    });

  program
    .command('update')
    .description(
      'check npm and ClawHub for a newer Ironheights and print the update commands (offer-only: never installs or updates anything)',
    )
    .option('--check', 'only report versions (same as update; kept for compatibility)')
    .option('--json', 'print JSON')
    .option(
      '--auto',
      'background mode used by the automatic check (logs to ~/.ironheights/update.log)',
    )
    .option('--disable', 'turn off automatic update checks')
    .option('--enable', 'turn automatic update checks back on')
    .action(async (opts: Record<string, boolean | undefined>) => {
      process.exitCode = await runUpdate({
        check: Boolean(opts.check),
        json: Boolean(opts.json),
        auto: Boolean(opts.auto),
        disable: Boolean(opts.disable),
        enable: Boolean(opts.enable),
        ...(hooks.fetchImpl ? { fetchImpl: hooks.fetchImpl } : {}),
      });
    });

  program
    .command('advisories')
    .argument('<action>', 'update or show')
    .action(async (action: string) => {
      process.exitCode = await runAdvisories(action, {
        ...(hooks.fetchImpl ? { fetchImpl: hooks.fetchImpl } : {}),
        ...(hooks.advisoryPublicKey !== undefined ? { publicKey: hooks.advisoryPublicKey } : {}),
      });
    });

  try {
    await program.parseAsync(argv, { from: 'user' });
  } catch (error) {
    if (error instanceof IronheightsError) {
      process.stderr.write(`${error.message}\n`);
      return error.exitCode;
    }
    if (error instanceof CommanderError) {
      if (error.code === 'commander.helpDisplayed' || error.code === 'commander.version') return 0;
      process.stderr.write(`${error.message}\n`);
      return 64;
    }
    const message = error instanceof Error ? error.message : 'internal error';
    process.stderr.write(`${message}\n`);
    return 70;
  }
  const code = process.exitCode;
  return typeof code === 'number' ? code : 0;
}

interface AuditCommandOptions {
  json?: boolean;
  sarif?: string;
  md?: string;
  failOn?: string;
  openclawConfig?: string;
  color?: boolean;
  quiet?: boolean;
}

function auditFlags(opts: AuditCommandOptions) {
  return {
    json: Boolean(opts.json),
    ...(typeof opts.sarif === 'string' ? { sarif: opts.sarif } : {}),
    ...(typeof opts.md === 'string' ? { md: opts.md } : {}),
    ...(typeof opts.failOn === 'string' ? { failOn: opts.failOn } : {}),
    ...(typeof opts.openclawConfig === 'string' ? { openclawConfig: opts.openclawConfig } : {}),
    noColor: Boolean(opts.color === false),
    quiet: Boolean(opts.quiet),
  };
}

interface CoexistCommandOptions {
  json?: boolean;
  failOn?: string;
  openclawConfig?: string;
  repo?: string;
  config?: string;
  color?: boolean;
  quiet?: boolean;
}

function coexistFlags(opts: CoexistCommandOptions) {
  return {
    json: Boolean(opts.json),
    ...(typeof opts.failOn === 'string' ? { failOn: opts.failOn } : {}),
    ...(typeof opts.openclawConfig === 'string' ? { openclawConfig: opts.openclawConfig } : {}),
    ...(typeof opts.repo === 'string' ? { repo: opts.repo } : {}),
    ...(typeof opts.config === 'string' ? { config: opts.config } : {}),
    noColor: Boolean(opts.color === false),
    quiet: Boolean(opts.quiet),
  };
}

function registerScan(program: Command, name: 'scan' | 'review', hooks: MainHooks): void {
  const description =
    name === 'review'
      ? 'scan, then ask a model for an advisory second opinion'
      : 'scan skill files with fixed rules';
  program
    .command(`${name} [paths...]`)
    .description(description)
    .option('--all', 'scan every configured skill directory')
    .option('--json', 'print JSON to stdout')
    .option('--sarif <file>', 'write SARIF 2.1.0')
    .option('--md <file>', 'write a markdown report')
    .option('--html <file>', 'write a self-contained HTML report')
    .option('--format <format>', 'stdout format: text, json, or html')
    .option(
      '--since-baseline [file]',
      'report findings that are new compared with an integrity baseline or a previous JSON result',
    )
    .option('--stdin', 'scan one piece of text from stdin')
    .option('--text <text>', 'scan one piece of text')
    .option('--fail-on <severity>', 'minimum severity that returns a non-zero exit code')
    .option('--config <file>', 'config file')
    .option('--no-color', 'disable color')
    .option('--quiet', 'disable color and extra emphasis')
    .option(
      '--allow-skipped',
      'accept skipped files and directories and return the finding verdict instead of incomplete',
    )
    .option(
      '--check-registry',
      'ask npm and PyPI whether the packages a skill installs exist (network; offline is reported as not checked)',
    )
    .option('--llm', 'ask a model for an advisory second opinion')
    .option('--llm-url <url>', 'model server base URL')
    .option('--llm-model <name>', 'model name')
    .option('--llm-api <api>', 'ollama or openai')
    .option('--llm-consent', 'send skill text to a non-localhost model server')
    .option('--dry-run', 'print the model prompt and do not send it')
    .option(
      '--print-suppressions',
      'print a suppression entry for each current finding, with evidence filled in and a placeholder reason',
    )
    .option(
      '--changed',
      'scan only skills that are new or whose content or version changed since their last scan',
    )
    .action(async (paths: string[], opts: Record<string, string | boolean | undefined>) => {
      const code = await runScan({
        paths,
        all: Boolean(opts.all),
        json: Boolean(opts.json),
        ...(typeof opts.sarif === 'string' ? { sarif: opts.sarif } : {}),
        ...(typeof opts.md === 'string' ? { md: opts.md } : {}),
        ...(typeof opts.html === 'string' ? { html: opts.html } : {}),
        ...(typeof opts.format === 'string' ? { format: opts.format } : {}),
        ...(opts.sinceBaseline === true || typeof opts.sinceBaseline === 'string'
          ? { sinceBaseline: opts.sinceBaseline }
          : {}),
        stdin: Boolean(opts.stdin),
        ...(typeof opts.text === 'string' ? { text: opts.text } : {}),
        ...(typeof opts.failOn === 'string' ? { failOn: opts.failOn } : {}),
        ...(typeof opts.config === 'string' ? { config: opts.config } : {}),
        noColor: Boolean(opts.color === false || opts.noColor),
        quiet: Boolean(opts.quiet),
        allowSkipped: Boolean(opts.allowSkipped),
        llm: name === 'review' || Boolean(opts.llm),
        ...(typeof opts.llmUrl === 'string' ? { llmUrl: opts.llmUrl } : {}),
        ...(typeof opts.llmModel === 'string' ? { llmModel: opts.llmModel } : {}),
        ...(typeof opts.llmApi === 'string' ? { llmApi: opts.llmApi } : {}),
        llmConsent: Boolean(opts.llmConsent),
        dryRun: Boolean(opts.dryRun),
        changed: Boolean(opts.changed),
        printSuppressions: Boolean(opts.printSuppressions),
        checkRegistry: Boolean(opts.checkRegistry),
        ...(hooks.advisoryPublicKey !== undefined
          ? { advisoryPublicKey: hooks.advisoryPublicKey }
          : {}),
      });
      process.exitCode = code;
    });
}

/**
 * True when this file is the process entry point.
 *
 * Unix package bins and npx are symlinks, so process.argv[1] is the link
 * while import.meta.url is the real file. Windows bins are cmd shims that
 * pass a relative path containing "..", sometimes with different drive-letter
 * casing. realpathSync.native canonicalizes both. If that call cannot resolve
 * the path, fall back to a normalized path compare so a direct node invocation
 * still runs.
 */
export function isDirectInvocation(moduleUrl: string, entryPath: string | undefined): boolean {
  if (entryPath === undefined || entryPath.length === 0) return false;
  let modulePath: string;
  try {
    modulePath = fileURLToPath(moduleUrl);
  } catch {
    return false;
  }
  try {
    return realpathSync.native(entryPath) === realpathSync.native(modulePath);
  } catch {
    return (
      resolve(entryPath) === resolve(modulePath) || pathToFileURL(entryPath).href === moduleUrl
    );
  }
}

if (isDirectInvocation(import.meta.url, process.argv[1])) {
  main(process.argv.slice(2))
    .then((code) => {
      finishCommand(code);
    })
    .catch(() => {
      finishCommand(70);
    });
}
