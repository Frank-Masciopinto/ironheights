import { Command, CommanderError } from 'commander';
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runAdvisories } from './commands/advisories.ts';
import { runAuditConfig } from './commands/audit-config.ts';
import { runBaseline, runVerify } from './commands/baseline.ts';
import { runBenchCommand } from './commands/bench.ts';
import { runCoexist } from './commands/coexist.ts';
import { runDrift } from './commands/drift.ts';
import { runThreatModel } from './commands/threatmodel.ts';
import { serveStdio } from '../mcp/server.ts';
import { runReport } from './commands/report.ts';
import { runDoctor } from './commands/doctor.ts';
import { runFetch } from './commands/fetch.ts';
import { runGuardLog, runGuardPolicyCheck, runGuardStatus } from './commands/guard.ts';
import { runQuarantine } from './commands/quarantine.ts';
import { runRules } from './commands/rules.ts';
import { runSafeInstall } from './commands/safe-install.ts';
import { runScan } from './commands/scan.ts';
import { runWatch } from './commands/watch.ts';
import { runActivityWatch, runInstall, runSandbox, runVerifyActivity } from './commands/runtime.ts';
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
    .option(
      '--activity',
      'record file, network, heartbeat, check and refusal activity to a signed log',
    )
    .option('--log <file>', 'activity log (default IRONHEIGHTS_HOME/activity.jsonl)')
    .option('--events <file>', 'JSONL inbox hooks, proxies and observers append events to')
    .option('--model <file>', 'threat model: declared hosts and observer heartbeat cadences')
    .option(
      '--check-budget <seconds>',
      'seconds before an open check is classed busy-queue or hang',
    )
    .option('--verify-log <file>', 'verify a signed activity log and exit')
    .option('--public-key <file>', 'public key for --verify-log')
    .action(async (paths: string[], opts: Record<string, string | boolean | undefined>) => {
      const o = (k: string) => (typeof opts[k] === 'string' ? (opts[k] as string) : undefined);
      if (o('verifyLog')) {
        process.exitCode = await runVerifyActivity(o('verifyLog') as string, o('publicKey'));
        return;
      }
      if (opts.activity) {
        process.exitCode = await runActivityWatch({
          paths,
          once: Boolean(opts.once),
          ...(o('log') ? { log: o('log') } : {}),
          ...(o('events') ? { events: o('events') } : {}),
          ...(o('model') ? { model: o('model') } : {}),
          ...(opts.interval !== '60' && o('interval') ? { interval: Number(o('interval')) } : {}),
          ...(Number(o('checkBudget')) > 0 ? { checkBudget: Number(o('checkBudget')) } : {}),
        });
        return;
      }
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

  const collect = (v: string, prev: string[] = []): string[] => [...prev, v];
  program
    .command('drift [action] [paths...]')
    .description(
      'approve skills and MCP tools, then detect changes after approval (rug pull): file hashes, SKILL.md description, new hosts, new credential paths, MCP server entries and tool descriptions. Actions: approve, check, watch. Local only.',
    )
    .option('--all', 'every configured skill directory')
    .option('--mcp <file>', 'MCP config JSON (mcpServers); repeatable', collect)
    .option('--tools <file>', 'saved MCP tools/list JSON; repeatable', collect)
    .option('--ledger <file>', 'approval ledger path (default: <ironheights home>/approvals.json)')
    .option('--interval <seconds>', 'seconds between checks for watch', '60')
    .option(
      '--adopt',
      'approve: label this first baseline "by adoption" (taken after the skill was already running)',
    )
    .option('--json', 'print JSON to stdout')
    .option('--config <file>', 'config file')
    .action(
      async (
        action: string | undefined,
        paths: string[],
        opts: Record<string, string | string[] | boolean | undefined>,
      ) => {
        process.exitCode = await runDrift({
          action,
          paths,
          all: Boolean(opts.all),
          adopt: Boolean(opts.adopt),
          json: Boolean(opts.json),
          ...(Array.isArray(opts.mcp) ? { mcp: opts.mcp } : {}),
          ...(Array.isArray(opts.tools) ? { tools: opts.tools } : {}),
          ...(typeof opts.ledger === 'string' ? { ledger: opts.ledger } : {}),
          ...(typeof opts.interval === 'string' ? { interval: opts.interval } : {}),
          ...(typeof opts.config === 'string' ? { config: opts.config } : {}),
        });
      },
    );

  program
    .command('report [targets...]')
    .description(
      'agent security posture report for a repo or an org folder of repos: skill inventory with grades, drift since approval, threat-model coverage, OWASP LLM Top 10 mapping and a trend over runs. JSON or self-contained HTML. Local only.',
    )
    .option('--title <text>', 'report title')
    .option('--ledger <file>', 'drift approval ledger to include')
    .option('--history <file>', 'JSONL file: read earlier runs for the trend and append this run')
    .option('--html <file>', 'write a self-contained HTML report')
    .option('--json-file <file>', 'write the JSON report to a file')
    .option('--json', 'print JSON to stdout')
    .option('--fail-on-block', 'exit 2 when any skill is blocked')
    .option(
      '--fail-on-incomplete',
      'exit 2 when any loaded skill was not fully inspected (skipped files or runtime-fetched instructions)',
    )
    .option('--valid-days <n>', 'days until the HTML report marks itself expired (default 7)')
    .option(
      '--check-interval <hours>',
      'grey grades by check interval: 1x degraded, 2x greyed, 3x grade hidden',
    )
    .option('--refusals <file>', 'JSONL refusal log: denials and what the agent did next')
    .option(
      '--artifacts <file>',
      'creation ledger (JSON or JSONL) of hooks, tokens and files skills created',
    )
    .option(
      '--loaded <file>',
      'runtime attestation JSON: repo/path -> content digest the agent loaded',
    )
    .option('--fixes <file>', 'JSON: repo/path -> version that fixes the open findings')
    .option(
      '--env-id <id>',
      'environment id for the stamp (default IRONHEIGHTS_ENV_ID or a host hash)',
    )
    .option('--image-digest <digest>', 'container image digest for the stamp')
    .option('--receipts <file>', 'MCP receipts JSONL for the reversal rate')
    .option('--reversal-window <n>', 'checks in the reversal-rate window (default 20)')
    .option(
      '--verify-sla <days>',
      'days before an unresolved loss path shows as contained pending check',
    )
    .option('--from-watch <log>', 'signed activity log from watch --activity: grade what happened')
    .option(
      '--watch-key <file>',
      'public key for --from-watch (default IRONHEIGHTS_HOME/watch-key.pub.pem)',
    )
    .option('--verify <report.json>', 're-check a saved JSON report against the files on disk now')
    .option('--config <file>', 'config file')
    .action(async (targets: string[], opts: Record<string, string | boolean | undefined>) => {
      const s = (k: string): string | undefined =>
        typeof opts[k] === 'string' ? (opts[k] as string) : undefined;
      process.exitCode = await runReport({
        targets,
        ...(s('title') ? { title: s('title') } : {}),
        ...(s('ledger') ? { ledger: s('ledger') } : {}),
        ...(s('history') ? { history: s('history') } : {}),
        ...(s('html') ? { html: s('html') } : {}),
        ...(s('jsonFile') ? { jsonFile: s('jsonFile') } : {}),
        ...(s('config') ? { config: s('config') } : {}),
        json: Boolean(opts.json),
        failOnBlock: Boolean(opts.failOnBlock),
        failOnIncomplete: Boolean(opts.failOnIncomplete),
        ...(s('validDays') !== undefined && Number.isFinite(Number(s('validDays')))
          ? { validDays: Number(s('validDays')) }
          : {}),
        ...(Number(s('checkInterval')) > 0
          ? { checkIntervalHours: Number(s('checkInterval')) }
          : {}),
        ...(s('refusals') ? { refusals: s('refusals') } : {}),
        ...(s('artifacts') ? { artifacts: s('artifacts') } : {}),
        ...(s('loaded') ? { loaded: s('loaded') } : {}),
        ...(s('fixes') ? { fixes: s('fixes') } : {}),
        ...(s('envId') ? { envId: s('envId') } : {}),
        ...(s('imageDigest') ? { imageDigest: s('imageDigest') } : {}),
        ...(s('receipts') ? { receipts: s('receipts') } : {}),
        ...(Number(s('reversalWindow')) > 0 ? { reversalWindow: Number(s('reversalWindow')) } : {}),
        ...(s('verifySla') !== undefined && Number.isFinite(Number(s('verifySla')))
          ? { verifySlaDays: Number(s('verifySla')) }
          : {}),
        ...(s('verify') ? { verify: s('verify') } : {}),
        ...(s('fromWatch') ? { fromWatch: s('fromWatch') } : {}),
        ...(s('watchKey') ? { watchKey: s('watchKey') } : {}),
      });
    });

  program
    .command('mcp')
    .description(
      'run Ironheights as an MCP server over stdio: check_skill (grade, verdict, findings, drift), verify_check, drift_status, threatmodel_check, get_rule. Add to any MCP client with: npx -y ironheights@<version> mcp',
    )
    .action(async () => {
      process.exitCode = await serveStdio();
    });

  program
    .command('threatmodel [action]')
    .description(
      'agent threat model as code: init writes ironheights.threatmodel.yml from the skills and MCP servers in a repo, check fails when a skill or MCP server reaches outside it (hosts, paths, env, tokens, shell, grade), diff --base <ref> reports only what a PR adds. Local only.',
    )
    .option('--dir <dir>', 'repository directory', '.')
    .option('--model <file>', 'model file relative to --dir', 'ironheights.threatmodel.yml')
    .option(
      '--skills <dir>',
      'skill directory; repeatable (default: skillDirs in the model)',
      collect,
    )
    .option('--mcp <file>', 'MCP config JSON; repeatable', collect)
    .option('--base <ref>', 'git base ref for diff')
    .option('--ledger <file>', 'also report drift since drift approve')
    .option('--no-grade', 'skip the scan grade (faster)')
    .option(
      '--fail-on-uncovered',
      'exit 2 when a host, token, env var, MCP server or webhook is not mentioned in the model',
    )
    .option(
      '--fail-on-widen',
      'diff: fail when a capability passes only because the same change widened the model',
    )
    .option(
      '--review',
      'diff: review tier for widenings: reasons rows, an approver who is not the author, evidence that predates the change',
    )
    .option('--author <login>', 'diff: author of the change (PR author)')
    .option(
      '--author-kind <kind>',
      'diff: human or agent (an agent-authored widening needs a human approver)',
    )
    .option('--approvers <logins>', 'diff: comma-separated logins that approved the change')
    .option('--force', 'overwrite an existing model on init')
    .option('--markdown <file>', 'write a Markdown summary (PR comment)')
    .option('--sarif <file>', 'write SARIF 2.1.0')
    .option('--json', 'print JSON to stdout')
    .option('--config <file>', 'config file')
    .action(
      async (
        action: string | undefined,
        opts: Record<string, string | string[] | boolean | undefined>,
      ) => {
        const str = (k: string): string | undefined =>
          typeof opts[k] === 'string' ? (opts[k] as string) : undefined;
        process.exitCode = await runThreatModel({
          action,
          ...(str('dir') ? { dir: str('dir') } : {}),
          ...(str('model') ? { model: str('model') } : {}),
          ...(Array.isArray(opts.skills) ? { skillDirs: opts.skills } : {}),
          ...(Array.isArray(opts.mcp) ? { mcp: opts.mcp } : {}),
          ...(str('base') ? { base: str('base') } : {}),
          ...(str('ledger') ? { ledger: str('ledger') } : {}),
          ...(str('markdown') ? { markdown: str('markdown') } : {}),
          ...(str('sarif') ? { sarif: str('sarif') } : {}),
          ...(str('config') ? { config: str('config') } : {}),
          noGrade: opts.grade === false,
          failOnUncovered: Boolean(opts.failOnUncovered),
          failOnWiden: Boolean(opts.failOnWiden),
          review: Boolean(opts.review),
          ...(str('author') ? { author: str('author') } : {}),
          ...(str('authorKind') === 'agent' || str('authorKind') === 'human'
            ? { authorKind: str('authorKind') as 'agent' | 'human' }
            : {}),
          ...(str('approvers')
            ? {
                approvers: (str('approvers') as string)
                  .split(',')
                  .map((x) => x.trim())
                  .filter(Boolean),
              }
            : {}),
          force: Boolean(opts.force),
          json: Boolean(opts.json),
        });
      },
    );

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

  const sandbox = program
    .command('sandbox')
    .description(
      'run a skill once in a throwaway container and compare what it did with the threat model',
    );
  sandbox
    .command('run <skill> [entry...]')
    .description(
      'run once with no network except a logging proxy; record writes, hosts and child processes; fail on anything the threat model does not declare',
    )
    .option('--model <file>', 'threat model file (default ironheights.threatmodel.yml)')
    .option(
      '--image <image>',
      'container image (default node:20-bookworm-slim or IRONHEIGHTS_SANDBOX_IMAGE)',
    )
    .option('--timeout <seconds>', 'kill the run after this many seconds (default 120)')
    .option('--trace <file>', 'compare a recorded trace instead of running')
    .option('--save-trace <file>', 'write the observed trace as JSON')
    .option(
      '--external <file>',
      'outside record (JSON list of {kind, value, count}) to reconcile with',
    )
    .option('--fail-on-unused', 'also fail when a declared write never happened')
    .option('--json', 'print JSON to stdout')
    .action(
      async (
        skill: string,
        entry: string[],
        opts: Record<string, string | boolean | undefined>,
      ) => {
        const o = (k: string) => (typeof opts[k] === 'string' ? (opts[k] as string) : undefined);
        process.exitCode = await runSandbox({
          skill,
          entry,
          json: Boolean(opts.json),
          failOnUnused: Boolean(opts.failOnUnused),
          ...(o('model') ? { model: o('model') } : {}),
          ...(o('image') ? { image: o('image') } : {}),
          ...(Number(o('timeout')) > 0 ? { timeout: Number(o('timeout')) } : {}),
          ...(o('trace') ? { trace: o('trace') } : {}),
          ...(o('saveTrace') ? { saveTrace: o('saveTrace') } : {}),
          ...(o('external') ? { external: o('external') } : {}),
        });
      },
    );

  program
    .command('install')
    .argument('<skill>', 'local skill folder, owner/slug or owner/slug@version')
    .description(
      'guarded install: write only the exact checked bytes and the pinned dependency closure; refuse on any mismatch',
    )
    .option('--dir <dir>', 'skills directory to install into')
    .option('--lock <file>', 'skill lock (files, digest, closure) to match exactly')
    .option('--expect-digest <sha256>', 'contentDigest from check_skill to match')
    .option('--write-lock <file>', 'write a lock for this skill and exit')
    .option(
      '--with-deps',
      'install the pinned closure (npm ci --ignore-scripts, pip --require-hashes)',
    )
    .option('--accept-review', 'install when the scan verdict is review')
    .option('--json', 'print JSON to stdout')
    .option('--config <file>', 'config file')
    .action(async (skill: string, opts: Record<string, string | boolean | undefined>) => {
      const o = (k: string) => (typeof opts[k] === 'string' ? (opts[k] as string) : undefined);
      process.exitCode = await runInstall({
        skill,
        json: Boolean(opts.json),
        withDeps: Boolean(opts.withDeps),
        acceptReview: Boolean(opts.acceptReview),
        ...(o('dir') ? { dir: o('dir') } : {}),
        ...(o('lock') ? { lock: o('lock') } : {}),
        ...(o('expectDigest') ? { expectDigest: o('expectDigest') } : {}),
        ...(o('writeLock') ? { writeLock: o('writeLock') } : {}),
        ...(o('config') ? { config: o('config') } : {}),
        ...(hooks.fetchImpl ? { fetchImpl: hooks.fetchImpl } : {}),
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
