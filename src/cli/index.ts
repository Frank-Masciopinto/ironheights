import { Command, CommanderError } from 'commander';
import { pathToFileURL } from 'node:url';
import { runBaseline, runVerify } from './commands/baseline.ts';
import { runBenchCommand } from './commands/bench.ts';
import { runDoctor } from './commands/doctor.ts';
import { runQuarantine } from './commands/quarantine.ts';
import { runRules } from './commands/rules.ts';
import { runScan } from './commands/scan.ts';
import { IronheightsError } from '../core/errors.ts';
import { TOOL_VERSION } from '../version.ts';

export async function main(argv: string[]): Promise<number> {
  if (argv.includes('--online')) {
    process.stdout.write('not implemented in MVP\n');
    return 0;
  }
  process.exitCode = undefined;
  const program = new Command();
  program
    .name('ironheights')
    .description('Local-first security scanner for OpenClaw skills')
    .version(TOOL_VERSION)
    .exitOverride();

  program
    .command('scan [paths...]')
    .option('--all', 'scan every configured skill directory')
    .option('--json', 'print JSON to stdout')
    .option('--sarif <file>', 'write SARIF 2.1.0')
    .option('--md <file>', 'write a markdown report')
    .option('--fail-on <severity>', 'minimum severity that returns a non-zero exit code')
    .option('--config <file>', 'config file')
    .option('--no-color', 'disable color')
    .option('--quiet', 'disable color and extra emphasis')
    .action(async (paths: string[], opts: Record<string, string | boolean | undefined>) => {
      const code = await runScan({
        paths,
        all: Boolean(opts.all),
        json: Boolean(opts.json),
        ...(typeof opts.sarif === 'string' ? { sarif: opts.sarif } : {}),
        ...(typeof opts.md === 'string' ? { md: opts.md } : {}),
        ...(typeof opts.failOn === 'string' ? { failOn: opts.failOn } : {}),
        ...(typeof opts.config === 'string' ? { config: opts.config } : {}),
        noColor: Boolean(opts.color === false || opts.noColor),
        quiet: Boolean(opts.quiet),
      });
      process.exitCode = code;
    });

  program
    .command('baseline [action]')
    .option('--config <file>', 'config file')
    .action(async (action: string | undefined, opts: { config?: string }) => {
      const code = await runBaseline(action, opts.config ? { config: opts.config } : {});
      process.exitCode = code;
    });

  program
    .command('verify')
    .option('--config <file>', 'config file')
    .action(async (opts: { config?: string }) => {
      const code = await runVerify(opts.config ? { config: opts.config } : {});
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

  program
    .command('doctor')
    .option('--config <file>', 'config file')
    .action(async (opts: { config?: string }) => {
      process.exitCode = await runDoctor(opts.config ? { config: opts.config } : {});
    });

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

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exit(code);
    })
    .catch(() => {
      process.exitCode = 70;
    });
}
