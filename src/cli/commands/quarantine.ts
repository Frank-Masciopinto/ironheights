import { resolve } from 'node:path';
import { UsageError } from '../../core/errors.ts';
import { ironheightsHome } from '../../core/config.ts';
import { quarantineSkill, restoreQuarantine } from '../../integrity/quarantine.ts';

export async function runQuarantine(
  skill: string | undefined,
  restoreId: string | undefined,
  options: { env?: NodeJS.ProcessEnv; stdout?: (text: string) => void; restore?: boolean },
): Promise<number> {
  const env = options.env ?? process.env;
  const home = ironheightsHome(env);
  const write = options.stdout ?? ((text: string) => process.stdout.write(text));
  if (options.restore) {
    if (!restoreId) throw new UsageError('quarantine restore requires an id');
    const manifest = await restoreQuarantine(restoreId, home);
    write(`restored ${manifest.id} to ${manifest.originalPath}\n`);
    return 0;
  }
  if (!skill) throw new UsageError('quarantine requires a skill path');
  const manifest = await quarantineSkill(resolve(skill), home);
  write(`quarantined ${manifest.skillName} as ${manifest.id}\n`);
  return 0;
}
