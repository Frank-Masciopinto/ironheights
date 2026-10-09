import { stat } from 'node:fs/promises';
import { loadConfig } from '../../core/config.ts';
import { locateOpenClaw } from '../../openclaw/locate.ts';
import { OPENCLAW_NODE_RANGE } from '../../version.ts';

export async function runDoctor(options: {
  config?: string;
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
}): Promise<number> {
  const env = options.env ?? process.env;
  const write = options.stdout ?? ((text: string) => process.stdout.write(text));
  const located = await locateOpenClaw(env);
  const nodeVersion = process.version;
  const supported = nodeMeetsOpenClaw(nodeVersion);
  write(
    `Node: ${nodeVersion} (${supported ? 'meets' : 'outside'} OpenClaw range ${OPENCLAW_NODE_RANGE})\n`,
  );
  write(`OpenClaw state: ${located.stateDir}\n`);
  write(`OpenClaw config: ${located.configFound ? 'found' : 'missing'} ${located.configPath}\n`);
  if (located.configFound)
    write(`OpenClaw config parsed: ${located.configParsed ? 'yes' : 'no'}\n`);
  write(`Workspace: ${located.workspace ?? 'unknown'}\n`);
  for (const dir of located.skillDirs) {
    write(`Skill dir (${dir.source}): ${dir.exists ? 'found' : 'missing'} ${dir.path}\n`);
  }
  for (const file of located.agentFiles) {
    let exists = false;
    try {
      await stat(file);
      exists = true;
    } catch {
      exists = false;
    }
    write(`Agent file: ${exists ? 'found' : 'missing'} ${file}\n`);
  }
  for (const note of located.notes) write(`Note: ${note}\n`);
  try {
    const config = await loadConfig({
      ...(options.config ? { explicitPath: options.config } : {}),
      env,
    });
    write(`Ironheights config: ${config.configPath ? `valid ${config.configPath}` : 'defaults'}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'invalid config';
    write(`Ironheights config: invalid (${message})\n`);
    return 64;
  }
  return 0;
}

export function nodeMeetsOpenClaw(version: string): boolean {
  const match = /^v(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) return false;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (major === 24) return minor > 16 || (minor === 16 && patch >= 0);
  if (major === 26) return minor > 1 || (minor === 1 && patch >= 0);
  if (major > 26) return true;
  return false;
}
