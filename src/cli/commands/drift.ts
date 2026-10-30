import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { loadConfig, ironheightsHome } from '../../core/config.ts';
import { UsageError } from '../../core/errors.ts';
import { discoverSkillRoots } from '../../core/scanner.ts';
import {
  diffSkill,
  exitCodeFor,
  readJsonItems,
  readLedger,
  snapshotSkill,
  writeLedger,
  type DriftChange,
  type DriftReport,
} from '../../drift/drift.ts';

export interface DriftFlags {
  action: string | undefined;
  paths: string[];
  all?: boolean;
  mcp?: string[];
  tools?: string[];
  ledger?: string;
  json?: boolean;
  interval?: string;
  config?: string;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  out?: (line: string) => void;
  sleep?: (ms: number) => Promise<void>;
  maxRounds?: number;
}

const sha256 = async (s: string): Promise<string> =>
  Promise.resolve(createHash('sha256').update(s).digest('hex'));

async function roots(flags: DriftFlags): Promise<string[]> {
  const env = flags.env ?? process.env;
  const targets = flags.all
    ? (await loadConfig({ ...(flags.config ? { explicitPath: flags.config } : {}), env })).skillDirs
    : flags.paths;
  const found: string[] = [];
  for (const t of targets) found.push(...(await discoverSkillRoots(t)));
  return [...new Set(found)];
}

function ledgerPath(flags: DriftFlags): string {
  return flags.ledger ?? join(ironheightsHome(flags.env ?? process.env), 'approvals.json');
}

async function items(flags: DriftFlags): Promise<{
  mcp: Array<[string, string]>;
  tools: Array<[string, string]>;
}> {
  const mcp: Array<[string, string]> = [];
  const tools: Array<[string, string]> = [];
  for (const f of flags.mcp ?? []) mcp.push(...(await readJsonItems(f, 'mcp')));
  for (const f of flags.tools ?? []) tools.push(...(await readJsonItems(f, 'tools')));
  return { mcp, tools };
}

export async function runDrift(flags: DriftFlags): Promise<number> {
  const out = flags.out ?? ((l: string) => process.stdout.write(l + '\n'));
  const action = flags.action ?? 'check';
  if (!['approve', 'check', 'watch'].includes(action)) {
    throw new UsageError('drift action must be approve, check, or watch');
  }
  const hasSources = flags.all || flags.paths.length || flags.mcp?.length || flags.tools?.length;
  if (!hasSources)
    throw new UsageError('drift needs a path, --all, --mcp <file>, or --tools <file>');
  if (action === 'approve') return approve(flags, out);
  if (action === 'check') return (await check(flags, out)).code;
  const seconds = Number(flags.interval ?? '60');
  if (!Number.isFinite(seconds) || seconds < 5) {
    throw new UsageError('--interval must be a number of seconds, 5 or more');
  }
  const sleep = flags.sleep ?? ((ms: number) => new Promise<void>((d) => setTimeout(d, ms)));
  const rounds = flags.maxRounds ?? Number.POSITIVE_INFINITY;
  let worst = 0;
  const seen = new Set<string>();
  for (let round = 0; round < rounds; round += 1) {
    if (round > 0) await sleep(seconds * 1000);
    const { code, report } = await check(flags, () => undefined);
    worst = Math.max(worst, code);
    for (const c of report.changes) {
      const key = JSON.stringify(c);
      if (seen.has(key)) continue;
      seen.add(key);
      out(flags.json ? JSON.stringify({ checkedAt: report.checkedAt, ...c }) : line(c));
    }
  }
  return worst;
}

async function approve(flags: DriftFlags, out: (l: string) => void): Promise<number> {
  const path = ledgerPath(flags);
  const ledger = await readLedger(path);
  const now = flags.now ?? new Date();
  let count = 0;
  for (const root of await roots(flags)) {
    const rec = await snapshotSkill(root, now);
    ledger.skills[rec.root] = rec;
    count += 1;
  }
  const { mcp, tools } = await items(flags);
  for (const [key, body] of mcp) {
    ledger.mcpServers[key] = {
      key,
      source: key.split('#')[0] as string,
      approvedAt: now.toISOString(),
      sha256: await sha256(body),
    };
  }
  for (const [key, body] of tools) {
    ledger.mcpTools[key] = {
      key,
      source: key.split('#')[0] as string,
      approvedAt: now.toISOString(),
      sha256: await sha256(body),
    };
  }
  await writeLedger(path, ledger);
  out(
    `approved ${count} skill(s), ${mcp.length} MCP server(s), ${tools.length} MCP tool(s) -> ${path}`,
  );
  return 0;
}

async function check(
  flags: DriftFlags,
  out: (l: string) => void,
): Promise<{ code: number; report: DriftReport }> {
  const ledger = await readLedger(ledgerPath(flags));
  const changes: DriftChange[] = [];
  const current = await roots(flags);
  for (const root of current) {
    const now = await snapshotSkill(root);
    const before = ledger.skills[now.root];
    if (!before) {
      changes.push({
        kind: 'skill-unapproved',
        severity: 'medium',
        target: now.root,
        detail: 'not in the approval ledger',
      });
      continue;
    }
    changes.push(...diffSkill(before, now));
  }
  if (flags.paths.length === 0 && flags.all) {
    const live = new Set(
      await Promise.all(current.map(async (r) => (await snapshotSkill(r)).root)),
    );
    for (const root of Object.keys(ledger.skills)) {
      if (!live.has(root))
        changes.push({
          kind: 'skill-missing',
          severity: 'info',
          target: root,
          detail: 'approved skill no longer present',
        });
    }
  }
  const { mcp, tools } = await items(flags);
  for (const [key, body] of mcp) {
    const rec = ledger.mcpServers[key];
    const hash = await sha256(body);
    if (!rec)
      changes.push({
        kind: 'mcp-server-added',
        severity: 'medium',
        target: key,
        detail: 'MCP server not approved',
      });
    else if (rec.sha256 !== hash)
      changes.push({
        kind: 'mcp-server-changed',
        severity: 'high',
        target: key,
        detail: 'command, args, url or env changed since approval',
      });
  }
  for (const [key, body] of tools) {
    const rec = ledger.mcpTools[key];
    const hash = await sha256(body);
    if (!rec)
      changes.push({
        kind: 'mcp-tool-added',
        severity: 'medium',
        target: key,
        detail: 'MCP tool not approved',
      });
    else if (rec.sha256 !== hash)
      changes.push({
        kind: 'mcp-tool-changed',
        severity: 'high',
        target: key,
        detail: 'tool description or input schema changed since approval (possible rug pull)',
      });
  }
  const report: DriftReport = { checkedAt: (flags.now ?? new Date()).toISOString(), changes };
  if (flags.json) out(JSON.stringify(report, null, 2));
  else if (changes.length === 0) out('no drift since approval');
  else for (const c of changes) out(line(c));
  return { code: exitCodeFor(changes), report };
}

function line(c: DriftChange): string {
  return `${c.severity.toUpperCase().padEnd(6)} ${c.kind}  ${c.target}  ${c.detail}`;
}
