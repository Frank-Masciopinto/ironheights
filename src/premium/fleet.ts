/**
 * Fleet inventory (0.26.0, Team / Fleet track, open and opt-in).
 *
 * Scans the skill folders of several bots on this host (`name=dir` targets) and merges
 * inventories exported from other hosts (`.json` targets) into one signed inventory: every
 * skill with its content digest and verdict per bot, plus a summary of verdicts and of skills
 * whose bytes differ between bots. `--audit-export` adds the local retention bundle, signed
 * together with the inventory, as the cross-bot audit record.
 */
import { createPublicKey, sign, verify } from 'node:crypto';
import { hostname } from 'node:os';
import { basename } from 'node:path';
import { contentDigest } from '../mcp/receipts.ts';
import type { WatchKey } from '../runtime/activity.ts';
import { TOOL_VERSION } from '../version.ts';
import { stable } from './attest.ts';
import type { RetentionBundle } from './retention.ts';

export interface FleetSkill {
  name: string;
  path: string;
  digest: string | null;
  verdict: string;
  findings: number;
}
export interface FleetBot {
  bot: string;
  host: string;
  dir: string;
  skills: FleetSkill[];
}
export interface FleetSummary {
  bots: number;
  hosts: number;
  skills: number;
  verdicts: Record<string, number>;
  /** Skills present in more than one bot with different bytes. */
  divergent: Array<{ name: string; digests: string[]; bots: string[] }>;
  blocked: Array<{ bot: string; skill: string }>;
}
export interface FleetInventory {
  format: 'ironheights-fleet/1';
  generatedAt: string;
  version: string;
  bots: FleetBot[];
  summary: FleetSummary;
  audit?: RetentionBundle;
}
export interface SignedInventory {
  inventory: FleetInventory;
  keyId: string;
  publicKey: string;
  signature: string;
}

export type Scanner = (dir: string) => Promise<{
  skills: Array<{ skillName: string; root: string; verdict: string; findings: unknown[] }>;
}>;

export function parseTarget(t: string): { bot: string; dir: string } {
  const i = t.indexOf('=');
  if (i > 0) return { bot: t.slice(0, i), dir: t.slice(i + 1) };
  return { bot: basename(t.replace(/[\\/]+$/, '')) || t, dir: t };
}

export async function inventoryBot(bot: string, dir: string, scan: Scanner): Promise<FleetBot> {
  const res = await scan(dir);
  const skills: FleetSkill[] = [];
  for (const s of res.skills) {
    const d = await contentDigest(s.root).catch(() => ({ digest: null }));
    skills.push({
      name: s.skillName,
      path: s.root,
      digest: d.digest,
      verdict: s.verdict,
      findings: s.findings.length,
    });
  }
  return { bot, host: hostname(), dir, skills };
}

export function summarize(bots: FleetBot[]): FleetSummary {
  const verdicts: Record<string, number> = {};
  const byName = new Map<string, { digests: Set<string>; bots: Set<string> }>();
  const blocked: FleetSummary['blocked'] = [];
  let skills = 0;
  for (const b of bots)
    for (const s of b.skills) {
      skills += 1;
      verdicts[s.verdict] = (verdicts[s.verdict] ?? 0) + 1;
      if (s.verdict === 'block') blocked.push({ bot: b.bot, skill: s.name });
      const e = byName.get(s.name) ?? { digests: new Set(), bots: new Set() };
      e.digests.add(s.digest ?? 'none');
      e.bots.add(`${b.host}/${b.bot}`);
      byName.set(s.name, e);
    }
  const divergent = [...byName.entries()]
    .filter(([, e]) => e.digests.size > 1)
    .map(([name, e]) => ({ name, digests: [...e.digests].sort(), bots: [...e.bots].sort() }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return {
    bots: bots.length,
    hosts: new Set(bots.map((b) => b.host)).size,
    skills,
    verdicts,
    divergent,
    blocked,
  };
}

export function buildInventory(
  bots: FleetBot[],
  now: Date,
  audit?: RetentionBundle,
): FleetInventory {
  return {
    format: 'ironheights-fleet/1',
    generatedAt: now.toISOString(),
    version: TOOL_VERSION,
    bots,
    summary: summarize(bots),
    ...(audit ? { audit } : {}),
  };
}

export function signInventory(inv: FleetInventory, key: WatchKey): SignedInventory {
  return {
    inventory: inv,
    keyId: key.keyId,
    publicKey: key.publicPem,
    signature: sign(null, Buffer.from(stable(inv)), key.privateKey).toString('base64'),
  };
}

export function verifyInventory(s: SignedInventory, trustedPem?: string): boolean {
  try {
    if (trustedPem && trustedPem.replace(/\s+/g, '') !== s.publicKey.replace(/\s+/g, ''))
      return false;
    return verify(
      null,
      Buffer.from(stable(s.inventory)),
      createPublicKey(s.publicKey),
      Buffer.from(s.signature, 'base64'),
    );
  } catch {
    return false;
  }
}
