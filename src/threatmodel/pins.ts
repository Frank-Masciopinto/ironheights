/**
 * Hash pins, owned overrides and the unpinned-skill gate (0.31.0).
 *
 * A recorded hash matches only when the installed artifact's content digest is equal
 * to it. A difference is stale and is never a green result. An unpin override applies
 * only with an owner and an unexpired expiry; an expired one stops applying and fails.
 * A skill with neither a pin nor a declared update source is reported only when the
 * model opts in (`defaults.unpinned`).
 */
import { resolve } from 'node:path';
import { contentDigest } from '../mcp/receipts.ts';
import {
  hostAllowed,
  toPosix,
  type SkillEntryT,
  type SkillProfile,
  type ThreatModel,
  type Violation,
} from './threatmodel.ts';

export interface ListedOverride {
  skill: string;
  kind: 'unpin';
  owner: string;
  expires: string;
  status: 'active' | 'expired';
  reason?: string;
}

export interface PinAssessment {
  violations: Violation[];
  overrides: ListedOverride[];
}

const HASH = /^(?:sha256:)?([0-9a-f]{64})$/i;

export function normalizeHash(value: string | undefined): string | null {
  if (!value) return null;
  const m = HASH.exec(value.trim());
  return m ? (m[1] as string).toLowerCase() : null;
}

export function parseMaxAge(value: string): number | null {
  const m = /^(\d+)\s*([dhms])$/i.exec(value.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = (m[2] as string).toLowerCase();
  const mult = unit === 'd' ? 86_400_000 : unit === 'h' ? 3_600_000 : unit === 'm' ? 60_000 : 1000;
  return n * mult;
}

function updateHost(source: string): string | null {
  const s = source.trim();
  if (!s) return null;
  try {
    if (s.includes('://')) return new URL(s).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (/^[a-z0-9.-]+$/i.test(s)) return s.toLowerCase();
  return null;
}

function declaredHosts(entry: SkillEntryT): string[] {
  return [...entry.network, ...(entry.egress ?? []).map((e) => e.host)];
}

interface LiveOverride {
  active: ListedOverride | null;
  expired: ListedOverride[];
}

export function classifyOverrides(id: string, entry: SkillEntryT, now: Date): LiveOverride {
  const expired: ListedOverride[] = [];
  let active: ListedOverride | null = null;
  for (const raw of entry.overrides ?? []) {
    const row: ListedOverride = {
      skill: id,
      kind: raw.kind,
      owner: raw.owner,
      expires: raw.expires,
      status: 'expired',
      ...(raw.reason ? { reason: raw.reason } : {}),
    };
    const when = Date.parse(raw.expires);
    if (!raw.owner.trim() || !Number.isFinite(when) || when <= now.getTime()) {
      expired.push(row);
      continue;
    }
    row.status = 'active';
    if (raw.kind === 'unpin') active = row;
  }
  return { active, expired };
}

/**
 * Compare one installed digest with the hash the model recorded.
 * Matching is hash equality. A max-age backstop still marks a match stale.
 */
export function hashVerdict(
  id: string,
  entry: SkillEntryT,
  installed: string | null,
  now: Date,
): { status: 'match' | 'unpinned' | 'stale' | 'missing'; detail: string } {
  const recorded = normalizeHash(entry.checkedHash);
  if (!recorded && !entry.checkedHash) return { status: 'unpinned', detail: 'no recorded hash' };
  if (!recorded)
    return {
      status: 'stale',
      detail: `stale: ${id} records checkedHash ${entry.checkedHash}, which is not a sha256 digest`,
    };
  if (!installed)
    return {
      status: 'missing',
      detail: `stale: ${id} is not installed, so its hash cannot match the recorded sha256:${recorded}`,
    };
  if (installed !== recorded)
    return {
      status: 'stale',
      detail: `stale: installed artifact sha256:${installed} differs from recorded sha256:${recorded} (matching is hash equality)`,
    };
  if (entry.maxAge) {
    const window = parseMaxAge(entry.maxAge);
    const checked = entry.checkedAt ? Date.parse(entry.checkedAt) : NaN;
    if (!window || !Number.isFinite(checked))
      return {
        status: 'stale',
        detail: `stale: ${id} sets maxAge ${entry.maxAge} without a parseable checkedAt, so the hash cannot be treated as fresh`,
      };
    if (now.getTime() - checked > window)
      return {
        status: 'stale',
        detail: `stale: recorded hash matches but checkedAt ${entry.checkedAt} is older than maxAge ${entry.maxAge}`,
      };
  }
  return { status: 'match', detail: `recorded hash matches installed sha256:${installed}` };
}

export async function assessPins(
  model: ThreatModel,
  profiles: SkillProfile[],
  base: string,
  now = new Date(),
): Promise<PinAssessment> {
  const violations: Violation[] = [];
  const overrides: ListedOverride[] = [];
  const byKey = new Map(profiles.map((p) => [p.key, p]));
  for (const [id, entry] of Object.entries(model.skills)) {
    const key = toPosix(entry.path).replace(/^\.\//, '').replace(/\/+$/, '');
    const file = `${key}/SKILL.md`;
    const target = `${id} (${key})`;
    const ov = classifyOverrides(id, entry, now);
    for (const row of ov.expired) {
      overrides.push(row);
      violations.push({
        kind: 'override-expired',
        severity: 'high',
        target,
        detail: `expired override stopped applying (owner ${row.owner}, expired ${row.expires})`,
        file,
      });
    }
    if (ov.active) {
      overrides.push(ov.active);
      violations.push({
        kind: 'override-active',
        severity: 'info',
        target,
        detail: `override unpin by ${ov.active.owner} until ${ov.active.expires}${ov.active.reason ? ` (${ov.active.reason})` : ''}`,
        file,
      });
    }
    const mode = model.defaults.unpinned;
    const pinned = Boolean(normalizeHash(entry.checkedHash));
    const sourced = Boolean(entry.updateSource?.trim());
    if (mode !== 'off' && !pinned && !sourced && !ov.active)
      violations.push({
        kind: 'unpinned-skill',
        severity: mode === 'fail' ? 'high' : 'medium',
        target,
        detail: `${id} has no checked hash and no declared update source`,
        file,
      });
    if (sourced) {
      const host = updateHost(entry.updateSource as string);
      const allowed = declaredHosts(entry);
      if (!host || !hostAllowed(host, allowed))
        violations.push({
          kind: 'update-host-not-in-egress',
          severity: 'medium',
          target,
          detail: `declared update host ${host ?? entry.updateSource} is not in network or egress`,
          file,
        });
    }
    if (!entry.checkedHash && !entry.maxAge) continue;
    const profile = byKey.get(key);
    const root = profile?.root ?? resolve(base, key);
    const digest = await contentDigest(root).catch(() => ({ digest: null }));
    const verdict = hashVerdict(id, entry, digest.digest, now);
    if (verdict.status === 'stale' && !ov.active)
      violations.push({
        kind: verdict.detail.includes('older than maxAge') ? 'hash-expired' : 'hash-stale',
        severity: 'high',
        target,
        detail: verdict.detail,
        file,
      });
    else if (verdict.status === 'missing' && !ov.active)
      violations.push({
        kind: 'hash-stale',
        severity: 'high',
        target,
        detail: verdict.detail,
        file,
      });
  }
  return { violations, overrides };
}
