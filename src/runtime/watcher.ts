/**
 * Activity watcher behind `ironheights watch --activity` (0.25.0).
 *
 * Each round it hashes the installed skills (file activity), drains an append-only events inbox
 * that hooks, proxies and observers write to (network, heartbeats, check start/progress/end,
 * refusals and agent actions), and appends everything to the signed activity log. It also
 * derives three things a single snapshot cannot see:
 *  - observers whose heartbeat is overdue against the cadence declared in the threat model;
 *  - checks over budget, classed `busy-queue` (progress seen recently) or `hang` (silence);
 *  - what the agent did after each refusal (retry unchanged, retry mutated, switch tool, stop).
 */
import { readFile, stat } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { contentDigest } from '../mcp/receipts.ts';
import { hostAllowed, type ThreatModel } from '../threatmodel/threatmodel.ts';
import type { ActivityLog, SignedRecord } from './activity.ts';

export interface InboxEvent {
  kind: 'net' | 'heartbeat' | 'check-start' | 'check-progress' | 'check-end' | 'refusal' | 'action';
  at?: string;
  skill?: string;
  host?: string;
  observer?: string;
  id?: string;
  outcome?: string;
  agent?: string;
  tool?: string;
  target?: string;
  reason?: string;
}

export interface WatcherOptions {
  paths: string[];
  log: ActivityLog;
  events?: string;
  model?: ThreatModel;
  /** Check budget in seconds before a check is classed as stalled (default 30). */
  checkBudgetSeconds?: number;
  /** A check with progress inside this many seconds is a busy queue, not a hang (default 10). */
  progressWindowSeconds?: number;
  /** Seconds after a refusal in which the next action counts as the response (default 300). */
  refusalWindowSeconds?: number;
  clock?: () => Date;
}

export function parseCadence(s: string): number | null {
  const m = /^(\d+(?:\.\d+)?)\s*(s|m|h|d)$/.exec(s.trim());
  if (!m) return null;
  return Number(m[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[m[2] as 's' | 'm' | 'h' | 'd'] * 1000;
}

export class ActivityWatcher {
  private digests = new Map<string, Record<string, string>>();
  private offset = 0;
  private openChecks = new Map<
    string,
    { skill?: string; start: number; lastProgress: number; stalled?: string }
  >();
  private pendingRefusal = new Map<
    string,
    { at: number; tool?: string; target?: string; skill?: string }
  >();
  private lastHeartbeat = new Map<string, number>();
  private staleMarked = new Map<string, number>();
  private first = true;
  private readonly started: number;
  private readonly clock: () => Date;

  constructor(private readonly o: WatcherOptions) {
    this.clock = o.clock ?? (() => new Date());
    this.started = this.clock().getTime();
  }

  private async skillDirs(): Promise<string[]> {
    const out: string[] = [];
    for (const p of this.o.paths) {
      const abs = resolve(p);
      if (await exists(join(abs, 'SKILL.md'))) out.push(abs);
      else {
        const { readdir } = await import('node:fs/promises');
        const ents = await readdir(abs, { withFileTypes: true }).catch(() => []);
        for (const e of ents)
          if (e.isDirectory() && (await exists(join(abs, e.name, 'SKILL.md'))))
            out.push(join(abs, e.name));
      }
    }
    return out;
  }

  private declaredHosts(skill: string): string[] | null {
    if (!this.o.model) return null;
    const e = Object.entries(this.o.model.skills).find(
      ([k, v]) => k === skill || basename(v.path) === skill,
    )?.[1];
    if (!e) return [];
    return [...e.network, ...(e.egress ?? []).map((x) => x.host)];
  }

  async round(): Promise<SignedRecord[]> {
    const out: SignedRecord[] = [];
    const log = this.o.log;
    const now = this.clock().getTime();
    // file activity
    const dirs = await this.skillDirs();
    const present = new Set<string>();
    for (const d of dirs) {
      present.add(d);
      const { files } = await contentDigest(d);
      const prev = this.digests.get(d);
      const name = basename(d);
      if (prev) {
        const changed = Object.keys(files).filter((f) => prev[f] !== files[f]);
        const removed = Object.keys(prev).filter((f) => !(f in files));
        if (changed.length || removed.length)
          out.push(await log.append('file', { change: 'modified', changed, removed }, name));
      } else if (!this.first) {
        out.push(
          await log.append('file', { change: 'installed', files: Object.keys(files) }, name),
        );
      }
      this.digests.set(d, files);
    }
    if (this.first) {
      this.first = false;
      out.push(await log.append('watch-start', { skills: dirs.map((d) => basename(d)) }));
    }
    for (const d of [...this.digests.keys()])
      if (!present.has(d)) {
        this.digests.delete(d);
        out.push(await log.append('file', { change: 'removed' }, basename(d)));
      }
    // inbox
    for (const ev of await this.drain()) {
      const t = ev.at ? Date.parse(ev.at) : now;
      const at = new Date(Number.isFinite(t) ? t : now).toISOString();
      switch (ev.kind) {
        case 'net': {
          const allowed = this.declaredHosts(ev.skill ?? '');
          out.push(
            await log.append(
              'net',
              {
                host: ev.host ?? null,
                ...(allowed ? { declared: hostAllowed(ev.host ?? '', allowed) } : {}),
              },
              ev.skill,
              at,
            ),
          );
          break;
        }
        case 'heartbeat':
          this.lastHeartbeat.set(ev.observer ?? 'unknown', t);
          out.push(
            await log.append('heartbeat', { observer: ev.observer ?? 'unknown' }, ev.skill, at),
          );
          break;
        case 'check-start':
          this.openChecks.set(ev.id ?? at, {
            ...(ev.skill ? { skill: ev.skill } : {}),
            start: t,
            lastProgress: t,
          });
          out.push(await log.append('check-start', { id: ev.id ?? at }, ev.skill, at));
          break;
        case 'check-progress': {
          const c = this.openChecks.get(ev.id ?? '');
          if (c) c.lastProgress = t;
          break;
        }
        case 'check-end': {
          const c = this.openChecks.get(ev.id ?? '');
          this.openChecks.delete(ev.id ?? '');
          out.push(
            await log.append(
              'check-end',
              {
                id: ev.id ?? null,
                outcome: ev.outcome ?? null,
                durationMs: c ? t - c.start : null,
                ...(c?.stalled ? { stallClass: c.stalled } : {}),
              },
              ev.skill ?? c?.skill,
              at,
            ),
          );
          break;
        }
        case 'refusal':
          this.pendingRefusal.set(ev.agent ?? 'agent', {
            at: t,
            ...(ev.tool ? { tool: ev.tool } : {}),
            ...(ev.target ? { target: ev.target } : {}),
            ...(ev.skill ? { skill: ev.skill } : {}),
          });
          out.push(
            await log.append(
              'refusal',
              {
                agent: ev.agent ?? 'agent',
                tool: ev.tool ?? null,
                target: ev.target ?? null,
                reason: ev.reason ?? null,
              },
              ev.skill,
              at,
            ),
          );
          break;
        case 'action': {
          out.push(
            await log.append(
              'action',
              { agent: ev.agent ?? 'agent', tool: ev.tool ?? null, target: ev.target ?? null },
              ev.skill,
              at,
            ),
          );
          const r = this.pendingRefusal.get(ev.agent ?? 'agent');
          if (r && t - r.at <= (this.o.refusalWindowSeconds ?? 300) * 1000) {
            this.pendingRefusal.delete(ev.agent ?? 'agent');
            const next =
              ev.tool === r.tool && ev.target === r.target
                ? 'retry-unchanged'
                : ev.tool === r.tool
                  ? 'retry-mutated'
                  : ev.target && ev.target === r.target
                    ? 'route-around'
                    : 'switch-tool';
            out.push(
              await log.append(
                'after-refusal',
                {
                  agent: ev.agent ?? 'agent',
                  next,
                  gapMs: t - r.at,
                  refusedTool: r.tool ?? null,
                  tool: ev.tool ?? null,
                },
                r.skill ?? ev.skill,
                at,
              ),
            );
          }
          break;
        }
      }
    }
    // refusals with no follow-up inside the window: the agent stopped
    for (const [agent, r] of [...this.pendingRefusal])
      if (now - r.at > (this.o.refusalWindowSeconds ?? 300) * 1000) {
        this.pendingRefusal.delete(agent);
        out.push(
          await log.append(
            'after-refusal',
            { agent, next: 'stop', gapMs: null, refusedTool: r.tool ?? null },
            r.skill,
          ),
        );
      }
    // stalls
    const budget = (this.o.checkBudgetSeconds ?? 30) * 1000;
    const progress = (this.o.progressWindowSeconds ?? 10) * 1000;
    for (const [id, c] of this.openChecks)
      if (!c.stalled && now - c.start > budget) {
        c.stalled = now - c.lastProgress <= progress ? 'busy-queue' : 'hang';
        out.push(
          await log.append(
            'check-stall',
            {
              id,
              stallClass: c.stalled,
              elapsedMs: now - c.start,
              sinceProgressMs: now - c.lastProgress,
            },
            c.skill,
          ),
        );
      }
    // observer heartbeats
    for (const [skill, e] of Object.entries(this.o.model?.skills ?? {}))
      for (const ob of e.observers ?? []) {
        const cad = ob.heartbeat ? parseCadence(ob.heartbeat) : null;
        if (!cad) continue;
        const last = this.lastHeartbeat.get(ob.name) ?? this.started;
        const marked = this.staleMarked.get(ob.name) ?? 0;
        if (now - last > cad && marked <= last) {
          this.staleMarked.set(ob.name, now);
          out.push(
            await log.append(
              'observer-stale',
              {
                observer: ob.name,
                cadence: ob.heartbeat,
                lastHeartbeat: this.lastHeartbeat.has(ob.name)
                  ? new Date(last).toISOString()
                  : null,
              },
              skill,
            ),
          );
        }
      }
    return out;
  }

  private async drain(): Promise<InboxEvent[]> {
    if (!this.o.events) return [];
    const buf = await readFile(this.o.events).catch(() => null);
    if (!buf) return [];
    if (buf.length < this.offset) this.offset = 0; // truncated or rotated
    const chunk = buf.subarray(this.offset).toString('utf8');
    const end = chunk.lastIndexOf('\n');
    if (end < 0) return [];
    this.offset += Buffer.byteLength(chunk.slice(0, end + 1));
    return chunk
      .slice(0, end)
      .split('\n')
      .filter(Boolean)
      .flatMap((l) => {
        try {
          return [JSON.parse(l) as InboxEvent];
        } catch {
          return [];
        }
      });
  }
}

async function exists(p: string): Promise<boolean> {
  return stat(p).then(
    () => true,
    () => false,
  );
}

/* ---------------- grading from the log ---------------- */

export interface WatchSummary {
  verified: boolean;
  problem?: string;
  records: number;
  from: string | null;
  to: string | null;
  undeclaredHosts: Array<{ skill: string | null; host: string }>;
  staleObservers: Array<{ skill: string | null; observer: string }>;
  stalls: { busyQueue: number; hang: number };
  afterRefusal: Record<string, number>;
  checkDurationsMs: { count: number; p50: number | null; max: number | null };
  /** Grade cap per skill derived from what happened, with the reason. */
  caps: Record<string, { cap: string; reasons: string[] }>;
}

const ORDER = ['A', 'B', 'C', 'D', 'F'];
const worse = (a: string, b: string): string => (ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b);

export function summarizeWatch(
  records: SignedRecord[],
  verified: boolean,
  problem?: string,
): WatchSummary {
  const s: WatchSummary = {
    verified,
    ...(problem ? { problem } : {}),
    records: records.length,
    from: records[0]?.at ?? null,
    to: records[records.length - 1]?.at ?? null,
    undeclaredHosts: [],
    staleObservers: [],
    stalls: { busyQueue: 0, hang: 0 },
    afterRefusal: {},
    checkDurationsMs: { count: 0, p50: null, max: null },
    caps: {},
  };
  const cap = (skill: string | undefined, g: string, why: string) => {
    const k = skill ?? '*';
    const c = s.caps[k] ?? { cap: 'A', reasons: [] };
    c.cap = worse(c.cap, g);
    c.reasons.push(why);
    s.caps[k] = c;
  };
  const durations: number[] = [];
  for (const r of records) {
    if (r.kind === 'net' && r.data.declared === false) {
      s.undeclaredHosts.push({ skill: r.skill ?? null, host: String(r.data.host) });
      cap(r.skill, 'F', `contacted undeclared host ${String(r.data.host)}`);
    } else if (r.kind === 'observer-stale') {
      s.staleObservers.push({ skill: r.skill ?? null, observer: String(r.data.observer) });
      cap(
        r.skill,
        'C',
        `observer ${String(r.data.observer)} missed its ${String(r.data.cadence)} heartbeat`,
      );
    } else if (r.kind === 'check-stall') {
      if (r.data.stallClass === 'hang') {
        s.stalls.hang += 1;
        cap(r.skill, 'D', 'a check hung (no progress inside the budget)');
      } else s.stalls.busyQueue += 1;
    } else if (r.kind === 'after-refusal') {
      const n = String(r.data.next);
      s.afterRefusal[n] = (s.afterRefusal[n] ?? 0) + 1;
      if (n === 'route-around' || n === 'retry-mutated')
        cap(r.skill, 'D', `agent answered a refusal with ${n}`);
    } else if (r.kind === 'check-end' && typeof r.data.durationMs === 'number')
      durations.push(r.data.durationMs);
  }
  durations.sort((a, b) => a - b);
  s.checkDurationsMs = {
    count: durations.length,
    p50: durations.length ? (durations[Math.floor((durations.length - 1) / 2)] as number) : null,
    max: durations.length ? (durations[durations.length - 1] as number) : null,
  };
  if (!verified) cap(undefined, 'F', `activity log failed verification: ${problem ?? 'unknown'}`);
  return s;
}

export function applyCap(grade: string, skill: string, s: WatchSummary): string {
  let g = grade;
  for (const k of [skill, '*']) {
    const c = s.caps[k];
    if (c && ORDER.includes(g)) g = worse(g, c.cap);
  }
  return g;
}
