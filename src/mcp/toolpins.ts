/**
 * Tool-description pins for MCP servers (0.24.0). Treat a server's tool manifest like an
 * access policy: version it, hash every tool at load, and on any mismatch revoke the whole
 * session first. Re-admit only tools whose own hash still matches: read-only tools come back
 * at once, tools that write, send or spend wait for one human confirmation that shows the
 * description diff. A drifted credential-bearing tool keeps the whole server revoked. The
 * fingerprint check runs alone: until it passes, every other call is blocked.
 */
import { createHash } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import { writeAtomic } from '../util/atomic.ts';

export interface ToolDef {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; openWorldHint?: boolean };
}

interface PinFile {
  version: 1;
  servers: Record<
    string,
    {
      pinnedAt: string;
      fingerprint: string;
      tools: Record<string, { sha256: string; description: string; readOnly: boolean }>;
      /** Optional approved change window (ISO times). Drift outside it is flagged as such. */
      changeWindow?: { from: string; until: string };
    }
  >;
}

const stableJson = (v: unknown): string =>
  JSON.stringify(v, (_k, x: unknown) =>
    x && typeof x === 'object' && !Array.isArray(x)
      ? Object.fromEntries(
          Object.entries(x as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
        )
      : x,
  );

export const toolHash = (t: ToolDef): string =>
  createHash('sha256')
    .update(
      stableJson({
        n: t.name,
        d: t.description ?? '',
        s: t.inputSchema ?? null,
        a: t.annotations ?? null,
      }),
    )
    .digest('hex');

const CREDENTIAL = /(token|secret|password|credential|api[_ -]?key|oauth|private key|wallet|sign)/i;
const SIDE_EFFECT =
  /\b(write|store|save|set|send|post|delete|remove|create|update|pay|spend|transfer|push|exec|run)\b/i;

export const isCredentialBearing = (t: ToolDef): boolean =>
  CREDENTIAL.test(`${t.name} ${t.description ?? ''} ${stableJson(t.inputSchema ?? {})}`);

export const isReadOnly = (t: ToolDef): boolean =>
  t.annotations?.readOnlyHint === true ||
  (t.annotations?.readOnlyHint !== false &&
    !SIDE_EFFECT.test(`${t.name} ${t.description ?? ''}`) &&
    !t.annotations?.destructiveHint);

export const pinsPath = (env: NodeJS.ProcessEnv): string =>
  join(ironheightsHome(env), 'mcp-tool-pins.json');

async function readPins(p: string): Promise<PinFile> {
  try {
    const d = JSON.parse(await readFile(p, 'utf8')) as PinFile;
    if (d && d.version === 1 && d.servers) return d;
  } catch {
    /* new file */
  }
  return { version: 1, servers: {} };
}

export interface ManifestResult {
  server: string;
  session: 'ok' | 'revoked' | 'unpinned' | 'pinned';
  /** True while the fingerprint check has not passed: block every other call to this server. */
  blockOtherCalls: boolean;
  serverMode: 'normal' | 'read-only' | 'revoked';
  fingerprint: string;
  readmitted: string[];
  awaitingConfirmation: string[];
  revoked: string[];
  added: string[];
  removed: string[];
  diff: Array<{ tool: string; before: string; after: string }>;
  outsideChangeWindow: boolean | null;
  reason: string;
}

export async function checkManifest(
  env: NodeJS.ProcessEnv,
  server: string,
  tools: ToolDef[],
  opts: {
    pin?: boolean;
    pinsFile?: string;
    changeWindow?: { from: string; until: string };
    now?: Date;
  },
): Promise<ManifestResult> {
  const file = opts.pinsFile ?? pinsPath(env);
  const pins = await readPins(file);
  const hashes = Object.fromEntries(tools.map((t) => [t.name, toolHash(t)]));
  const fingerprint = createHash('sha256')
    .update(
      Object.entries(hashes)
        .sort()
        .map(([n, h]) => `${n}:${h}`)
        .join('\n'),
    )
    .digest('hex');
  const base: Omit<ManifestResult, 'session' | 'blockOtherCalls' | 'serverMode' | 'reason'> = {
    server,
    fingerprint,
    readmitted: [],
    awaitingConfirmation: [],
    revoked: [],
    added: [],
    removed: [],
    diff: [],
    outsideChangeWindow: null,
  };
  if (opts.pin) {
    pins.servers[server] = {
      pinnedAt: (opts.now ?? new Date()).toISOString(),
      fingerprint,
      tools: Object.fromEntries(
        tools.map((t) => [
          t.name,
          {
            sha256: hashes[t.name] as string,
            description: t.description ?? '',
            readOnly: isReadOnly(t),
          },
        ]),
      ),
      ...(opts.changeWindow ? { changeWindow: opts.changeWindow } : {}),
    };
    await mkdir(dirname(file), { recursive: true });
    await writeAtomic(file, JSON.stringify(pins, null, 2) + '\n');
    return {
      ...base,
      readmitted: tools.map((t) => t.name),
      session: 'pinned',
      blockOtherCalls: false,
      serverMode: 'normal',
      reason: 'manifest pinned; later loads are compared to these hashes',
    };
  }
  const pinned = pins.servers[server];
  if (!pinned)
    return {
      ...base,
      session: 'unpinned',
      blockOtherCalls: true,
      serverMode: 'read-only',
      awaitingConfirmation: tools.map((t) => t.name),
      reason:
        'no pinned manifest for this server; pin it after a human reads the tools (pin: true)',
    };
  if (pinned.fingerprint === fingerprint)
    return {
      ...base,
      readmitted: tools.map((t) => t.name),
      session: 'ok',
      blockOtherCalls: false,
      serverMode: 'normal',
      reason: 'every tool hash matches the pinned manifest',
    };
  // Any mismatch: the whole session is revoked first; then per-tool re-admission.
  let credentialDrift = false;
  for (const t of tools) {
    const p = pinned.tools[t.name];
    if (!p) {
      base.added.push(t.name);
      base.awaitingConfirmation.push(t.name);
      continue;
    }
    if (p.sha256 === hashes[t.name]) {
      if (isReadOnly(t)) base.readmitted.push(t.name);
      else base.awaitingConfirmation.push(t.name);
    } else {
      base.revoked.push(t.name);
      base.diff.push({ tool: t.name, before: p.description, after: t.description ?? '' });
      if (isCredentialBearing(t)) credentialDrift = true;
    }
  }
  for (const n of Object.keys(pinned.tools)) if (!(n in hashes)) base.removed.push(n);
  const now = (opts.now ?? new Date()).getTime();
  const w = pinned.changeWindow;
  base.outsideChangeWindow = w ? !(now >= Date.parse(w.from) && now <= Date.parse(w.until)) : null;
  if (credentialDrift) {
    base.awaitingConfirmation.push(...base.readmitted);
    base.readmitted = [];
  }
  return {
    ...base,
    session: 'revoked',
    blockOtherCalls: true,
    serverMode: credentialDrift ? 'revoked' : 'read-only',
    reason: credentialDrift
      ? 'a credential-bearing tool description changed: the whole server stays revoked until a human confirms the diff'
      : 'tool descriptions changed: session revoked; matching read-only tools re-admitted, everything that writes, sends or spends waits for one human confirmation of the diff',
  };
}
