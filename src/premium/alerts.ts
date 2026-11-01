/**
 * Alerts hook (0.26.0, Team / Fleet track, open and opt-in).
 *
 * Off unless configured. When IRONHEIGHTS_ALERT_WEBHOOK, IRONHEIGHTS_ALERT_COMMAND or
 * IRONHEIGHTS_HOME/alerts.json is set, a block verdict, drift since approval or a failed
 * verification sends a signed JSON payload: POSTed to the webhook (https, or http to
 * localhost) and/or piped to the command on stdin. The ed25519 signature over the exact body
 * bytes is in the `x-ironheights-signature` header and the IRONHEIGHTS_ALERT_SIGNATURE
 * variable. An alert never changes an exit code or a verdict, and a failed delivery is
 * reported on stderr only.
 */
import { spawnSync } from 'node:child_process';
import { createPublicKey, sign, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import { loadOrCreateWatchKey } from '../runtime/activity.ts';
import { TOOL_NAME, TOOL_VERSION } from '../version.ts';
import { RetentionStore } from './retention.ts';

export type AlertKind = 'block' | 'drift' | 'verify-failed' | 'test';

export interface AlertConfig {
  webhook?: string;
  command?: string;
}

export interface AlertPayload {
  type: 'ironheights-alert/1';
  kind: AlertKind;
  at: string;
  host: string;
  tool: string;
  version: string;
  keyId: string;
  summary: string;
  data: Record<string, unknown>;
}

export interface AlertHooks {
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
  exec?: (command: string, input: string, env: NodeJS.ProcessEnv) => number | null;
  now?: Date;
  warn?: (line: string) => void;
}

export async function alertConfig(env: NodeJS.ProcessEnv = process.env): Promise<AlertConfig> {
  const cfg: AlertConfig = {};
  try {
    const file = JSON.parse(
      await readFile(join(ironheightsHome(env), 'alerts.json'), 'utf8'),
    ) as AlertConfig;
    if (typeof file.webhook === 'string') cfg.webhook = file.webhook;
    if (typeof file.command === 'string') cfg.command = file.command;
  } catch {
    /* no file: alerts stay off unless env is set */
  }
  if (env.IRONHEIGHTS_ALERT_WEBHOOK) cfg.webhook = env.IRONHEIGHTS_ALERT_WEBHOOK;
  if (env.IRONHEIGHTS_ALERT_COMMAND) cfg.command = env.IRONHEIGHTS_ALERT_COMMAND;
  return cfg;
}

export function webhookAllowed(url: string): boolean {
  try {
    const u = new URL(url);
    if (u.protocol === 'https:') return true;
    return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  } catch {
    return false;
  }
}

const defaultExec = (command: string, input: string, env: NodeJS.ProcessEnv): number | null =>
  spawnSync(command, {
    shell: true,
    input,
    env,
    stdio: ['pipe', 'ignore', 'inherit'],
    timeout: 15_000,
  }).status;

export interface AlertResult {
  sent: boolean;
  webhook?: 'ok' | 'failed' | 'refused';
  command?: 'ok' | 'failed';
  body?: string;
  signature?: string;
}

/** Send an alert when configured. Never throws. */
export async function emitAlert(
  kind: AlertKind,
  summary: string,
  data: Record<string, unknown>,
  hooks: AlertHooks = {},
): Promise<AlertResult> {
  const env = hooks.env ?? process.env;
  const warn = hooks.warn ?? ((l: string) => process.stderr.write(l + '\n'));
  try {
    const cfg = await alertConfig(env);
    if (!cfg.webhook && !cfg.command) return { sent: false };
    const key = await loadOrCreateWatchKey(ironheightsHome(env));
    const payload: AlertPayload = {
      type: 'ironheights-alert/1',
      kind,
      at: (hooks.now ?? new Date()).toISOString(),
      host: hostname(),
      tool: TOOL_NAME,
      version: TOOL_VERSION,
      keyId: key.keyId,
      summary,
      data,
    };
    const body = JSON.stringify(payload);
    const signature = sign(null, Buffer.from(body), key.privateKey).toString('base64');
    const result: AlertResult = { sent: true, body, signature };
    if (cfg.webhook) {
      if (!webhookAllowed(cfg.webhook)) {
        result.webhook = 'refused';
        warn('ironheights alert: webhook must be https (or http to localhost); not sent');
      } else {
        try {
          const res = await (hooks.fetchImpl ?? fetch)(cfg.webhook, {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'x-ironheights-signature': signature,
              'x-ironheights-key-id': key.keyId,
            },
            body,
            signal: AbortSignal.timeout(10_000),
          });
          result.webhook = res.ok ? 'ok' : 'failed';
          if (!res.ok) warn(`ironheights alert: webhook answered ${res.status}`);
        } catch (e) {
          result.webhook = 'failed';
          warn(`ironheights alert: webhook failed: ${(e as Error).message}`);
        }
      }
    }
    if (cfg.command) {
      const status = (hooks.exec ?? defaultExec)(cfg.command, body, {
        ...env,
        IRONHEIGHTS_ALERT_SIGNATURE: signature,
        IRONHEIGHTS_ALERT_KIND: kind,
      });
      result.command = status === 0 ? 'ok' : 'failed';
      if (status !== 0) warn(`ironheights alert: command exited ${String(status)}`);
    }
    const store = await RetentionStore.open(env, hooks.now ? () => hooks.now as Date : undefined);
    await store.append('alert', {
      kind,
      summary,
      webhook: result.webhook ?? null,
      command: result.command ?? null,
    });
    return result;
  } catch (e) {
    warn(`ironheights alert: not sent: ${(e as Error).message}`);
    return { sent: false };
  }
}

export function verifyAlert(body: string, signature: string, publicPem: string): boolean {
  try {
    return verify(
      null,
      Buffer.from(body),
      createPublicKey(publicPem),
      Buffer.from(signature, 'base64'),
    );
  } catch {
    return false;
  }
}
