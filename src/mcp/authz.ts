/**
 * Short-lived, single-use install authorizations for the MCP server (0.24.0).
 *
 * check_skill issues an authorization only for an `allow` decision on a pinned artifact. It is
 * bound to the content digest, the Ironheights version and rule set, the action, the target,
 * the executor that will mutate, the server session and an expiry. redeem_authorization is the
 * install gate: it re-hashes the bytes when they are on disk, refuses an expired, reused,
 * mismatched or unknown authorization, and refuses sessions that never ran a check. The
 * signing key is created on first use in the Ironheights home (mode 0600) and never leaves it.
 * Suggested by Moltbook bots (credits in CHANGELOG 0.24.0).
 */
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile, appendFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import { TOOL_VERSION } from '../version.ts';
import { contentDigest, rulesetHash } from './receipts.ts';

/** One id per server process. A redeem from another session is refused. */
export const SESSION_ID = `ihs_${randomUUID().replace(/-/g, '').slice(0, 24)}`;

export interface AuthorizationClaims {
  id: string;
  checkId: string;
  digest: string;
  version: string;
  rulesetHash: string;
  action: string;
  target: string;
  executor: string;
  session: string;
  issuedAt: string;
  expiresAt: string;
  singleUse: true;
}

export interface Authorization {
  claims: AuthorizationClaims;
  /** HMAC-SHA256 over the claims with the local key. */
  signature: string;
}

const keyPath = (env: NodeJS.ProcessEnv): string => join(ironheightsHome(env), 'mcp-authz.key');
const ledgerPath = (env: NodeJS.ProcessEnv): string =>
  join(ironheightsHome(env), 'mcp-redemptions.jsonl');

async function signingKey(env: NodeJS.ProcessEnv): Promise<Buffer> {
  const p = keyPath(env);
  try {
    const raw = await readFile(p);
    if (raw.length >= 32) return raw;
  } catch {
    /* create below */
  }
  await mkdir(dirname(p), { recursive: true });
  const key = randomBytes(32);
  await writeFile(p, key, { mode: 0o600, flag: 'wx' }).catch(async () => undefined);
  await chmod(p, 0o600).catch(() => undefined);
  return readFile(p);
}

const canonical = (c: AuthorizationClaims): string =>
  JSON.stringify(
    Object.keys(c)
      .sort()
      .map((k) => [k, (c as unknown as Record<string, unknown>)[k]]),
  );

export async function issueAuthorization(
  env: NodeJS.ProcessEnv,
  input: Omit<
    AuthorizationClaims,
    'id' | 'version' | 'rulesetHash' | 'session' | 'issuedAt' | 'singleUse'
  > & {
    issuedAt: Date;
  },
): Promise<Authorization> {
  const claims: AuthorizationClaims = {
    id: `iha_${randomUUID().replace(/-/g, '')}`,
    checkId: input.checkId,
    digest: input.digest,
    version: TOOL_VERSION,
    rulesetHash: rulesetHash(),
    action: input.action,
    target: input.target,
    executor: input.executor,
    session: SESSION_ID,
    issuedAt: input.issuedAt.toISOString(),
    expiresAt: input.expiresAt,
    singleUse: true,
  };
  const key = await signingKey(env);
  return { claims, signature: createHmac('sha256', key).update(canonical(claims)).digest('hex') };
}

export interface RedeemInput {
  authorization: unknown;
  digest?: string;
  action?: string;
  target?: string;
  executor?: string;
  path?: string;
  idempotencyKey?: string;
  now?: Date;
}

export interface RedeemResult {
  decision: 'allow' | 'blocked';
  status: 'redeemed' | 'already-redeemed' | 'refused';
  reason: string;
  operationId?: string;
  authorizationId?: string;
  logLine: string;
}

interface Redemption {
  authorizationId: string;
  operationId: string;
  idempotencyKey: string | null;
  at: string;
  digest: string;
  action: string;
  target: string;
  executor: string;
}

async function redemptions(env: NodeJS.ProcessEnv): Promise<Redemption[]> {
  try {
    return (await readFile(ledgerPath(env), 'utf8'))
      .split('\n')
      .filter(Boolean)
      .flatMap((l) => {
        try {
          return [JSON.parse(l) as Redemption];
        } catch {
          return [];
        }
      });
  } catch {
    return [];
  }
}

export async function redeemAuthorization(
  env: NodeJS.ProcessEnv,
  input: RedeemInput,
  checkedThisSession: ReadonlySet<string>,
): Promise<RedeemResult> {
  const refuse = (reason: string, id?: string): RedeemResult => ({
    decision: 'blocked',
    status: 'refused',
    reason,
    ...(id ? { authorizationId: id } : {}),
    logLine: `install refused${id ? ` for ${id}` : ''}: ${reason}`,
  });
  const a = input.authorization as Authorization | undefined;
  if (!a || typeof a !== 'object' || !a.claims || typeof a.signature !== 'string')
    return refuse('no authorization presented; call check_skill on the pinned artifact first');
  const c = a.claims;
  const key = await signingKey(env);
  const want = Buffer.from(createHmac('sha256', key).update(canonical(c)).digest('hex'));
  const got = Buffer.from(a.signature);
  if (want.length !== got.length || !timingSafeEqual(want, got))
    return refuse('signature does not verify (not issued by this Ironheights home)', c.id);
  const now = input.now ?? new Date();
  if (Date.parse(c.expiresAt) <= now.getTime())
    return refuse(
      `expired at ${c.expiresAt}; an expired check forces a re-check, not an install`,
      c.id,
    );
  if (c.session !== SESSION_ID || !checkedThisSession.has(c.checkId))
    return refuse('this server session never ran the check behind this authorization', c.id);
  if (c.version !== TOOL_VERSION || c.rulesetHash !== rulesetHash())
    return refuse('issued under a different Ironheights version or rule set', c.id);
  const bound: Array<[string, string | undefined, string]> = [
    ['digest', input.digest, c.digest],
    ['action', input.action, c.action],
    ['target', input.target, c.target],
    ['executor', input.executor, c.executor],
  ];
  for (const [k, given, expected] of bound) {
    if (given === undefined) return refuse(`${k} is required to redeem`, c.id);
    if (given !== expected)
      return refuse(`${k} mismatch: authorized ${expected}, presented ${given}`, c.id);
  }
  if (input.path) {
    const d = await contentDigest(input.path).catch(() => ({ digest: null }));
    if (d.digest !== c.digest)
      return refuse(
        'the bytes on disk do not match the checked digest; do not run any package hook',
        c.id,
      );
  }
  const prior = (await redemptions(env)).filter((r) => r.authorizationId === c.id);
  if (prior.length) {
    const same = prior.find(
      (r) => input.idempotencyKey && r.idempotencyKey === input.idempotencyKey,
    );
    if (same)
      return {
        decision: 'blocked',
        status: 'already-redeemed',
        reason: 'this idempotency key already redeemed; query the operation, do not mutate again',
        operationId: same.operationId,
        authorizationId: c.id,
        logLine: `retry of ${same.operationId}: already redeemed at ${same.at}`,
      };
    return refuse('single-use authorization already redeemed', c.id);
  }
  const rec: Redemption = {
    authorizationId: c.id,
    operationId: `iho_${randomUUID().replace(/-/g, '')}`,
    idempotencyKey: input.idempotencyKey ?? null,
    at: now.toISOString(),
    digest: c.digest,
    action: c.action,
    target: c.target,
    executor: c.executor,
  };
  await mkdir(dirname(ledgerPath(env)), { recursive: true });
  await appendFile(ledgerPath(env), JSON.stringify(rec) + '\n');
  return {
    decision: 'allow',
    status: 'redeemed',
    reason: 'signature, expiry, session, digest, action, target and executor all match',
    operationId: rec.operationId,
    authorizationId: c.id,
    logLine: `check passed for ${c.target} at sha256:${c.digest}, install matched (${rec.operationId})`,
  };
}
