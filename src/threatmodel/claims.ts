/**
 * Per-claim results for `threatmodel check` and `threatmodel diff`.
 *
 * A claim is one allow-list category of one model entry. `untested` means the
 * check matched zero rows (nothing to fire on). That does not change the exit
 * code. `uncovered` is a capability no claim mentions; it fails only when
 * `defaults.uncovered` is `fail` or `--fail-on-uncovered` is set.
 */
import { stable } from '../drift/drift.ts';
import {
  hostAllowed,
  nameAllowed,
  pathAllowed,
  type McpServerDef,
  type SkillEntryT,
  type SkillProfile,
  type ThreatModel,
  type Violation,
} from './threatmodel.ts';

export type ClaimStatus = 'passed' | 'violated' | 'untested';

export interface ClaimResult {
  target: string;
  claim: string;
  status: ClaimStatus;
  observed: number | string | string[];
  allowed: number | string | string[] | boolean;
  detail: string;
  /** Where the claim is checked. `unenforced` means nothing can fail it. */
  enforcement: string;
  unenforced?: true;
}

export type UncoveredKind = 'host' | 'token' | 'env' | 'mcp-server' | 'webhook';

export interface UncoveredCapability {
  target: string;
  kind: UncoveredKind;
  value: string;
  file?: string;
  suggestedClaim: string;
}

export interface ClaimAssessment {
  claims: ClaimResult[];
  uncovered: UncoveredCapability[];
}

const ENFORCEMENT = {
  network: 'egress/allowlist in diff',
  filesystem: 'workspace write',
  env: 'env var reference',
  tokens: 'secret read',
  shell: 'shell or child process',
  minGrade: 'scan grade',
  command: 'mcp command, args and url',
  tools: 'unenforced',
  remote: 'scanner IH-INJ-004',
  prose: 'unenforced',
} as const;

function normPath(p: string): string {
  return p.replace(/^\.\//, '').replace(/\/+$/, '');
}

function skillId(model: ThreatModel, profile: SkillProfile): string {
  for (const [id, entry] of Object.entries(model.skills)) {
    if (normPath(entry.path) === profile.key) return id;
  }
  return profile.name || profile.key;
}

function targetOf(id: string, profile: SkillProfile): string {
  return `${id} (${profile.key})`;
}

function added(
  head: readonly string[],
  base: readonly string[] | undefined,
  diff: boolean,
): string[] {
  if (!diff) return [...head];
  const prev = new Set(base ?? []);
  return head.filter((item) => !prev.has(item));
}

function countDetail(n: number, ok: number, noun: string, diff: boolean, tail: string): string {
  const word = n === 1 ? noun : `${noun}s`;
  const where = diff ? 'in diff' : 'referenced';
  if (n === 0) return `0 ${word} ${where}`;
  return `${n} ${word} ${where}, ${ok} ${tail}`;
}

function listClaim(input: {
  target: string;
  claim: string;
  observed: string[];
  allow: (value: string) => boolean;
  diff: boolean;
  noun: string;
  tail: string;
  enforcement: string;
}): ClaimResult {
  const ok = input.observed.filter(input.allow).length;
  const status: ClaimStatus =
    input.observed.length === 0 ? 'untested' : ok === input.observed.length ? 'passed' : 'violated';
  return {
    target: input.target,
    claim: input.claim,
    status,
    observed: input.observed.length,
    allowed: ok,
    detail: countDetail(input.observed.length, ok, input.noun, input.diff, input.tail),
    enforcement: input.enforcement,
  };
}

function entryFor(model: ThreatModel, profile: SkillProfile): [string, SkillEntryT] | undefined {
  for (const [id, entry] of Object.entries(model.skills)) {
    if (normPath(entry.path) === profile.key) return [id, entry];
  }
  return undefined;
}

function baseProfile(
  profile: SkillProfile,
  base: SkillProfile[] | undefined,
): SkillProfile | undefined {
  return base?.find((item) => item.key === profile.key);
}

function skillClaims(
  model: ThreatModel,
  profile: SkillProfile,
  base: SkillProfile | undefined,
  diff: boolean,
): ClaimResult[] {
  const hit = entryFor(model, profile);
  const claims: ClaimResult[] = [];
  const id = hit?.[0] ?? skillId(model, profile);
  const target = targetOf(id, profile);
  if (hit) {
    const entry = hit[1];
    claims.push(
      listClaim({
        target,
        claim: 'network',
        observed: added(profile.hosts, base?.hosts, diff),
        allow: (host) => hostAllowed(host, entry.network),
        diff,
        noun: 'host',
        tail: 'on allowlist',
        enforcement: ENFORCEMENT.network,
      }),
      listClaim({
        target,
        claim: 'filesystem',
        observed: added(profile.paths, base?.paths, diff),
        allow: (path) => pathAllowed(path, entry.filesystem),
        diff,
        noun: 'path',
        tail: 'allowed',
        enforcement: ENFORCEMENT.filesystem,
      }),
      listClaim({
        target,
        claim: 'env',
        observed: added(profile.env, base?.env, diff),
        allow: (name) => nameAllowed(name, entry.env) || nameAllowed(name, entry.tokens),
        diff,
        noun: 'var',
        tail: 'allowed',
        enforcement: ENFORCEMENT.env,
      }),
      listClaim({
        target,
        claim: 'tokens',
        observed: added(profile.tokens, base?.tokens, diff),
        allow: (name) => nameAllowed(name, entry.tokens),
        diff,
        noun: 'token',
        tail: 'allowed',
        enforcement: ENFORCEMENT.tokens,
      }),
    );
    const shellNow = diff ? profile.shell && !base?.shell : profile.shell;
    claims.push({
      target,
      claim: 'shell',
      status: !shellNow ? 'untested' : entry.shell ? 'passed' : 'violated',
      observed: shellNow ? 1 : 0,
      allowed: entry.shell,
      detail: !shellNow
        ? 'shell not used'
        : entry.shell
          ? 'shell used, allowed'
          : 'shell used, not allowed',
      enforcement: ENFORCEMENT.shell,
    });
    const min = entry.minGrade ?? model.defaults.minGrade;
    if (min) {
      const grade = profile.grade;
      const untested = !grade || grade === 'nothing-scanned';
      const violated = !untested && (grade === 'incomplete' || gradeWorse(grade, min));
      claims.push({
        target,
        claim: 'minGrade',
        status: untested ? 'untested' : violated ? 'violated' : 'passed',
        observed: grade ?? 0,
        allowed: min,
        detail: untested ? 'grade not computed' : `grade ${grade}, minimum ${min}`,
        enforcement: ENFORCEMENT.minGrade,
      });
    }
    if (entry.purpose) {
      claims.push(unenforced(target, 'purpose', entry.purpose, entry.purpose));
    }
    if (entry.dataBoundaries.length > 0) {
      claims.push(unenforced(target, 'dataBoundaries', entry.dataBoundaries, entry.dataBoundaries));
    }
  }
  claims.push(remoteClaim(model, target, profile, base, diff));
  return claims;
}

function unenforced(
  target: string,
  claim: string,
  observed: string | string[],
  allowed: string | string[],
): ClaimResult {
  return {
    target,
    claim,
    status: 'untested',
    observed,
    allowed,
    detail: 'free text, not checked',
    enforcement: ENFORCEMENT.prose,
    unenforced: true,
  };
}

const GRADE_RANK: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 };

function gradeWorse(grade: string, min: string): boolean {
  const g = GRADE_RANK[grade];
  const m = GRADE_RANK[min];
  if (g === undefined || m === undefined) return true;
  return g > m;
}

function remoteClaim(
  model: ThreatModel,
  target: string,
  profile: SkillProfile,
  base: SkillProfile | undefined,
  diff: boolean,
): ClaimResult {
  const allowed = entryFor(model, profile)?.[1].remoteInstructions === true;
  const hit = profile.remoteInstructionsHit === true;
  const introduced = diff ? hit && base?.remoteInstructionsHit !== true : hit;
  let status: ClaimStatus = 'passed';
  let detail = 'no remote instruction text';
  if (allowed) {
    status = 'passed';
    detail = hit ? 'allowed by remoteInstructions: true' : 'no remote instruction text';
  } else if (diff && hit && !introduced) {
    status = 'untested';
    detail = 'remote instruction text unchanged in this diff';
  } else if (introduced) {
    status = 'violated';
    detail =
      'instruction text tells the agent to fetch a URL and follow it (IH-INJ-004). A hash pins the file, not the page it points to.';
  }
  return {
    target,
    claim: 'remote-instructions',
    status,
    observed: introduced ? 1 : 0,
    allowed,
    detail,
    enforcement: ENFORCEMENT.remote,
  };
}

function mcpClaims(
  model: ThreatModel,
  server: McpServerDef,
  base: McpServerDef | undefined,
  diff: boolean,
): ClaimResult[] {
  const allowed = model.mcpServers[server.name];
  if (!allowed) return [];
  const target = server.name;
  const claims: ClaimResult[] = [];
  const pins: string[] = [];
  if (allowed.command !== undefined) pins.push('command');
  if (allowed.args !== undefined) pins.push('args');
  if (allowed.url !== undefined) pins.push('url');
  const changed =
    (allowed.command !== undefined && allowed.command !== server.command) ||
    (allowed.url !== undefined && allowed.url !== server.url) ||
    (allowed.args !== undefined && stable(allowed.args) !== stable(server.args ?? []));
  const observedPins = diff && base && !changed ? [] : pins;
  claims.push({
    target,
    claim: 'command/args/url',
    status:
      pins.length === 0 || observedPins.length === 0 ? 'untested' : changed ? 'violated' : 'passed',
    observed: observedPins.length,
    allowed: pins.length,
    detail:
      pins.length === 0
        ? 'command, args and url are not pinned'
        : changed
          ? 'command, args or url differ from the model'
          : `${pins.join(', ')} matches`,
    enforcement: ENFORCEMENT.command,
  });
  const envObserved = added(server.env, base?.env, diff);
  claims.push(
    listClaim({
      target,
      claim: 'env',
      observed: envObserved,
      allow: (name) => nameAllowed(name, allowed.env),
      diff,
      noun: 'var',
      tail: 'allowed',
      enforcement: ENFORCEMENT.env,
    }),
  );
  claims.push({
    target,
    claim: 'tools',
    status: 'untested',
    observed: 0,
    allowed: allowed.tools?.length ?? 0,
    detail: 'no tool-call list to check',
    enforcement: ENFORCEMENT.tools,
    unenforced: true,
  });
  if (allowed.purpose) claims.push(unenforced(target, 'purpose', allowed.purpose, allowed.purpose));
  return claims;
}

function yamlAtom(value: string): string {
  return /^[A-Za-z0-9._*-]+$/.test(value) ? value : JSON.stringify(value);
}

function coversHost(model: ThreatModel, host: string): boolean {
  return Object.values(model.skills).some((entry) => hostAllowed(host, entry.network));
}

function coversName(model: ThreatModel, name: string, field: 'env' | 'tokens'): boolean {
  return Object.values(model.skills).some((entry) => nameAllowed(name, entry[field]));
}

function webhookHost(value: string): string {
  return value.split('/')[0] ?? value;
}

export function assessClaims(input: {
  model: ThreatModel;
  profiles: SkillProfile[];
  mcp: McpServerDef[];
  baseProfiles?: SkillProfile[];
  baseMcp?: McpServerDef[];
  diff: boolean;
}): ClaimAssessment {
  const claims: ClaimResult[] = [];
  for (const profile of input.profiles) {
    claims.push(
      ...skillClaims(input.model, profile, baseProfile(profile, input.baseProfiles), input.diff),
    );
  }
  for (const server of input.mcp) {
    const base = input.baseMcp?.find((item) => item.name === server.name);
    claims.push(...mcpClaims(input.model, server, base, input.diff));
  }
  return { claims, uncovered: uncoveredCapabilities(input) };
}

function uncoveredCapabilities(input: {
  model: ThreatModel;
  profiles: SkillProfile[];
  mcp: McpServerDef[];
  baseProfiles?: SkillProfile[];
  baseMcp?: McpServerDef[];
  diff: boolean;
}): UncoveredCapability[] {
  const out: UncoveredCapability[] = [];
  const seen = new Set<string>();
  const push = (item: UncoveredCapability): void => {
    const key = `${item.kind}|${item.target}|${item.value}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(item);
  };
  for (const profile of input.profiles) {
    const base = baseProfile(profile, input.baseProfiles);
    const id = skillId(input.model, profile);
    const target = targetOf(id, profile);
    const file = `${profile.key}/SKILL.md`;
    const webhookHosts = new Set<string>();
    for (const hook of added(profile.webhooks, base?.webhooks, input.diff)) {
      const host = webhookHost(hook);
      webhookHosts.add(host);
      if (coversHost(input.model, host)) continue;
      push({
        target,
        kind: 'webhook',
        value: hook,
        file,
        suggestedClaim: `skills.${id}.network: [${yamlAtom(host)}]`,
      });
    }
    for (const host of added(profile.hosts, base?.hosts, input.diff)) {
      if (webhookHosts.has(host) || coversHost(input.model, host)) continue;
      push({
        target,
        kind: 'host',
        value: host,
        file,
        suggestedClaim: `skills.${id}.network: [${yamlAtom(host)}]`,
      });
    }
    for (const name of added(profile.tokens, base?.tokens, input.diff)) {
      if (coversName(input.model, name, 'tokens')) continue;
      push({
        target,
        kind: 'token',
        value: name,
        file,
        suggestedClaim: `skills.${id}.tokens: [${yamlAtom(name)}]`,
      });
    }
    for (const name of added(profile.env, base?.env, input.diff)) {
      if (coversName(input.model, name, 'env') || coversName(input.model, name, 'tokens')) continue;
      push({
        target,
        kind: 'env',
        value: name,
        file,
        suggestedClaim: `skills.${id}.env: [${yamlAtom(name)}]`,
      });
    }
  }
  for (const server of input.mcp) {
    const baseNames = new Set((input.baseMcp ?? []).map((item) => item.name));
    if (input.diff && baseNames.has(server.name)) continue;
    if (input.model.mcpServers[server.name]) continue;
    push({
      target: server.name,
      kind: 'mcp-server',
      value: server.name,
      file: server.file,
      suggestedClaim: `mcpServers.${server.name}: {}`,
    });
  }
  return out;
}

function remoteSeverity(
  policy: ThreatModel['defaults']['remoteInstructions'],
): Violation['severity'] {
  if (policy === 'deny') return 'high';
  if (policy === 'warn') return 'medium';
  return 'info';
}

function alreadyCovered(existing: readonly Violation[], value: string): boolean {
  return existing.some((v) => v.detail === value);
}

/** Violations that opt-in policy adds. Info remote-instruction hits do not change the exit code. */
export function claimViolations(input: {
  model: ThreatModel;
  claims: ClaimResult[];
  uncovered: UncoveredCapability[];
  existing: readonly Violation[];
  failOnUncovered: boolean;
}): Violation[] {
  const out: Violation[] = [];
  const remote = input.model.defaults.remoteInstructions;
  for (const claim of input.claims) {
    if (claim.claim !== 'remote-instructions' || claim.status !== 'violated') continue;
    out.push({
      kind: 'remote-instructions',
      severity: remoteSeverity(remote),
      target: claim.target,
      detail:
        'instruction text tells the agent to fetch a URL and follow it (IH-INJ-004). A hash pins the file, not the page it points to.',
    });
  }
  const fail = input.failOnUncovered || input.model.defaults.uncovered === 'fail';
  if (!fail) return out;
  const seen = new Set<string>();
  for (const item of input.uncovered) {
    if (alreadyCovered(input.existing, item.value) || seen.has(item.value)) continue;
    seen.add(item.value);
    out.push({
      kind: 'uncovered-capability',
      severity: 'high',
      target: item.target,
      detail: item.value,
      ...(item.file ? { file: item.file } : {}),
    });
  }
  return out;
}
