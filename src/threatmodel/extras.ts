/**
 * Threat model checks added in 0.24.0 (suggested by Moltbook bots; credits in CHANGELOG):
 * declared writes and persistence, triggers with owners, independent observers per reach,
 * egress per code branch with the secret it carries, env-chosen destinations, skill folders
 * outside the declared scope, and the review tier for widenings (reasons, non-author
 * approval, evidence that predates the change, reason rows that reopen on dependency change).
 * Static text checks: they say what the files name, not what runs.
 */
import { readFile, readdir } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import picomatch from 'picomatch';
import { snapshotSkill } from '../drift/drift.ts';
import {
  hostAllowed,
  isSecretName,
  toPosix,
  type SkillEntryT,
  type SkillProfile,
  type ThreatModel,
  type Violation,
} from './threatmodel.ts';

export interface LineHit {
  value: string;
  file: string;
  line: number;
  why: string;
}

export interface FallbackHit extends LineHit {
  env: string;
  host: string;
  secret: string | null;
}

export interface ExtraProfile {
  key: string;
  writes: LineHit[];
  triggers: LineHit[];
  fallbacks: FallbackHit[];
  destinationEnv: LineHit[];
  /** Secret names used within 5 lines of each host, for egress-per-branch checks. */
  hostSecrets: Array<{ host: string; secret: string; file: string; line: number }>;
}

const MAX_TEXT = 1_048_576;

async function fileLines(root: string): Promise<Array<{ file: string; lines: string[] }>> {
  const rec = await snapshotSkill(root);
  const out: Array<{ file: string; lines: string[] }> = [];
  for (const [rel, hash] of Object.entries(rec.files)) {
    if (hash === 'symlink' || hash.startsWith('oversize:')) continue;
    try {
      const buf = await readFile(resolve(rec.root, rel));
      if (buf.length > MAX_TEXT || buf.subarray(0, 8000).includes(0)) continue;
      out.push({ file: rel, lines: buf.toString('utf8').split(/\r?\n/) });
    } catch {
      /* unreadable */
    }
  }
  return out;
}

const WRITE_PATTERNS: Array<[RegExp, string]> = [
  [
    /\b(?:writeFile|appendFile|writeFileSync|appendFileSync|createWriteStream)\s*\(\s*['"`]([^'"`]+)['"`]/g,
    'file write',
  ],
  [/\bopen\(\s*['"]([^'"]+)['"]\s*,\s*['"][wax]\+?b?['"]/g, 'file write'],
  [/(?:^|[^\d&>])>>?\s*(['"]?)([~$./][^\s;|&'"]+)\1/g, 'shell redirect'],
  [/\btee\s+(?:-a\s+)?([~$./][^\s;|&]+)/g, 'tee'],
  [/\bmkdir\s+-p\s+([~$/][^\s;|&]+)/g, 'mkdir'],
];

const ON_BEHALF: Array<[RegExp, string, string]> = [
  [/\bpip3?\s+install\b/, 'site-packages', "pip install writes on the skill's behalf"],
  [
    /\bnpm\s+(?:i|install)\s+-g\b|\bnpm\s+install\s+--global\b/,
    'global node_modules',
    "npm install -g writes on the skill's behalf",
  ],
  [
    /\bgit\s+config\s+--global\b/,
    '~/.gitconfig',
    "git config --global writes on the skill's behalf",
  ],
  [/\bcrontab\s+(?!-l)/, 'crontab', 'crontab installs a scheduled job'],
  [
    /\blaunchctl\s+(?:load|bootstrap)\b/,
    '~/Library/LaunchAgents',
    'launchctl registers a login item',
  ],
  [/\bsystemctl\s+(?:--user\s+)?enable\b/, 'systemd unit', 'systemctl enable registers a service'],
  [/navigator\.serviceWorker\.register\s*\(/, 'service-worker', 'registers a service worker'],
];

const STARTUP =
  /(?:\.bashrc|\.zshrc|\.zprofile|\.bash_profile|(?:^|[/~])\.profile|config\.fish|crontab|LaunchAgents|LaunchDaemons|systemd|autostart|rc\.local|service-worker)/;
const OTHER_TOOL =
  /(?:\.claude\/|\.cursor\/|\.codex\/|\.vscode\/|mcp\.json|\.gitconfig|\.npmrc|\.pypirc|\.openclaw\/)/;
const PACKAGE_OR_ENV = /(?:^|\/)(?:package\.json|\.env(?:\.[\w-]+)?)$/;

export function persistenceClass(path: string): string | null {
  if (STARTUP.test(path)) return 'startup file';
  if (OTHER_TOOL.test(path)) return "another tool's config";
  if (PACKAGE_OR_ENV.test(path)) return path.endsWith('package.json') ? 'package.json' : '.env';
  return null;
}

const TRIGGERS: Array<[RegExp, string]> = [
  [/\bheartbeat\b/i, 'heartbeat'],
  [
    /\bcrontab\b|\bcron\s*\(|\bschedule:\s|\bsetInterval\s*\(|@every\b|on:\s*schedule|\bevery \d+ (?:minutes|hours)\b/i,
    'schedule',
  ],
  [/"hooks"\s*:|\bPreToolUse\b|\bPostToolUse\b|\bSessionStart\b|\bUserPromptSubmit\b/, 'hook'],
  [/\b(?:on|at) (?:session )?start(?:up)?\b|\bautostart\b|\bonStartup\b/i, 'on-startup'],
];

const FALLBACK: RegExp[] = [
  /process\.env\.([A-Z][A-Z0-9_]*)\s*(?:\|\||\?\?)\s*['"`](https?:\/\/[^'"`\s]+)/g,
  /process\.env\[['"]([A-Z][A-Z0-9_]*)['"]\]\s*(?:\|\||\?\?)\s*['"`](https?:\/\/[^'"`\s]+)/g,
  /os\.(?:getenv|environ\.get)\(\s*['"]([A-Z][A-Z0-9_]*)['"]\s*,\s*['"](https?:\/\/[^'"\s]+)/g,
  /\$\{([A-Z][A-Z0-9_]*):?-(https?:\/\/[^}\s]+)\}/g,
];
const DEST_ENV =
  /\b(?:process\.env\.|process\.env\[['"]|os\.(?:getenv|environ\.get)\(\s*['"]|os\.environ\[['"]|\$\{?)([A-Z][A-Z0-9_]*(?:URL|URI|HOST|ENDPOINT|WEBHOOK|BUCKET|BASE|BASE_URL|DSN))\b/g;
const SECRET_REF =
  /\b([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|AUTH|CREDENTIAL|COOKIE|SESSION)[A-Z0-9_]*)\b/g;
const URL_HOST = /\b(?:https?|wss?):\/\/([a-z0-9.-]+)/gi;

const hostOf = (u: string): string => {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return u;
  }
};

export async function profileExtras(profile: SkillProfile): Promise<ExtraProfile> {
  const files = await fileLines(profile.root);
  const writes: LineHit[] = [];
  const triggers: LineHit[] = [];
  const fallbacks: FallbackHit[] = [];
  const destinationEnv: LineHit[] = [];
  const hostSecrets: ExtraProfile['hostSecrets'] = [];
  const seenTrig = new Set<string>();
  for (const { file, lines } of files) {
    if (/(?:^|\/)HEARTBEAT\.md$/i.test(file) && !seenTrig.has('heartbeat')) {
      seenTrig.add('heartbeat');
      triggers.push({ value: 'heartbeat', file, line: 1, why: 'HEARTBEAT.md runs on a timer' });
    }
    lines.forEach((text, i) => {
      const line = i + 1;
      for (const [re, why] of WRITE_PATTERNS) {
        for (const m of text.matchAll(re)) {
          const p = (m[2] ?? m[1] ?? '').replace(/^\$HOME/, '~').replace(/[.,:)]+$/, '');
          if (!p || /^\/dev\//.test(p) || /^&/.test(p) || p.length < 2) continue;
          writes.push({ value: p.replace(/^\.\//, ''), file, line, why });
        }
      }
      for (const [re, value, why] of ON_BEHALF)
        if (re.test(text)) writes.push({ value, file, line, why });
      for (const [re, value] of TRIGGERS)
        if (!seenTrig.has(value) && re.test(text)) {
          seenTrig.add(value);
          triggers.push({ value, file, line, why: text.trim().slice(0, 120) });
        }
      const window = lines.slice(Math.max(0, i - 5), i + 6).join('\n');
      const secrets = [...window.matchAll(SECRET_REF)]
        .map((m) => m[1] as string)
        .filter(isSecretName);
      const bearer = /\bAuthorization\b|\bBearer\b/.test(window);
      for (const re of FALLBACK)
        for (const m of text.matchAll(re)) {
          const env = m[1] as string;
          const host = hostOf(m[2] as string);
          const secret = secrets.find((s) => s !== env) ?? (bearer ? 'Authorization header' : null);
          fallbacks.push({
            value: host,
            env,
            host,
            secret,
            file,
            line,
            why: `default when ${env} is unset`,
          });
        }
      for (const m of text.matchAll(DEST_ENV))
        destinationEnv.push({
          value: m[1] as string,
          file,
          line,
          why: 'env var chooses a destination',
        });
      for (const m of text.matchAll(URL_HOST)) {
        const host = (m[1] as string).toLowerCase();
        for (const s of new Set(secrets)) hostSecrets.push({ host, secret: s, file, line });
      }
    });
  }
  const uniq = <T extends LineHit>(xs: T[]): T[] => {
    const seen = new Set<string>();
    return xs.filter((x) => {
      const k = `${x.value}|${x.why}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  };
  return {
    key: profile.key,
    writes: uniq(writes),
    triggers,
    fallbacks: uniq(fallbacks),
    destinationEnv: uniq(destinationEnv),
    hostSecrets,
  };
}

const norm = (p: string): string =>
  p
    .replace(/^\$HOME/, '~')
    .replace(/^\.\//, '')
    .replace(/\/+$/, '');

export function writeCovered(path: string, declared: string[]): boolean {
  const n = norm(path);
  return declared.some((d) => {
    const g = norm(d);
    return n === g || n.startsWith(g + '/') || picomatch(g, { dot: true })(n);
  });
}

function declaredWrites(e: SkillEntryT): Array<{ path: string; reason?: string }> {
  if (e.writes === undefined || e.writes === 'none') return [];
  return e.writes.map((w) => (typeof w === 'string' ? { path: w } : w));
}

export interface ExtrasResult {
  violations: Violation[];
  /** Writes seen in the files but not declared, proposed for a human to accept (never persistence). */
  proposedWrites: Array<{
    target: string;
    path: string;
    why: string;
    file: string;
    line: number;
    denyByDefault?: true;
  }>;
}

const DAY = 86_400_000;

export function evaluateExtras(
  model: ThreatModel,
  profiles: SkillProfile[],
  extras: ExtraProfile[],
  now = new Date(),
): ExtrasResult {
  const v: Violation[] = [];
  const proposed: ExtrasResult['proposedWrites'] = [];
  const d = model.defaults;
  const byKey = new Map(extras.map((x) => [x.key, x]));
  for (const [id, e] of Object.entries(model.skills)) {
    const key = norm(toPosix(e.path));
    const p = profiles.find((x) => x.key === key);
    const x = byKey.get(key);
    if (!p || !x) continue;
    const t = `${id} (${key})`;
    const at = (h: LineHit): string => `${key}/${h.file}`;
    /* writes and persistence */
    const writesOn = d.writes === 'require' || e.writes !== undefined;
    if (d.writes === 'require' && e.writes === undefined)
      v.push({
        kind: 'writes-missing',
        severity: 'high',
        target: t,
        detail:
          'no writes section; declare the places this skill may leave things behind, or writes: none',
        file: `${key}/SKILL.md`,
      });
    if (writesOn) {
      const decl = declaredWrites(e);
      const paths = decl.map((w) => w.path);
      for (const w of x.writes) {
        const cls = persistenceClass(w.value);
        const hit = decl.find((dw) => writeCovered(w.value, [dw.path]));
        if (cls) {
          if (d.persistence === 'deny' || !hit || !hit.reason)
            v.push({
              kind: 'persistence-write',
              severity: 'high',
              target: t,
              detail: `${w.value} (${cls}) at ${w.file}:${w.line}: ${w.why}${d.persistence === 'deny' ? '; persistence: deny fails on declaration alone' : hit ? '; declared without a reason' : ''}`,
              file: at(w),
            });
          if (!hit)
            proposed.push({
              target: t,
              path: w.value,
              why: w.why,
              file: at(w),
              line: w.line,
              denyByDefault: true,
            });
          continue;
        }
        if (!hit) {
          v.push({
            kind: 'write-not-declared',
            severity: 'high',
            target: t,
            detail: `${w.value} at ${w.file}:${w.line} (${w.why})${e.writes === 'none' ? '; model says writes: none' : ''}`,
            file: at(w),
          });
          proposed.push({
            target: t,
            path: w.value,
            why: `${w.why} at ${w.file}:${w.line}`,
            file: at(w),
            line: w.line,
          });
        }
      }
      for (const dp of paths)
        if (!x.writes.some((w) => writeCovered(w.value, [dp])))
          v.push({
            kind: 'write-declared-unused',
            severity: 'info',
            target: t,
            detail: `declared write ${dp} is never named in the skill files (over-wide; remove it so the model does not only grow)`,
            file: `${key}/SKILL.md`,
          });
    }
    /* triggers */
    const triggersOn = d.triggers === 'require' || e.triggers !== undefined;
    if (triggersOn) {
      const declared = e.triggers ?? [];
      for (const tr of x.triggers)
        if (!declared.some((dt) => dt.kind === tr.value))
          v.push({
            kind: 'trigger-undeclared',
            severity: 'high',
            target: t,
            detail: `${tr.value} trigger at ${tr.file}:${tr.line} is not declared; a trigger is new reach even for a read-only skill`,
            file: `${key}/${tr.file}`,
          });
      for (const dt of declared) {
        if (dt.kind === 'on-request') continue;
        if (!dt.owner && !dt.audience)
          v.push({
            kind: 'trigger-no-owner',
            severity: 'high',
            target: t,
            detail: `${dt.kind} trigger has no owner or audience: a scheduled output nobody reads is new reach`,
            file: `${key}/SKILL.md`,
          });
        else if (dt.owner && /^#|\bchannel\b/i.test(dt.owner))
          v.push({
            kind: 'trigger-no-owner',
            severity: 'medium',
            target: t,
            detail: `${dt.kind} trigger owner "${dt.owner}" is a channel; name a person or a pager who acts if it looks wrong`,
            file: `${key}/SKILL.md`,
          });
        const last = dt.lastExercised ? Date.parse(dt.lastExercised) : NaN;
        if (!dt.escalation || !Number.isFinite(last) || now.getTime() - last > 90 * DAY)
          v.push({
            kind: 'escalation-unexercised',
            severity: 'medium',
            target: t,
            detail: `${dt.kind} trigger: ${!dt.escalation ? 'no escalation path' : !Number.isFinite(last) ? 'escalation path never exercised (counts as missing)' : `escalation last exercised ${dt.lastExercised}, over 90 days ago`}`,
            file: `${key}/SKILL.md`,
          });
      }
    }
    /* observers */
    const warnExpired =
      d.observers === 'warn' &&
      d.observersWarnUntil !== undefined &&
      Date.parse(d.observersWarnUntil) < now.getTime();
    const obsMode =
      d.observers !== 'off'
        ? warnExpired
          ? 'require'
          : d.observers
        : e.observers
          ? 'require'
          : 'off';
    if (obsMode !== 'off') {
      const reaches: Array<'network' | 'secrets' | 'writes' | 'read'> = ['read'];
      if (p.hosts.length) reaches.push('network');
      if (p.tokens.length || p.paths.some((q) => /\.ssh|\.aws|\.env|credential|token/i.test(q)))
        reaches.push('secrets');
      if (x.writes.length) reaches.push('writes');
      const skillWritable = [...e.filesystem, ...declaredWrites(e).map((w) => w.path), key];
      for (const r of reaches) {
        const obs = (e.observers ?? []).filter((o) => o.reaches.includes(r));
        const independent = obs.filter(
          (o) =>
            o.kind !== 'in-skill' &&
            o.identity !== 'same' &&
            !(o.store && o.writeOnce !== true && writeCovered(o.store, skillWritable)),
        );
        const leaves = r !== 'read';
        if (!obs.length) {
          v.push({
            kind: 'observer-missing',
            severity: leaves && obsMode === 'require' ? 'high' : 'medium',
            target: t,
            detail: `${r} reach has no observer outside the skill${leaves ? ' (reach that leaves the process)' : ' (local read-only)'}`,
            file: `${key}/SKILL.md`,
          });
        } else if (!independent.length) {
          v.push({
            kind: 'observer-self-witness',
            severity: leaves && obsMode === 'require' ? 'high' : 'medium',
            target: t,
            detail: `${r} reach is witnessed only by ${obs.map((o) => o.name).join(', ')}, which runs as the skill or writes to a store the skill can rewrite; the actor cannot be its own witness`,
            file: `${key}/SKILL.md`,
          });
        }
        for (const o of independent)
          if (!o.heartbeat)
            v.push({
              kind: 'observer-no-heartbeat',
              severity: 'medium',
              target: t,
              detail: `observer ${o.name} has no declared heartbeat; a beat is new records in its store within the interval, not a live process`,
              file: `${key}/SKILL.md`,
            });
      }
    }
    /* egress per branch, fallbacks, env-chosen destinations */
    const egressOn =
      d.egress === 'deny' || e.egress !== undefined || e.destinationEnv !== undefined;
    for (const f of x.fallbacks) {
      const allowed = hostAllowed(f.host, e.network);
      if (allowed && !egressOn) continue;
      const decl = (e.egress ?? []).find((g) => hostAllowed(f.host, [g.host]));
      v.push({
        kind: 'fallback-host',
        severity: allowed ? 'info' : 'high',
        target: t,
        detail: `branch "default when ${f.env} is unset" sends to ${f.host}${f.secret ? ` carrying ${f.secret}` : ''} (${f.file}:${f.line})${allowed ? '; host is allowed, listed so reviewers see the default' : '; host is not in the model: an unset variable must fail closed, not invent a destination'}`,
        file: at(f),
      });
      if (e.egress && allowed && !decl)
        v.push({
          kind: f.secret ? 'egress-secret-not-declared' : 'egress-branch-undeclared',
          severity: f.secret ? 'high' : 'medium',
          target: t,
          detail: `branch "default when ${f.env} is unset" -> ${f.host}${f.secret ? ` carries ${f.secret}` : ''} but egress has no row for it`,
          file: at(f),
        });
    }
    if (e.egress) {
      const seen = new Set<string>();
      for (const hs of x.hostSecrets) {
        const k = `${hs.host}|${hs.secret}`;
        if (seen.has(k)) continue;
        seen.add(k);
        if (!hostAllowed(hs.host, e.network)) continue;
        const ok = e.egress.some((g) => hostAllowed(hs.host, [g.host]) && g.secret === hs.secret);
        if (!ok)
          v.push({
            kind: 'egress-secret-not-declared',
            severity: 'high',
            target: t,
            detail: `${hs.host} is named within 5 lines of ${hs.secret} (${hs.file}:${hs.line}); egress has no row carrying that secret to that host`,
            file: `${key}/${hs.file}`,
          });
      }
    }
    for (const de of egressOn ? x.destinationEnv : []) {
      const set = e.destinationEnv?.[de.value];
      if (!set) {
        v.push({
          kind: 'destination-env-unbounded',
          severity: d.egress === 'deny' ? 'high' : 'medium',
          target: t,
          detail: `${de.value} chooses where data goes (${de.file}:${de.line}) and has no allowed set in destinationEnv; an env override is its own door`,
          file: `${key}/${de.file}`,
        });
        continue;
      }
      const fb = x.fallbacks.find((f) => f.env === de.value);
      if (fb && !hostAllowed(fb.host, set))
        v.push({
          kind: 'destination-env-unbounded',
          severity: 'high',
          target: t,
          detail: `${de.value} default ${fb.host} is not a member of its allowed set (${set.join(', ')}); the default must be the safest member`,
          file: at(fb),
        });
    }
    /* reason expiry */
    for (const [rk, r] of Object.entries(e.reasons ?? {}))
      if (r.expires && Date.parse(r.expires) < now.getTime())
        v.push({
          kind: 'reason-expired',
          severity: 'medium',
          target: t,
          detail: `reason for ${rk} expired ${r.expires}: re-approve it or remove the access`,
          file: `${key}/SKILL.md`,
        });
  }
  /* host-not-allowed for a fallback host is reported once, as the named branch */
  return { violations: v, proposedWrites: proposed };
}

const SKIP = new Set(['.git', 'node_modules', 'dist', 'build', '.venv', 'venv', '__pycache__']);

/** SKILL.md folders anywhere in the repo that are outside every declared skill dir. */
export async function undeclaredSkillFolders(
  base: string,
  skillDirs: string[],
  maxDepth = 6,
): Promise<string[]> {
  const out: string[] = [];
  const declared = skillDirs.map((x) => norm(x));
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const rel = toPosix(relative(base, dir)) || '.';
    if (entries.some((x) => x.isFile() && x.name === 'SKILL.md')) {
      const inside = declared.some(
        (d) => d === '.' || d === '' || rel === d || rel.startsWith(d + '/'),
      );
      if (!inside) out.push(rel);
    }
    for (const x of entries)
      if (x.isDirectory() && !SKIP.has(x.name)) await walk(join(dir, x.name), depth + 1);
  };
  await walk(base, 0);
  return out.sort();
}

export function folderViolations(model: ThreatModel, profiles: SkillProfile[]): Violation[] {
  return profiles.map((p) => {
    const authority = p.shell || p.tokens.length > 0 || p.hosts.length > 0 || p.paths.length > 0;
    return {
      kind: 'undeclared-folder' as const,
      severity:
        authority && model.defaults.undeclaredFolders === 'fail'
          ? ('high' as const)
          : ('info' as const),
      target: p.key,
      detail: authority
        ? `skill folder outside skillDirs grants authority (${[p.shell ? 'shell' : '', p.tokens.length ? 'secrets' : '', p.hosts.length ? 'network' : '', p.paths.length ? 'paths' : ''].filter(Boolean).join(', ')}); the check never searched it`
        : 'skill folder outside skillDirs; inert (no shell, secrets, hosts or paths named)',
      file: `${p.key}/SKILL.md`,
    };
  });
}

/* ---------------- diff: review tier ---------------- */

export interface ReviewInput {
  baseModel: ThreatModel;
  headModel: ThreatModel;
  widenings: Violation[];
  modelFileChanged: boolean;
  author?: string;
  authorKind?: 'human' | 'agent';
  approvers: string[];
  /** Files that exist at base (for evidence that predates the change). */
  baseHas: (rel: string) => Promise<boolean>;
}

export interface ReviewResult {
  violations: Violation[];
  selfApproved: Array<{ target: string; detail: string }>;
  extractorHealth: { classified: number; unclassified: number; rate: number };
}

const CLASSIFIED =
  /^(network|filesystem|env|tokens|dataBoundaries|writes|triggers|egress) \+= |^shell: |^minGrade |^new trusted |^command |^(unknownSkill|unknownMcpServer|remoteInstructions|uncovered|modelChanges|writes|persistence|undeclaredFolders|egress|triggers|observers) /;

function reasonKey(detail: string): string | null {
  const m = /^(network|filesystem|env|tokens|writes|triggers|egress) \+= (\S+)/.exec(detail);
  if (m) return `${m[1]}:${m[2]}`;
  if (detail.startsWith('shell:')) return 'shell';
  return null;
}

const isBot = (n: string): boolean => /\[bot\]$|-bot$|^bot-/i.test(n);

export async function reviewTier(input: ReviewInput): Promise<ReviewResult> {
  const v: Violation[] = [];
  const selfApproved: ReviewResult['selfApproved'] = [];
  const others = input.approvers.filter(
    (a) => a && a !== input.author && !(input.authorKind === 'agent' && isBot(a)),
  );
  let classified = 0;
  let unclassified = 0;
  for (const w of input.widenings) {
    if (!CLASSIFIED.test(w.detail)) {
      unclassified += 1;
      v.push({
        kind: 'model-change-unclassified',
        severity: 'medium',
        target: w.target,
        detail: `${w.detail}: the extractor could not classify this change, so it goes to the approval tier; exit only with checkable evidence`,
        ...(w.file ? { file: w.file } : {}),
      });
      continue;
    }
    classified += 1;
    const entry = input.headModel.skills[w.target];
    const rk = reasonKey(w.detail);
    const capability = rk !== null || /^new trusted|^command /.test(w.detail);
    const reason = rk && entry?.reasons ? entry.reasons[rk] : undefined;
    if (capability && rk && !reason)
      v.push({
        kind: 'widening-unjustified',
        severity: 'high',
        target: w.target,
        detail: `${w.detail}: add reasons."${rk}" with a reason line; every widening needs a justification reviewed before the code`,
        ...(w.file ? { file: w.file } : {}),
      });
    if (capability && !others.length) {
      selfApproved.push({ target: w.target, detail: w.detail });
      v.push({
        kind: 'widening-self-approved',
        severity: 'high',
        target: w.target,
        detail: `${w.detail}: self-approved mark; needs an approver who did not author the change${input.authorKind === 'agent' ? ' (agent-authored: a human, not a bot)' : ''}`,
        ...(w.file ? { file: w.file } : {}),
      });
    }
    if (reason?.approvedBy && input.author && reason.approvedBy === input.author)
      v.push({
        kind: 'widening-self-approved',
        severity: 'high',
        target: w.target,
        detail: `${w.detail}: reasons."${rk}".approvedBy is the author (${input.author})`,
        ...(w.file ? { file: w.file } : {}),
      });
    if (reason?.evidence && !(await input.baseHas(reason.evidence)))
      v.push({
        kind: 'widening-evidence-same-change',
        severity: 'medium',
        target: w.target,
        detail: `${w.detail}: evidence ${reason.evidence} does not exist at base; evidence must not be produced by the same change`,
        ...(w.file ? { file: w.file } : {}),
      });
    const value = rk?.split(':').slice(1).join(':');
    if (
      reason &&
      value &&
      reason.reviewerNote !== undefined &&
      !reason.reviewerNote.includes(value)
    )
      v.push({
        kind: 'widening-review-vague',
        severity: 'medium',
        target: w.target,
        detail: `${w.detail}: reviewerNote must say something concrete about ${value}, not only approve`,
        ...(w.file ? { file: w.file } : {}),
      });
  }
  if (input.modelFileChanged && !others.length)
    v.push({
      kind: 'model-file-self-approved',
      severity: 'high',
      target: 'threat model',
      detail:
        'the threat model file changed; it needs a separate approval from someone other than the author so the boundary has a fixed point',
    });
  const total = classified + unclassified;
  return {
    violations: v,
    selfApproved,
    extractorHealth: {
      classified,
      unclassified,
      rate: total ? Math.round((unclassified / total) * 1000) / 1000 : 0,
    },
  };
}

/* ---------------- diff: lockfiles, reasons, triggers ---------------- */

export interface LockPkg {
  version: string | null;
  resolved: string | null;
}

export async function readLock(dir: string): Promise<Record<string, LockPkg> | null> {
  try {
    const lock = JSON.parse(await readFile(join(dir, 'package-lock.json'), 'utf8')) as {
      packages?: Record<string, { version?: string; resolved?: string }>;
    };
    const out: Record<string, LockPkg> = {};
    for (const [k, v] of Object.entries(lock.packages ?? {})) {
      if (!k) continue;
      out[k.replace(/^.*node_modules\//, '')] = {
        version: v.version ?? null,
        resolved: v.resolved ?? null,
      };
    }
    return out;
  } catch {
    return null;
  }
}

const publisherOf = (resolved: string | null): string | null => {
  if (!resolved) return null;
  try {
    const u = new URL(resolved);
    return `${u.host}${u.pathname.split('/-/')[0]?.split('/').slice(0, 2).join('/') ?? ''}`;
  } catch {
    return resolved;
  }
};

export function lockAndReasonChanges(
  headModel: ThreatModel,
  pairs: Array<{
    id: string;
    key: string;
    base: Record<string, LockPkg> | null;
    head: Record<string, LockPkg> | null;
  }>,
  introducedReach: boolean,
): Violation[] {
  const v: Violation[] = [];
  for (const { id, key, base, head } of pairs) {
    if (!base && !head) continue;
    const b = base ?? {};
    const h = head ?? {};
    const changed = Object.keys({ ...b, ...h }).filter(
      (n) => b[n]?.version !== h[n]?.version || b[n]?.resolved !== h[n]?.resolved,
    );
    if (!changed.length) continue;
    const t = `${id} (${key})`;
    const entry = headModel.skills[id];
    const added = changed.filter((n) => !b[n]);
    for (const [rk, r] of Object.entries(entry?.reasons ?? {})) {
      if (!r.package) continue;
      const pb = b[r.package];
      const ph = h[r.package];
      let why: string | null = null;
      if (pb && !ph && added.length && r.reopenOn.includes('fork'))
        why = `${r.package} was replaced (new: ${added.join(', ')}); a new package name is a fork`;
      else if (pb && ph && pb.version !== ph.version && r.reopenOn.includes('dependency-update'))
        why = `${r.package} ${pb.version} -> ${ph.version}`;
      else if (
        pb &&
        ph &&
        publisherOf(pb.resolved) !== publisherOf(ph.resolved) &&
        r.reopenOn.includes('publisher-change')
      )
        why = `${r.package} publisher/source changed (${publisherOf(pb.resolved)} -> ${publisherOf(ph.resolved)})`;
      if (why)
        v.push({
          kind: 'reason-reopened',
          severity: 'high',
          target: t,
          detail: `reasons."${rk}" reopened: ${why}. Old row: "${r.reason}"${r.approvedBy ? ` (approved by ${r.approvedBy}${r.approvedAtVersion ? ` at ${r.approvedAtVersion}` : ''})` : ''}; confirm the diff and re-approve`,
          file: `${key}/package-lock.json`,
        });
    }
    if (!introducedReach)
      v.push({
        kind: 'lockfile-churn',
        severity: 'info',
        target: t,
        detail: `lockfile changed with no new reach: ${changed.slice(0, 10).join(', ')}${changed.length > 10 ? ', ...' : ''}`,
        file: `${key}/package-lock.json`,
      });
  }
  return v;
}

export function triggerChanges(
  headModel: ThreatModel,
  baseExtras: ExtraProfile[],
  headExtras: ExtraProfile[],
  strict: boolean,
): Violation[] {
  const v: Violation[] = [];
  const kinds = (x: ExtraProfile | undefined): string[] =>
    x?.triggers.length ? [...new Set(x.triggers.map((t) => t.value))].sort() : ['on-request'];
  for (const h of headExtras) {
    const b = baseExtras.find((x) => x.key === h.key);
    if (!b) continue;
    const before = kinds(b);
    const after = kinds(h);
    if (before.join(',') === after.join(',')) continue;
    const id =
      Object.entries(headModel.skills).find(([, e]) => norm(toPosix(e.path)) === h.key)?.[0] ??
      h.key;
    v.push({
      kind: 'trigger-changed',
      severity: strict ? 'high' : 'medium',
      target: `${id} (${h.key})`,
      detail: `trigger changed from ${before.join('+')} to ${after.join('+')}; the prior review is void because this premise moved`,
      file: `${h.key}/SKILL.md`,
    });
  }
  return v;
}
