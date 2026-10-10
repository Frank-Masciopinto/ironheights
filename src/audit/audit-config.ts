import { lstat, readFile, stat } from 'node:fs/promises';
import { basename } from 'node:path';
import type { Finding, Rule, Severity, SkillReport, Verdict } from '../core/types.ts';
import { scoreFindings, verdictFor } from '../core/verdict.ts';
import { parseJson5, locateOpenClaw } from '../openclaw/locate.ts';
import { isBroadPath } from '../util/paths.ts';
import { clip } from '../util/text.ts';
import { cfg001, cfg002, cfg003, cfg004, cfg005, cfg006, cfg007, cfg008, cfg009 } from './rules.ts';

export const AUDIT_LIMITS = [
  'Reads the OpenClaw config file only. It does not start the Gateway, open a socket, or run openclaw security audit.',
  'Does not follow $include. Included files are not read.',
  'Does not resolve SecretRefs or read OPENCLAW_GATEWAY_TOKEN, OPENCLAW_GATEWAY_PASSWORD, or other secret environment variables.',
  'Does not flag a loopback bind that simply omits gateway.auth. Native gateway.loopback_no_auth can still fire once OpenClaw resolves the effective auth.',
  'Does not implement token length, rate limits, Tailscale Serve, hooks, browser, plugins, mDNS, or sandbox mount checks. Those stay in the native catalog.',
  'On Windows, Unix mode bits are not ACLs. IH-CFG-006 does not report world-readable permissions there and does not run icacls.',
  'JSON5 support is the small subset parseJson5 already accepts (comments, trailing commas, unquoted keys), not a full JSON5 parser.',
] as const;

const SECRET_KEY =
  /(?:token|password|passwd|secret|apikey|api_key|accesstoken|access_token|privatekey|private_key|bottoken|apptoken|signalsecret|signingsecret)$/i;

const PLACEHOLDERS = new Set([
  '',
  'undefined',
  'null',
  'changeme',
  'change-me',
  'change_me',
  'password',
  'secret',
  'token',
  'your-token',
  'your-password',
  'replace-me',
  'replace-with-long-random-token',
  'todo',
  'test',
  'example',
  'xxx',
]);

const LOOPBACK_HOSTS = new Set(['loopback', 'localhost', '127.0.0.1', '::1', '[::1]']);

export interface AuditConfigResult {
  configPath: string;
  configFound: boolean;
  configParsed: boolean;
  limits: string[];
  skills: SkillReport[];
  verdict: Verdict;
}

export async function auditOpenClawConfig(
  env: NodeJS.ProcessEnv = process.env,
): Promise<AuditConfigResult> {
  const located = await locateOpenClaw(env);
  const limits: string[] = [...AUDIT_LIMITS];
  const fileName = basename(located.configPath);
  if (!located.configFound) {
    return {
      configPath: located.configPath,
      configFound: false,
      configParsed: false,
      limits,
      verdict: 'no-findings',
      skills: [
        emptyReport(
          located.stateDir,
          'OpenClaw config was not found. Nothing in the file was audited.',
        ),
      ],
    };
  }

  let raw: string;
  try {
    raw = await readFile(located.configPath, 'utf8');
  } catch {
    return incomplete(
      located.configPath,
      located.stateDir,
      fileName,
      'config file could not be read',
      limits,
    );
  }
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
  if (raw.includes('$include')) {
    limits.push('This file mentions $include. Those files were not opened.');
  }

  let parsed: unknown;
  try {
    parsed = parseJson5(raw);
  } catch {
    return incomplete(
      located.configPath,
      located.stateDir,
      fileName,
      'OpenClaw config was found but could not be parsed',
      limits,
    );
  }

  const findings: Finding[] = [];
  findings.push(...(await permissionFindings(located.configPath, fileName, raw)));
  findings.push(...policyFindings(parsed, raw, fileName, env));
  findings.sort(compareAuditFindings);
  const score = scoreFindings(findings);
  const verdict = verdictFor(findings, { block: 80, review: 15 });
  return {
    configPath: located.configPath,
    configFound: true,
    configParsed: true,
    limits,
    verdict,
    skills: [
      {
        skillName: 'openclaw-config',
        root: located.stateDir,
        filesScanned: 1,
        filesSkipped: [],
        findings,
        score,
        verdict,
      },
    ],
  };
}

function incomplete(
  configPath: string,
  stateDir: string,
  fileName: string,
  reason: string,
  limits: string[],
): AuditConfigResult {
  const skipped = [{ file: fileName, reason }];
  const verdict = verdictFor([], { block: 80, review: 15 }, { filesSkipped: 1 });
  return {
    configPath,
    configFound: true,
    configParsed: false,
    limits,
    verdict,
    skills: [
      {
        skillName: 'openclaw-config',
        root: stateDir,
        filesScanned: 0,
        filesSkipped: skipped,
        findings: [],
        score: 0,
        verdict,
      },
    ],
  };
}

function emptyReport(root: string, _note: string): SkillReport {
  return {
    skillName: 'openclaw-config',
    root,
    filesScanned: 0,
    filesSkipped: [],
    findings: [],
    score: 0,
    verdict: 'no-findings',
  };
}

async function permissionFindings(
  filePath: string,
  fileName: string,
  raw: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  let link;
  try {
    link = await lstat(filePath);
  } catch {
    return findings;
  }
  if (!link.isFile() && !link.isSymbolicLink()) {
    return findings;
  }
  let subject = link;
  if (link.isSymbolicLink()) {
    findings.push(
      makeFinding(cfg006, fileName, raw, 'openclaw.json', {
        severity: 'medium',
        evidence: 'symlink',
        message:
          'openclaw.json is a symlink. OpenClaw documents that a symlinked config is unsupported and adds another trust boundary.',
      }),
    );
    try {
      subject = await stat(filePath);
    } catch {
      return findings;
    }
  }
  if (process.platform === 'win32') return findings;
  if (!subject.isFile()) return findings;
  const mode = subject.mode & 0o777;
  const worldWrite = (mode & 0o002) !== 0;
  const groupWrite = (mode & 0o020) !== 0;
  const worldRead = (mode & 0o004) !== 0;
  const groupRead = (mode & 0o040) !== 0;
  if (!worldWrite && !groupWrite && !worldRead && !groupRead) return findings;
  const octal = mode.toString(8).padStart(3, '0');
  let severity: Severity = 'medium';
  if (worldWrite || groupWrite || worldRead) severity = 'critical';
  const reason = worldWrite
    ? 'world-writable'
    : groupWrite
      ? 'group-writable'
      : worldRead
        ? 'world-readable'
        : 'group-readable';
  findings.push(
    makeFinding(cfg006, fileName, raw, 'openclaw.json', {
      severity,
      evidence: `mode ${octal} (${reason})`,
      message: `Config file is ${reason}. Other users may be able to read tokens or change tool policy.`,
    }),
  );
  return findings;
}

interface Collected {
  bind?: string;
  customBindHost?: string;
  tailscaleMode?: string;
  authMode?: string;
  authToken?: unknown;
  authPassword?: unknown;
  hasAuthObject: boolean;
  dmOpen: string[];
  groupOpen: string[];
  execSecurity: string[];
  execAsk: string[];
  elevatedEnabled: boolean;
  elevatedWildcard: boolean;
  sandboxModes: string[];
  sandboxDocker: boolean;
  extraDirs: string[];
  symlinkTargets: string[];
  secrets: Array<{ path: string; placeholder: boolean }>;
}

function policyFindings(
  parsed: unknown,
  raw: string,
  fileName: string,
  env: NodeJS.ProcessEnv,
): Finding[] {
  const collected = collect(parsed);
  const findings: Finding[] = [];
  const dangerousTools =
    collected.execSecurity.some((value) => value === 'full') ||
    collected.elevatedEnabled ||
    collected.dmOpen.length > 0;

  const bind = collected.bind?.toLowerCase();
  if (bind && !LOOPBACK_HOSTS.has(bind)) {
    const custom = collected.customBindHost?.toLowerCase();
    const customLoopback = bind === 'custom' && custom !== undefined && LOOPBACK_HOSTS.has(custom);
    if (!customLoopback) {
      let severity: Severity = 'high';
      if (bind === 'auto') severity = 'medium';
      if (
        bind === '0.0.0.0' ||
        bind === '::' ||
        bind === 'all' ||
        bind === '*' ||
        custom === '0.0.0.0' ||
        custom === '::' ||
        custom === '*'
      ) {
        severity = 'critical';
      }
      findings.push(
        makeFinding(cfg001, fileName, raw, 'bind', {
          severity,
          evidence: `gateway.bind=${collected.bind}`,
          message:
            severity === 'medium'
              ? 'gateway.bind is auto. The effective address is chosen at runtime and was not probed.'
              : 'Gateway bind is not loopback, so the listener may be reachable beyond this machine.',
        }),
      );
    }
  }
  if (collected.tailscaleMode === 'funnel') {
    findings.push(
      makeFinding(cfg001, fileName, raw, 'tailscale', {
        severity: 'critical',
        evidence: 'gateway.tailscale.mode=funnel',
        message: 'Tailscale Funnel publishes the Gateway on the public internet.',
      }),
    );
  }

  const tokenPlaceholder = isPlaceholderValue(collected.authToken);
  const passwordPlaceholder = isPlaceholderValue(collected.authPassword);
  const mode = collected.authMode?.toLowerCase();
  const customHost = collected.customBindHost?.toLowerCase();
  const customIsLoopback =
    bind === 'custom' && customHost !== undefined && LOOPBACK_HOSTS.has(customHost);
  const exposedBind = Boolean(bind) && !LOOPBACK_HOSTS.has(bind ?? '') && !customIsLoopback;
  if (mode === 'none' || mode === 'trusted-proxy') {
    findings.push(
      makeFinding(cfg002, fileName, raw, 'auth', {
        evidence: `gateway.auth.mode=${collected.authMode}`,
        message:
          mode === 'none'
            ? 'Gateway auth mode is none.'
            : 'Gateway auth mode is trusted-proxy. The proxy is the auth boundary. Proxy IPs and identity headers are not checked here.',
      }),
    );
  } else if (exposedBind && !collected.hasAuthObject) {
    findings.push(
      makeFinding(cfg002, fileName, raw, 'auth', {
        evidence: `gateway.bind=${collected.bind ?? 'unset'}`,
        message: 'Gateway bind is not loopback and gateway.auth is missing.',
      }),
    );
  } else if (tokenPlaceholder || passwordPlaceholder) {
    findings.push(
      makeFinding(cfg002, fileName, raw, tokenPlaceholder ? 'token' : 'password', {
        evidence: tokenPlaceholder
          ? 'gateway.auth.token=<redacted>'
          : 'gateway.auth.password=<redacted>',
        message: 'Gateway token or password in the config file is empty or a placeholder.',
      }),
    );
  }

  for (const path of collected.dmOpen) {
    findings.push(
      makeFinding(cfg003, fileName, raw, path, {
        evidence: `${path}=open`,
        message: 'DM policy is open, so a stranger can message the agent.',
      }),
    );
  }
  for (const path of collected.groupOpen) {
    findings.push(
      makeFinding(cfg004, fileName, raw, path, {
        severity: dangerousTools ? 'critical' : 'high',
        evidence: `${path}=open`,
        message: dangerousTools
          ? 'Group policy is open and the config also enables a tool or DM path a stranger could use.'
          : 'Group policy is open, so members of the room can talk to the agent.',
      }),
    );
  }

  for (const secret of collected.secrets) {
    if (
      secret.placeholder &&
      (secret.path === 'gateway.auth.token' || secret.path === 'gateway.auth.password')
    ) {
      continue;
    }
    findings.push(
      makeFinding(cfg005, fileName, raw, secret.path, {
        evidence: `${secret.path}=<redacted>`,
        message: 'A secret-like key is set to a literal string. The value is not printed.',
      }),
    );
  }

  if (collected.execSecurity.some((value) => value === 'full')) {
    findings.push(
      makeFinding(cfg007, fileName, raw, 'security', {
        severity:
          collected.dmOpen.length > 0 || collected.groupOpen.length > 0 ? 'critical' : 'high',
        evidence: 'tools.exec.security=full',
        message: 'Host exec security is full, so tool calls are not limited to an allowlist.',
      }),
    );
  }
  const askOff = collected.execAsk.some((value) => value === 'off' || value === 'never');
  const securityNotDeny = collected.execSecurity.some((value) => value !== 'deny');
  if (askOff && securityNotDeny) {
    findings.push(
      makeFinding(cfg007, fileName, raw, 'ask', {
        evidence: 'tools.exec.ask=off',
        message: 'Exec approval ask is off while exec security is not deny.',
      }),
    );
  }
  if (collected.elevatedEnabled) {
    findings.push(
      makeFinding(cfg007, fileName, raw, 'elevated', {
        severity: collected.elevatedWildcard ? 'critical' : 'high',
        evidence: collected.elevatedWildcard
          ? 'tools.elevated.allowFrom=*'
          : 'tools.elevated.enabled=true',
        message: collected.elevatedWildcard
          ? 'Elevated tools are enabled and allowFrom includes *, which approves every sender.'
          : 'Elevated tools are enabled. Elevated exec runs outside the sandbox.',
      }),
    );
  }

  for (const dir of collected.extraDirs) {
    findings.push(extraDirFinding(cfg008, fileName, raw, 'extraDirs', dir, env));
  }
  for (const dir of collected.symlinkTargets) {
    findings.push(extraDirFinding(cfg008, fileName, raw, 'allowSymlinkTargets', dir, env));
  }

  const sandboxOff = collected.sandboxModes.some((value) => value === 'off');
  const sandboxMissing = collected.sandboxModes.length === 0;
  const execFull = collected.execSecurity.some((value) => value === 'full');
  const openRoom = collected.dmOpen.length > 0 || collected.groupOpen.length > 0;
  if (collected.sandboxDocker && (sandboxOff || sandboxMissing)) {
    findings.push(
      makeFinding(cfg009, fileName, raw, 'docker', {
        evidence: 'sandbox.docker set while sandbox mode is off',
        message: 'Sandbox Docker settings are present and sandbox mode is off or omitted.',
      }),
    );
  }
  if ((sandboxOff || sandboxMissing) && (execFull || collected.elevatedEnabled || openRoom)) {
    findings.push(
      makeFinding(cfg009, fileName, raw, 'sandbox', {
        severity: execFull || collected.elevatedEnabled ? 'high' : 'medium',
        evidence: sandboxOff ? 'sandbox.mode=off' : 'sandbox.mode omitted',
        message:
          'Sandbox is off or omitted while exec, elevated tools, or an open room is configured.',
      }),
    );
  }

  return findings;
}

function extraDirFinding(
  rule: Rule,
  fileName: string,
  raw: string,
  key: string,
  dir: string,
  env: NodeJS.ProcessEnv,
): Finding {
  const broad = isBroadPath(dir, env);
  return makeFinding(rule, fileName, raw, key, {
    severity: broad ? 'critical' : 'medium',
    evidence: clip(`${key}=${dir}`),
    message: broad
      ? `${key} points at a home directory, a filesystem root, or a path that contains '..'.`
      : `${key} loads skills from a directory outside the default OpenClaw locations.`,
  });
}

function collect(parsed: unknown): Collected {
  const collected: Collected = {
    hasAuthObject: false,
    dmOpen: [],
    groupOpen: [],
    execSecurity: [],
    execAsk: [],
    elevatedEnabled: false,
    elevatedWildcard: false,
    sandboxModes: [],
    sandboxDocker: false,
    extraDirs: [],
    symlinkTargets: [],
    secrets: [],
  };
  const root = asRecord(parsed);
  if (!root) return collected;
  const gateway = asRecord(root.gateway);
  if (gateway) {
    if (typeof gateway.bind === 'string') collected.bind = gateway.bind;
    if (typeof gateway.customBindHost === 'string')
      collected.customBindHost = gateway.customBindHost;
    const tailscale = asRecord(gateway.tailscale);
    if (typeof tailscale?.mode === 'string') collected.tailscaleMode = tailscale.mode.toLowerCase();
    const auth = asRecord(gateway.auth);
    if (auth) {
      collected.hasAuthObject = true;
      if (typeof auth.mode === 'string') collected.authMode = auth.mode;
      collected.authToken = auth.token;
      collected.authPassword = auth.password;
    }
  }
  const skills = asRecord(root.skills);
  const load = asRecord(skills?.load);
  if (Array.isArray(load?.extraDirs)) {
    for (const dir of load.extraDirs) {
      if (typeof dir === 'string' && dir.trim().length > 0) collected.extraDirs.push(dir);
    }
  }
  if (Array.isArray(load?.allowSymlinkTargets)) {
    for (const dir of load.allowSymlinkTargets) {
      if (typeof dir === 'string' && dir.trim().length > 0) collected.symlinkTargets.push(dir);
    }
  }
  walk(root, [], collected);
  return collected;
}

function walk(value: unknown, pathParts: string[], collected: Collected): void {
  if (Array.isArray(value)) {
    for (const item of value) walk(item, pathParts, collected);
    return;
  }
  const record = asRecord(value);
  if (!record) return;
  const parent = pathParts[pathParts.length - 1] ?? '';
  for (const [key, child] of Object.entries(record)) {
    const next = [...pathParts, key];
    const path = next.join('.');
    if ((key === 'dmPolicy' || (key === 'policy' && parent === 'dm')) && isOpen(child)) {
      collected.dmOpen.push(path);
    }
    if (key === 'groupPolicy' && isOpen(child)) collected.groupOpen.push(path);
    if (key === 'security' && parent === 'exec' && typeof child === 'string') {
      collected.execSecurity.push(child.toLowerCase());
    }
    if (key === 'ask' && parent === 'exec' && typeof child === 'string') {
      collected.execAsk.push(child.toLowerCase());
    }
    if (key === 'enabled' && parent === 'elevated' && child === true)
      collected.elevatedEnabled = true;
    if (key === 'allowFrom' && pathParts.includes('elevated') && arrayHasStar(child)) {
      collected.elevatedWildcard = true;
    }
    if (key === 'mode' && parent === 'sandbox' && typeof child === 'string') {
      collected.sandboxModes.push(child.toLowerCase());
    }
    if (key === 'docker' && parent === 'sandbox' && asRecord(child)) collected.sandboxDocker = true;
    if (SECRET_KEY.test(key) && isSecretRefObject(child)) continue;
    if (typeof child === 'string' && SECRET_KEY.test(key) && !isSecretReference(child)) {
      collected.secrets.push({ path, placeholder: isPlaceholderValue(child) });
    }
    if (asRecord(child) || Array.isArray(child)) walk(child, next, collected);
  }
}

function makeFinding(
  rule: Rule,
  fileName: string,
  raw: string,
  key: string,
  details: { evidence: string; message: string; severity?: Severity },
): Finding {
  const line = lineOf(raw, key);
  return {
    ruleId: rule.id,
    severity: details.severity ?? rule.severity,
    confidence: 'high',
    file: fileName,
    ...(line !== undefined ? { line } : {}),
    evidence: clip(details.evidence),
    message: details.message,
    remediation: rule.remediation,
  };
}

function lineOf(raw: string, key: string): number | undefined {
  const leaf = key.split('.').pop() ?? key;
  const lines = raw.split(/\r?\n/);
  const needle = new RegExp(`\\b${leaf.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
  for (let i = 0; i < lines.length; i += 1) {
    if (needle.test(lines[i] ?? '')) return i + 1;
  }
  return undefined;
}

function isOpen(value: unknown): boolean {
  return typeof value === 'string' && value.toLowerCase() === 'open';
}

function arrayHasStar(value: unknown): boolean {
  if (!Array.isArray(value)) return false;
  return value.some((item) => item === '*');
}

function isPlaceholderValue(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  return PLACEHOLDERS.has(value.trim().toLowerCase());
}

function isSecretReference(value: string): boolean {
  const trimmed = value.trim();
  if (/^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(trimmed)) return true;
  if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed)) return true;
  return false;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function compareAuditFindings(a: Finding, b: Finding): number {
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const bySeverity = rank[a.severity] - rank[b.severity];
  if (bySeverity !== 0) return bySeverity;
  if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
  return (a.line ?? 0) - (b.line ?? 0);
}

export function isSecretRefObject(value: unknown): boolean {
  const record = asRecord(value);
  if (!record) return false;
  return (
    record.source === 'env' ||
    record.source === 'file' ||
    record.source === 'exec' ||
    record.source === 'store'
  );
}
