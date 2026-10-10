import { posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import { badHost, extractUrls, hostAllowed, hostOf } from '../rules/network.ts';
import { clip } from '../util/text.ts';
import { redactSecrets } from './redact.ts';
import type { ResolvedGuardPolicy, ToolCall, Violation } from './types.ts';

/**
 * Runtime signals aligned with the scanner rules, applied to a tool call
 * instead of a file. Quantifiers are bounded. IH-EXEC-001's pipe and
 * substitution shapes live here as IH-GUARD-EXEC; a download saved to a
 * file and executed later, in a separate tool call, is not correlated.
 */

const READ_TOOLS = new Set(['read']);
const WRITE_TOOLS = new Set(['write', 'edit', 'apply_patch']);
const EXEC_TOOLS = new Set(['exec', 'bash', 'shell', 'code_execution']);
const NET_TOOLS = new Set(['web_fetch', 'browser', 'web_search']);

const PATH_KEYS = ['path', 'file_path', 'filepath', 'filePath', 'filename', 'target'];
const URL_KEYS = ['url', 'uri', 'href', 'endpoint', 'targetUrl', 'target_url'];
const COMMAND_KEYS = ['command', 'cmd', 'script', 'code', 'source', 'javascript', 'typescript'];
const PATCH_KEYS = ['patch', 'content', 'contents', 'text', 'new_string', 'newText', 'diff'];

const IDENTITY_FILES = new Set([
  'AGENTS.md',
  'SOUL.md',
  'IDENTITY.md',
  'USER.md',
  'TOOLS.md',
  'BOOTSTRAP.md',
  'MEMORY.md',
]);

const CREDENTIAL_DIR = /(?:^|\/)\.(?:ssh|aws|gnupg|azure)(?:\/|$)/i;
const KEY_BASENAME = /^id_(?:rsa|dsa|ecdsa|ed25519)$/i;
const ENV_BASENAME = /^\.env(?:\.(?:local|production|development|prod|dev))?$/i;
const PRIVATE_KEY_FILE = /(?:^|\/)(?:private|secret|wallet)[^/]{0,80}\.(?:pem|key)$/i;

const PIPE_TO_INTERPRETER =
  /\b(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]{0,400}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|iex|powershell|pwsh|Invoke-Expression)\b/i;
const SUBSTITUTION =
  /\b(?:sh|bash|zsh|python3?|node|powershell|pwsh)\b[^\n]{0,80}\$\([^)\n]{0,200}\b(?:curl|wget)\b/i;
const PROCESS_SUBST = /\b(?:bash|sh|zsh)\b[^\n]{0,40}<\(\s*(?:curl|wget)\b/i;
const BASE64_PIPE =
  /\bbase64\b[^\n]{0,80}(?:-d|--decode)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|iex|powershell|pwsh)\b/i;
const SAVED_DOWNLOAD =
  /\b(?:curl|wget|iwr)\b[^|\n;]{0,300}\s(?:-o|-O|--output)\s+('[^']{1,200}'|"[^"]{1,200}"|\S{1,200})[^|\n;]{0,200}(?:&&|;)\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node)\b[^|\n]{0,80}\1/i;

const REDIRECT =
  /(?:>>?)\s*(?:'([^'\n]{1,300})'|"([^"\n]{1,300})"|((?:~|\/)[^\s;|&]{1,300})|([A-Za-z]:\/[^\s;|&]{1,300}))/g;
const TEE =
  /\btee\b(?:\s+-[A-Za-z]{1,8}){0,4}\s+(?:'([^'\n]{1,300})'|"([^"\n]{1,300})"|((?:~|\/)[^\s;|&]{1,300}))/g;
const PATCH_FILE = /^\*\*\* (?:Update|Add|Delete) File: ([^\n]{1,300})$/gm;

const MAX_TEXT = 8000;
const MAX_VIOLATIONS = 16;

export function collectViolations(call: ToolCall, policy: ResolvedGuardPolicy): Violation[] {
  const family = toolFamily(call);
  const violations: Violation[] = [];
  const paramPaths = paramAndDerivedPaths(call, policy);
  const command = commandText(call);

  switch (family) {
    case 'read':
      for (const path of paramPaths) {
        if (isCredentialPath(path)) pushViolation(violations, credentialViolation('read', path));
      }
      break;
    case 'write':
      for (const path of [...paramPaths, ...patchPaths(call, policy)]) {
        addWrite(violations, path, policy);
      }
      break;
    case 'exec':
      noteExec(violations, paramPaths, command, policy);
      break;
    case 'net':
      break;
    case 'other':
      for (const path of paramPaths) {
        if (isCredentialPath(path)) pushViolation(violations, credentialViolation('use', path));
        if (isProtectedWrite(path, policy)) addProtected(violations, path);
      }
      if (command) noteExec(violations, [], command, policy);
      break;
    default: {
      const _never: never = family;
      return _never;
    }
  }
  const urls = destinationUrls(call, family, command);
  const allow = domainsFor(call, policy);
  const seenHosts = new Set<string>();
  for (const url of urls) {
    if (seenHosts.has(url.host)) continue;
    seenHosts.add(url.host);
    if (hostAllowed(url.host, allow)) continue;
    const raised = badHost(url.host, url.raw);
    pushViolation(violations, {
      ruleId: 'IH-GUARD-NET',
      severity: raised ? 'high' : 'medium',
      message: raised
        ? `outbound request to high-risk host ${url.host}`
        : `outbound request to undeclared host ${url.host}`,
      evidence: show(url.raw),
      host: url.host,
    });
  }
  return violations.slice(0, MAX_VIOLATIONS);
}

function noteExec(
  violations: Violation[],
  paramPaths: string[],
  command: string,
  policy: ResolvedGuardPolicy,
): void {
  for (const path of paramPaths) {
    if (isCredentialPath(path)) pushViolation(violations, credentialViolation('use', path));
    if (isProtectedWrite(path, policy)) addProtected(violations, path);
  }
  for (const path of commandPaths(command, policy)) {
    if (isCredentialPath(path)) pushViolation(violations, credentialViolation('use', path));
  }
  for (const path of redirectPaths(command, policy)) addWrite(violations, path, policy);
  const execHit = command ? downloadExec(command) : undefined;
  if (!execHit) return;
  pushViolation(violations, {
    ruleId: 'IH-GUARD-EXEC',
    severity: 'critical',
    message: 'command downloads remote content and passes it to an interpreter',
    evidence: show(execHit),
  });
}

function addWrite(violations: Violation[], path: string, policy: ResolvedGuardPolicy): void {
  if (isCredentialPath(path)) pushViolation(violations, credentialViolation('write', path));
  if (isProtectedWrite(path, policy)) addProtected(violations, path);
}

function addProtected(violations: Violation[], path: string): void {
  pushViolation(violations, {
    ruleId: 'IH-GUARD-WRITE',
    severity: 'high',
    message: `write to an agent identity, memory, or skill path (${show(path)})`,
    evidence: show(path),
    path,
  });
}

function toolFamily(call: ToolCall): 'read' | 'write' | 'exec' | 'net' | 'other' {
  if (call.toolKind === 'code_mode_exec') return 'exec';
  const name = call.toolName;
  if (READ_TOOLS.has(name)) return 'read';
  if (WRITE_TOOLS.has(name)) return 'write';
  if (EXEC_TOOLS.has(name)) return 'exec';
  if (name === 'process' && commandText(call)) return 'exec';
  if (NET_TOOLS.has(name)) return 'net';
  return 'other';
}

function credentialViolation(kind: 'read' | 'write' | 'use', path: string): Violation {
  const verb =
    kind === 'read'
      ? 'read of a credential path'
      : kind === 'write'
        ? 'write to a credential path'
        : 'command uses a credential path';
  return {
    ruleId: 'IH-GUARD-CRED',
    severity: 'high',
    message: `${verb} (${show(path)})`,
    evidence: show(path),
    path,
  };
}

export function isCredentialPath(path: string): boolean {
  const norm = slash(path);
  if (CREDENTIAL_DIR.test(norm)) return true;
  const base = posix.basename(norm);
  if (KEY_BASENAME.test(base)) return true;
  if (ENV_BASENAME.test(base) && !/\.example$/i.test(base) && base !== '.env.example') return true;
  if (/^wallet\.dat$/i.test(base) || /^utc--/i.test(base)) return true;
  if (/(?:^|\/)\.electrum(?:\/|$)/i.test(norm)) return true;
  if (PRIVATE_KEY_FILE.test(norm)) return true;
  if (/(?:^|\/)\.bash_history$/i.test(norm) || /(?:^|\/)\.zsh_history$/i.test(norm)) return true;
  if (/(?:^|\/)auth-profiles\.json$/i.test(norm)) return true;
  if (/(?:^|\/)\.openclaw\/openclaw\.json$/i.test(norm)) return true;
  if (/(?:^|\/)\.openclaw\/credentials(?:\/|$)/i.test(norm)) return true;
  if (/(?:^|\/)(?:Login Data|Cookies|cookies\.sqlite)$/i.test(norm)) return true;
  return false;
}

export function isProtectedWrite(path: string, policy: ResolvedGuardPolicy): boolean {
  const norm = slash(path);
  for (const root of policy.protectedPaths) {
    if (root && isInside(norm, slash(root))) return true;
  }
  for (const dir of policy.skillDirs) {
    if (dir && isInside(norm, slash(dir))) return true;
  }
  const base = posix.basename(norm);
  if (IDENTITY_FILES.has(base)) {
    if (policy.workspaceDir && isInside(norm, slash(policy.workspaceDir))) return true;
    if (policy.stateDir && isInside(norm, slash(policy.stateDir))) return true;
  }
  if (
    policy.workspaceDir &&
    isInside(norm, slash(posix.join(slash(policy.workspaceDir), 'memory')))
  ) {
    return true;
  }
  return false;
}

function paramAndDerivedPaths(call: ToolCall, policy: ResolvedGuardPolicy): string[] {
  return uniquePaths([...stringValues(call.params, PATH_KEYS), ...call.derivedPaths], policy);
}

function patchPaths(call: ToolCall, policy: ResolvedGuardPolicy): string[] {
  const raw: string[] = [];
  for (const text of stringValues(call.params, PATCH_KEYS)) {
    const slice = text.slice(0, MAX_TEXT);
    PATCH_FILE.lastIndex = 0;
    for (const match of slice.matchAll(PATCH_FILE)) {
      const path = match[1]?.trim();
      if (path) raw.push(path);
    }
    PATCH_FILE.lastIndex = 0;
  }
  return uniquePaths(raw, policy);
}

function commandPaths(command: string, policy: ResolvedGuardPolicy): string[] {
  if (!command) return [];
  const raw: string[] = [];
  for (const match of command.matchAll(/(?:^|[\s"'`=])((?:~\/|\/)[A-Za-z0-9._~+/-]{1,240})/g)) {
    const path = match[1];
    if (path && !path.startsWith('//')) raw.push(path);
  }
  return uniquePaths(raw, policy);
}

function redirectPaths(command: string, policy: ResolvedGuardPolicy): string[] {
  if (!command) return [];
  const raw: string[] = [];
  REDIRECT.lastIndex = 0;
  for (const match of command.matchAll(REDIRECT)) {
    const path = match[1] ?? match[2] ?? match[3] ?? match[4];
    if (path) raw.push(path);
  }
  REDIRECT.lastIndex = 0;
  TEE.lastIndex = 0;
  for (const match of command.matchAll(TEE)) {
    const path = match[1] ?? match[2] ?? match[3];
    if (path) raw.push(path);
  }
  TEE.lastIndex = 0;
  return uniquePaths(raw, policy);
}

function uniquePaths(raw: string[], policy: ResolvedGuardPolicy): string[] {
  const found: string[] = [];
  for (const value of raw) {
    const resolved = resolveToolPath(value, policy);
    if (!resolved || found.includes(resolved)) continue;
    found.push(resolved);
    if (found.length >= 32) break;
  }
  return found;
}

export function resolveToolPath(raw: string, policy: ResolvedGuardPolicy): string {
  let value = slash(raw.trim());
  if (value.length === 0 || value.length > 4096) return '';
  if (value.startsWith('file://')) {
    try {
      value = slash(fileURLToPath(value));
    } catch {
      return '';
    }
  }
  if (value === '~') value = slash(policy.homeDir);
  else if (value.startsWith('~/'))
    value = `${slash(policy.homeDir).replace(/\/$/, '')}/${value.slice(2)}`;
  else if (!value.startsWith('/') && !/^[A-Za-z]:\//.test(value) && policy.workspaceDir) {
    value = `${slash(policy.workspaceDir).replace(/\/$/, '')}/${value.replace(/^\.\//, '')}`;
  }
  const normalized = posix.normalize(value);
  if (normalized === '.' || normalized.length === 0) return '';
  return normalized;
}

function commandText(call: ToolCall): string {
  const parts = stringValues(call.params, COMMAND_KEYS);
  if (parts.length === 0) return '';
  return parts.join('\n').slice(0, MAX_TEXT);
}

function destinationUrls(
  call: ToolCall,
  family: 'read' | 'write' | 'exec' | 'net' | 'other',
  command: string,
): Array<{ raw: string; host: string }> {
  const blobs: string[] = [];
  if (family === 'exec' || family === 'other' || family === 'net') {
    if (command) blobs.push(command);
  }
  if (family === 'net' || family === 'other') {
    blobs.push(...stringValues(call.params, URL_KEYS));
    if (call.toolName === 'web_search') {
      blobs.push(...stringValues(call.params, ['query', 'q']));
    }
  }
  const found: Array<{ raw: string; host: string }> = [];
  for (const blob of blobs) {
    const slice = blob.slice(0, MAX_TEXT);
    for (const url of extractUrls(slice)) found.push(url);
    if (!slice.includes('://')) continue;
    const direct = hostOf(slice.trim());
    if (direct && !found.some((item) => item.raw === slice.trim())) {
      found.push({ raw: slice.trim(), host: direct });
    }
  }
  return found;
}

function downloadExec(command: string): string | undefined {
  const patterns = [PIPE_TO_INTERPRETER, SUBSTITUTION, PROCESS_SUBST, BASE64_PIPE, SAVED_DOWNLOAD];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    const match = pattern.exec(command);
    pattern.lastIndex = 0;
    const text = match?.[0];
    if (text) return text;
  }
  return undefined;
}

function domainsFor(call: ToolCall, policy: ResolvedGuardPolicy): string[] {
  if (!call.skill) return policy.globalAllowDomains;
  return [
    ...policy.globalAllowDomains,
    ...(policy.skills[call.skill]?.allowDomains ?? []),
    ...(policy.skillDeclaredDomains[call.skill] ?? []),
  ];
}

function stringValues(params: Record<string, unknown>, keys: readonly string[]): string[] {
  const found: string[] = [];
  for (const key of keys) {
    const value = params[key];
    if (typeof value === 'string' && value.length > 0) found.push(value);
    if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string' && item.length > 0) found.push(item);
      }
    }
  }
  return found;
}

function pushViolation(violations: Violation[], violation: Violation): void {
  const exists = violations.some(
    (item) =>
      item.ruleId === violation.ruleId &&
      item.path === violation.path &&
      item.host === violation.host &&
      item.message === violation.message,
  );
  if (!exists) violations.push(violation);
}

function isInside(child: string, parent: string): boolean {
  const root = parent.replace(/\/+$/, '');
  if (!root || root === '.') return false;
  return child === root || child.startsWith(`${root}/`);
}

function slash(value: string): string {
  return value.replace(/\\/g, '/');
}

function show(value: string): string {
  return clip(redactSecrets(value), 160);
}
