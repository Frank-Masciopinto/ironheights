import { BAD_HOST_MARKERS, BAD_HOST_SUFFIXES } from '../core/domains.ts';
import type { Finding, Rule, ScannedFile, Severity } from '../core/types.ts';
import { eachLine } from '../util/text.ts';
import { createFinding, pushUnique } from './helpers.ts';

const URL_RE = /\b(?:https?:\/\/|\/\/)[^\s<>"'`)]{1,500}/gi;

export const net001: Rule = {
  id: 'IH-NET-001',
  title: 'Undeclared network destination',
  category: 'network',
  severity: 'medium',
  priority: 'P0',
  description:
    'A skill that contacts a host outside the allowlist can send data somewhere the user did not expect.',
  remediation:
    'Declare the host in allowDomains, or remove the request. Prefer the official API host.',
  appliesTo: ['any'],
  examples: {
    matches: ['https://evil.invalid/collect', 'https://webhook.site.invalid/hook'],
    nonMatches: ['https://example.com/docs', 'https://api.github.com/repos'],
  },
  check: checkNet001,
};

export const net002: Rule = {
  id: 'IH-NET-002',
  title: 'Possible exfiltration',
  category: 'network',
  severity: 'high',
  priority: 'P1',
  description:
    'A sensitive read and an outbound request in the same file can move credentials off the machine.',
  remediation:
    'Split credential access from network calls, and do not send secrets to a remote host.',
  appliesTo: ['any'],
  examples: {
    matches: ['read ~/.ssh/id_rsa then curl https://evil.invalid'],
    nonMatches: ['curl https://example.com/health', 'read the local notes file'],
  },
  check: checkNet002,
};

export interface ExtractedUrl {
  raw: string;
  host: string;
  line: number;
}

export function extractUrls(text: string): ExtractedUrl[] {
  const found: ExtractedUrl[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = (lines[i] ?? '').slice(0, 4000);
    for (const match of line.matchAll(URL_RE)) {
      const raw = match[0] ?? '';
      const host = hostOf(raw);
      if (host) found.push({ raw, host, line: i + 1 });
    }
  }
  return found;
}

export function hostOf(raw: string): string | undefined {
  const trimmed = raw.replace(/^\/\//, 'http://');
  try {
    const url = new URL(trimmed);
    return url.hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

export function hostAllowed(host: string, allow: readonly string[]): boolean {
  const normalized = host.toLowerCase().replace(/\.$/, '');
  return allow.some((entry) => {
    const candidate = entry.toLowerCase();
    return normalized === candidate || normalized.endsWith(`.${candidate}`);
  });
}

export function badHost(host: string, raw: string): boolean {
  if (isIp(host)) return true;
  const normalized = host.toLowerCase();
  if (
    BAD_HOST_SUFFIXES.some((suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`))
  ) {
    return true;
  }
  if (
    normalized.endsWith('.invalid') &&
    BAD_HOST_MARKERS.some((marker) => normalized.includes(marker))
  ) {
    return true;
  }
  const lower = raw.toLowerCase();
  if (lower.includes('discord.com/api/webhooks') || lower.includes('discordapp.com/api/webhooks'))
    return true;
  if (normalized === 'api.telegram.org' && lower.includes('/bot')) return true;
  return false;
}

function checkNet001(file: ScannedFile, ctx: { config: { allowDomains: string[] } }): Finding[] {
  const findings: Finding[] = [];
  for (const url of extractUrls(file.text)) {
    if (hostAllowed(url.host, ctx.config.allowDomains)) continue;
    const raised = badHost(url.host, url.raw);
    const severity: Severity = raised ? 'high' : 'medium';
    pushUnique(
      findings,
      createFinding(net001, file, {
        line: url.line,
        evidence: url.raw,
        severity,
        confidence: raised ? 'high' : 'medium',
        message: raised
          ? `Destination ${url.host} is a raw address or a known high-risk host.`
          : `Destination ${url.host} is not in the allowlist.`,
      }),
    );
  }
  return findings;
}

const OUTBOUND =
  /\b(?:curl|wget|iwr|Invoke-WebRequest|fetch\s*\(|axios\.|http\.request|https\.request|XMLHttpRequest|net\.connect)\b/i;
const ENV_DUMP = /\b(?:printenv|process\.env|os\.environ|env\s*\|)\b/;

function checkNet002(file: ScannedFile): Finding[] {
  const sensitive = hasSensitiveMarker(file.text) || ENV_DUMP.test(file.text);
  const outbound = OUTBOUND.test(file.text) || extractUrls(file.text).length > 0;
  if (!sensitive || !outbound) return [];
  return [
    createFinding(net002, file, {
      evidence: file.text.slice(0, 180),
      message: 'The same file reads sensitive data and makes an outbound request.',
      confidence: 'medium',
    }),
  ];
}

export function hasSensitiveMarker(text: string): boolean {
  return SENSITIVE_PATH.test(text);
}

const SENSITIVE_PATH =
  /(?:~\/\.ssh\/|\/\.ssh\/|id_rsa|id_ed25519|\.aws\/credentials|\.aws\/config|application_default_credentials|\.azure\/|\.env\b|Login Data|Cookies|cookies\.sqlite|login\.keychain|\.bash_history|\.zsh_history|openclaw\.json|credentials\/whatsapp|auth-profiles\.json|\.electrum|wallet\.dat|seed phrase)/i;

function isIp(host: string): boolean {
  if (host.includes(':')) return true;
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

export function linesMentionOutbound(text: string): boolean {
  let hit = false;
  eachLine(text, (line) => {
    if (OUTBOUND.test(line)) hit = true;
  });
  return hit;
}
