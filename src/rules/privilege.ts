import type { Finding, Rule } from '../core/types.ts';
import { eachLine } from '../util/text.ts';
import { echoHintOnly, isDescribedRegex } from './described.ts';
import { createFinding, pushUnique } from './helpers.ts';

const EXEC_PATTERN = /\bchmod\s+(?:-R\s+)?(?:777|666|755|\+x|a\+x|u\+x)\b/;
/** Setting the execute bit on a script is routine; world-writable modes stay high. */
const EXEC_BIT = /\bchmod\s+(?:755|\+x|a\+x|u\+x)\b/;
const PATTERNS: RegExp[] = [
  /\bsudo\b/,
  EXEC_PATTERN,
  /\bxattr\s+(?:-d|-c)\b[^\n]{0,80}quarantine/i,
  /\bspctl\s+--master-disable\b/,
  /\b(?:disable|turn off)\b[^\n]{0,40}\b(?:gatekeeper|antivirus|firewall|real-time protection)\b/i,
  /\bufw\s+disable\b/i,
  /\biptables\s+-F\b/,
  /DisableRealtimeMonitoring/i,
];

/**
 * Advice against elevation ("never use sudo", "do not run this with sudo", "no sudo needed").
 * Only the sudo pattern is excused, and only when every sudo on the line is negated and the line
 * carries no other privilege pattern.
 */
const NEGATED_SUDO =
  /\b(?:never|don'?t|do\s+not|doesn'?t|does\s+not|won'?t|will\s+not|avoid(?:ing)?|without|no\s+need\s+(?:for|to)|not\s+require|no)\b(?:\s+(?:use|using|run|running|need|needs|require|requires|prefix|with|as|any|ever|be|it|this|the|command|commands|script|install|installer)){0,4}\s+(?:with\s+)?[`'"(]?sudo\b|\bsudo\b[`'")]?\s+(?:is\s+)?(?:not\s+(?:needed|required)|never\s+needed|isn'?t\s+(?:needed|required)|is\s+unnecessary)/gi;

/** `sudo rm` or `chmod 777` / `666`. Package installs are not this. */
export function isDestructivePrivilegeLine(line: string): boolean {
  return /\bsudo\s+rm\b|\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b|\bchmod\s+(?:-R\s+)?(?:777|666)\b/.test(
    line,
  );
}

/** The line forbids the command, or only mentions it inside a sentence. */
function destructiveAside(line: string): 'forbid' | 'mention' | undefined {
  if (!isDestructivePrivilegeLine(line)) return undefined;
  if (line.includes('❌') || line.includes('🚫')) return 'forbid';
  const at = line.search(/\b(?:sudo|chmod|rm)\b/i);
  const before = at >= 0 ? line.slice(Math.max(0, at - 40), at) : '';
  if (!/[.!?]\s/.test(before) && /\b(?:never|do not|don't|must not)\b/i.test(before))
    return 'forbid';
  if (/`[^`\n]*(?:sudo\s+rm|chmod\s+(?:-R\s+)?(?:777|666))[^`\n]*`/i.test(line)) {
    const outside = line.replace(/`[^`\n]*`/g, ' ');
    if (/[A-Za-z]{3,}/.test(outside)) return 'mention';
  }
  return undefined;
}

/** `sudo apt`, `sudo tee`. A bare mention (`become_method: sudo`) is not a command. */
function sudoMentionOnly(line: string): boolean {
  if (!/\bsudo\b/i.test(line)) return false;
  if (PATTERNS.some((pattern) => pattern !== PATTERNS[0] && pattern.test(line))) return false;
  if (/\bsudo\s+(?:-[A-Za-z]+\s+)*[A-Za-z0-9./][\w./-]*/.test(line)) return false;
  if (/sudoers|NOPASSWD/i.test(line)) return false;
  return true;
}

export function negatedSudoOnly(line: string): boolean {
  if (!/\bsudo\b/.test(line)) return false;
  const rest = line.replace(NEGATED_SUDO, ' ');
  if (rest === line) return false;
  return !PATTERNS.some((pattern) => pattern.test(rest));
}

export const priv001: Rule = {
  id: 'IH-PRIV-001',
  title: 'Privilege or OS protection bypass',
  category: 'privilege',
  severity: 'high',
  priority: 'P1',
  description:
    'sudo, broad chmod, and commands that turn off Gatekeeper or firewall protections weaken the host.',
  remediation:
    'Do not elevate privileges or remove OS protections. Ask the user to install software through the normal path.',
  appliesTo: ['any'],
  examples: {
    matches: ['sudo bash install.sh', 'xattr -d com.apple.quarantine ./tool'],
    nonMatches: ['Run the command as the current user.', 'Never use sudo with this installer.'],
  },
  check(file) {
    const findings: Finding[] = [];
    eachLine(file.text, (line, lineNumber) => {
      if (isDescribedRegex(line)) return;
      if (!PATTERNS.some((pattern) => pattern.test(line) && !echoHintOnly(line, pattern))) return;
      if (negatedSudoOnly(line)) return;
      const aside = destructiveAside(line);
      const onlyExecBit =
        EXEC_BIT.test(line) &&
        !PATTERNS.some((pattern) => pattern !== EXEC_PATTERN && pattern.test(line));
      const mention = sudoMentionOnly(line);
      pushUnique(
        findings,
        createFinding(priv001, file, {
          line: lineNumber,
          evidence: line,
          message:
            aside === 'forbid'
              ? 'The line forbids a destructive command. Running it is still a finding.'
              : aside === 'mention'
                ? 'The line mentions a destructive command inside a sentence. A fenced run of the same command stays high.'
                : mention
                  ? 'The line names sudo and does not run it. A sudo command and a sudoers write stay at full severity.'
                  : onlyExecBit
                    ? 'The file marks a file executable (chmod +x / 755). Check what that file runs.'
                    : 'The file elevates privileges or disables an OS protection.',
          confidence: aside || mention || onlyExecBit ? 'medium' : 'high',
          ...(aside === 'forbid' ? { severity: 'info' as const, scoreExempt: true } : {}),
          ...(aside === 'mention' || mention
            ? { severity: 'low' as const, scoreExempt: true }
            : {}),
          ...(onlyExecBit && !mention && !aside ? { severity: 'medium' as const } : {}),
        }),
      );
    });
    return findings;
  },
};
