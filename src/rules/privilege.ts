import type { Finding, Rule } from '../core/types.ts';
import { eachLine } from '../util/text.ts';
import { createFinding, pushUnique } from './helpers.ts';

const PATTERNS: RegExp[] = [
  /\bsudo\b/,
  /\bchmod\s+(?:-R\s+)?(?:777|666|755|\+x|a\+x|u\+x)\b/,
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
      if (!PATTERNS.some((pattern) => pattern.test(line))) return;
      if (negatedSudoOnly(line)) return;
      pushUnique(
        findings,
        createFinding(priv001, file, {
          line: lineNumber,
          evidence: line,
          message: 'The file elevates privileges or disables an OS protection.',
          confidence: 'high',
        }),
      );
    });
    return findings;
  },
};
