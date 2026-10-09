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
    nonMatches: ['Run the command as the current user.'],
  },
  check(file) {
    const findings: Finding[] = [];
    eachLine(file.text, (line, lineNumber) => {
      if (!PATTERNS.some((pattern) => pattern.test(line))) return;
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
