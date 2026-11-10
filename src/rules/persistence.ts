import type { Finding, Rule } from '../core/types.ts';
import { eachLine } from '../util/text.ts';
import { echoHintOnly, isDescribedRegex } from './described.ts';
import { createFinding, pushUnique } from './helpers.ts';

/**
 * Persistence patterns. Each one looks for a concrete mechanism, not the word alone.
 * crontab - , launchd plist paths, systemd enable or unit writes, rc-file appends,
 * Windows Run keys, schtasks /create, git hook paths, and Startup folder writes.
 */

/**
 * `systemctl start` inside a Terraform user_data or cloud-init example boots a
 * new VM. `systemctl enable` and a start outside that example stay persistence.
 */
function userDataServiceStart(text: string, lineNumber: number): boolean {
  const lines = text.split(/\r?\n/);
  const line = lines[lineNumber - 1] ?? '';
  if (!/\bsystemctl\s+start\b/i.test(line) || /\bsystemctl\s+enable\b/i.test(line)) return false;
  const around = lines.slice(Math.max(0, lineNumber - 40), lineNumber + 3).join('\n');
  return /\b(?:user_data|cloud-init|cloud_config|runcmd:)\b/i.test(around);
}

const PATTERNS: RegExp[] = [
  /\bcrontab\b[^\n]{0,40}(?:-e|-l|-r|\s+[^\s]+\.cron)/i,
  /LaunchAgents\/|LaunchDaemons\/|\/Library\/LaunchAgents/i,
  /\bsystemctl\s+(?:enable|start)\b|\b(?:WantedBy|ExecStart)=/i,
  />>?\s*~?\/?\.?(?:bashrc|zshrc|profile|bash_profile)\b/i,
  /CurrentVersion\\Run/i,
  /\bschtasks\s+\/create\b/i,
  /\.git\/hooks\/(?:pre-commit|post-commit|pre-push)/i,
  /Start Menu\\Programs\\Startup/i,
];

export const persist001: Rule = {
  id: 'IH-PERSIST-001',
  title: 'Persistence mechanism',
  category: 'persistence',
  severity: 'high',
  priority: 'P0',
  description:
    'Scheduled tasks, login hooks, and shell startup files keep code running after the skill is closed.',
  remediation:
    'Remove the persistence step. A skill should not install itself into login or scheduler configuration.',
  appliesTo: ['any'],
  examples: {
    matches: ['crontab -e', 'schtasks /create /tn updater'],
    nonMatches: ['Write the notes to notes/today.md'],
  },
  check(file) {
    const findings: Finding[] = [];
    eachLine(file.text, (line, lineNumber) => {
      if (isDescribedRegex(line)) return;
      if (userDataServiceStart(file.text, lineNumber)) return;
      if (!PATTERNS.some((pattern) => pattern.test(line) && !echoHintOnly(line, pattern))) return;
      pushUnique(
        findings,
        createFinding(persist001, file, {
          line: lineNumber,
          evidence: line,
          message: 'A persistence mechanism is described or invoked.',
          confidence: 'high',
        }),
      );
    });
    return findings;
  },
};
