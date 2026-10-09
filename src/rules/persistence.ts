import type { Finding, Rule } from '../core/types.ts';
import { eachLine } from '../util/text.ts';
import { createFinding, pushUnique } from './helpers.ts';

/**
 * Persistence patterns. Each one looks for a concrete mechanism, not the word alone.
 * crontab - , launchd plist paths, systemd enable or unit writes, rc-file appends,
 * Windows Run keys, schtasks /create, git hook paths, and Startup folder writes.
 */

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
      if (!PATTERNS.some((pattern) => pattern.test(line))) return;
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
