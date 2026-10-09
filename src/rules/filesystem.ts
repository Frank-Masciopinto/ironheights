import type { Finding, Rule } from '../core/types.ts';
import { eachLine } from '../util/text.ts';
import { createFinding, pushUnique } from './helpers.ts';

const TRAVERSAL = /(?:\.\.\/|\.\.\\){1,8}/;

export const fs001: Rule = {
  id: 'IH-FS-001',
  title: 'Suspicious filesystem access',
  category: 'filesystem',
  severity: 'medium',
  priority: 'P1',
  description:
    'Symlinks that leave the skill, path traversal, and hidden files can read or hide data outside the skill.',
  remediation:
    'Keep every file inside the skill directory. Do not use symlinks that point elsewhere or dotfiles to hide content.',
  appliesTo: ['any'],
  examples: {
    matches: ['../../etc/passwd', 'ln -s /etc/passwd stolen'],
    nonMatches: ['./notes/today.md'],
  },
  check(file) {
    const findings: Finding[] = [];
    if (file.symlinkOutside || file.symlinkLoop) {
      findings.push(
        createFinding(fs001, file, {
          evidence: file.symlinkTarget ?? file.relativePath,
          message: file.symlinkLoop
            ? 'Symlink loop detected. The link was not followed.'
            : 'Symlink points outside the skill directory and was not followed.',
          confidence: 'high',
        }),
      );
    }
    if (file.relativePath.split('/').includes('..')) {
      findings.push(
        createFinding(fs001, file, {
          evidence: file.relativePath,
          message: 'Relative path contains a traversal segment.',
          confidence: 'high',
        }),
      );
    }
    if (file.hidden) {
      findings.push(
        createFinding(fs001, file, {
          evidence: file.relativePath,
          severity: 'low',
          message: 'Hidden dotfile inside the skill.',
          confidence: 'medium',
        }),
      );
    }
    eachLine(file.text, (line, lineNumber) => {
      if (!TRAVERSAL.test(line) && !/\bln\s+-s\s+\//.test(line)) return;
      pushUnique(
        findings,
        createFinding(fs001, file, {
          line: lineNumber,
          evidence: line,
          message: 'Path traversal or an absolute symlink is described in the file.',
          confidence: 'medium',
        }),
      );
    });
    return findings;
  },
};
