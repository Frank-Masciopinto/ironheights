import { extensionOf, isArchiveMagic, isExecutableMagic, zipEncrypted } from '../core/filetype.ts';
import type { Finding, Rule } from '../core/types.ts';
import { createFinding } from './helpers.ts';

const EXEC_EXT = new Set(['exe', 'dll', 'msi', 'dmg', 'pkg', 'so', 'dylib', 'apk']);
const ARCHIVE_EXT = new Set(['zip', 'tar', 'gz', 'tgz', '7z', 'rar', 'bz2', 'xz', 'jar']);

export const bin001: Rule = {
  id: 'IH-BIN-001',
  title: 'Bundled executable or archive',
  category: 'binary',
  severity: 'high',
  priority: 'P0',
  description:
    'Executables and archives shipped inside a skill can hide an installer. Archives are flagged and never extracted.',
  remediation:
    'Remove the binary. Document a package-manager install instead of bundling an executable or archive.',
  appliesTo: ['binary'],
  examples: {
    matches: ['payload.exe', 'setup.zip'],
    nonMatches: ['notes.txt', 'diagram.png'],
  },
  check(file) {
    const ext = extensionOf(file.relativePath);
    const executable = EXEC_EXT.has(ext) || isExecutableMagic(file.head);
    const archive = file.archive || ARCHIVE_EXT.has(ext) || isArchiveMagic(file.head);
    if (!executable && !archive) return [];
    const encrypted = zipEncrypted(file.head);
    const findings: Finding[] = [];
    if (executable) {
      findings.push(
        createFinding(bin001, file, {
          evidence: file.relativePath,
          message: 'Bundled executable or installer detected by extension or magic bytes.',
          confidence: 'high',
        }),
      );
    }
    if (archive) {
      findings.push(
        createFinding(bin001, file, {
          evidence: encrypted ? `${file.relativePath} (encrypted zip flag)` : file.relativePath,
          severity: 'medium',
          message: encrypted
            ? 'Password-protected archive detected. Archives are not extracted.'
            : 'Archive detected. Archives are not extracted, including nested archives.',
          confidence: 'high',
        }),
      );
    }
    return findings;
  },
};
