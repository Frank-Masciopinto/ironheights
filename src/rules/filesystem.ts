import { posix } from 'node:path';
import type { Finding, Rule } from '../core/types.ts';
import { eachLine } from '../util/text.ts';
import { createFinding, pushUnique } from './helpers.ts';

const TRAVERSAL = /(?:\.\.\/|\.\.\\){1,8}/;
/** URLs and API route paths (`GET /api/v1/posts/uuid.../comments`) are not file paths. */
const URL_TOKEN = /\b[a-z][a-z0-9+.-]*:\/\/\S+/gi;
const ROUTE_TOKEN =
  /(?:\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)?(?<![\w.])\/(?:api|v\d+)(?:\/[^\s"'`)]*)?/g;
/** An ellipsis placeholder such as `uuid.../` is not a parent-directory segment. */
const ELLIPSIS = /\.{3,}/g;

export function stripNonPathTokens(line: string): string {
  return line.replace(URL_TOKEN, ' ').replace(ROUTE_TOKEN, ' ').replace(ELLIPSIS, ' ');
}

const READ_ONLY_WORDS =
  /\b(?:read[- ]only|readonly|reads?|reading|refer(?:s|ence)?|see|cat|less|open(?:s)?|loads?)\b/i;
const WRITE_OR_WALK =
  /\b(?:write|writes|writing|overwrite|append|delete|remove|rm|mv|cp|chmod|chown|walk|recurs\w*|find|glob|rsync|tar|zip|upload|send|post|curl|wget|ln|mkdir|touch|tee|sed\s+-i)\b|>|\*|\s-R\b|\s-r\b/i;
/** `../` at most twice, then a named file with an extension and no wildcard. */
const NAMED_NEARBY_FILE =
  /(?<![\w/.~])(?:\.\.\/){1,2}(?:[\w@+-]+\/){0,3}[\w@+-]+\.[a-z0-9]{1,8}\b/gi;
/** Paths a "read-only" label must never excuse. */
const SENSITIVE_TARGET =
  /\b(?:etc|ssh|\.ssh|aws|\.aws|gnupg|\.env|env|passwd|shadow|id_rsa|id_ed25519|credentials?|secrets?|tokens?|keychain|cookies?|wallet|\.git|openclaw\.json|config\.json)\b/i;

/**
 * A line that names one nearby file (at most two `../`) and says it is only read, with no write,
 * delete, copy, recursive walk, wildcard or network verb, and no sensitive target.
 * Reported as info so it is visible but does not change the verdict or grade.
 */
export function declaredReadOnlyReference(line: string): boolean {
  if (!READ_ONLY_WORDS.test(line) || WRITE_OR_WALK.test(line) || SENSITIVE_TARGET.test(line)) {
    return false;
  }
  const named = line.match(NAMED_NEARBY_FILE) ?? [];
  if (named.length !== 1) return false;
  const rest = line.replace(NAMED_NEARBY_FILE, ' ');
  return !TRAVERSAL.test(rest);
}

/** Each `../` path token on a line (after URLs and routes are stripped). */
const TRAVERSAL_TOKEN = /(?<![\w.~])(?:\.\.\/)+[^\s"'`)<>|;,]*/g;

/**
 * True when every `../` path on the line resolves to a place inside the skill folder, judged from
 * the folder of the file that names it (`scripts/run.sh` naming `../references/api.md`). Backslash
 * traversal, a bare `..` that climbs out, or any token that leaves the root keeps the finding.
 */
export function staysInsideSkill(line: string, relativePath: string): boolean {
  if (/\.\.\\/.test(line)) return false;
  const tokens = line.match(TRAVERSAL_TOKEN) ?? [];
  if (tokens.length === 0) return false;
  const rest = line.replace(TRAVERSAL_TOKEN, ' ');
  if (TRAVERSAL.test(rest)) return false;
  const dir = posix.dirname(relativePath.replace(/\\/g, '/'));
  return tokens.every((token) => {
    const resolved = posix.normalize(posix.join(dir, token));
    return resolved !== '..' && !resolved.startsWith('../') && !posix.isAbsolute(resolved);
  });
}

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
      const scrubbed = stripNonPathTokens(line);
      const symlink = /\bln\s+-s\s+\//.test(line);
      if (!TRAVERSAL.test(scrubbed) && !symlink) return;
      if (!symlink && staysInsideSkill(scrubbed, file.relativePath)) return;
      const readOnly = !symlink && declaredReadOnlyReference(scrubbed);
      pushUnique(
        findings,
        createFinding(fs001, file, {
          line: lineNumber,
          evidence: line,
          ...(readOnly ? { severity: 'info' as const } : {}),
          message: readOnly
            ? 'Declared read-only reference to one named file outside the skill folder.'
            : 'Path traversal or an absolute symlink is described in the file.',
          confidence: readOnly ? 'low' : 'medium',
        }),
      );
    });
    return findings;
  },
};
