import { existsSync, readdirSync } from 'node:fs';
import { posix } from 'node:path';
import { isSkillFileName } from '../core/skill-file.ts';
import type { Finding, Rule } from '../core/types.ts';
import { fencedLineNumbers } from '../util/text.ts';
import { createFinding, pushUnique } from './helpers.ts';

/**
 * IH-REF-001 (0.12.0): SKILL.md tells the agent to run a script or file that is not in the package.
 * The agent then improvises, fetches a replacement, or runs whatever later appears at that path.
 * Suggested by synapseguide, ccbillboardbug, felixnexus and fujikatsu on Moltbook.
 */
const SCRIPT_EXT = 'py|sh|bash|zsh|js|mjs|cjs|ts|mts|rb|pl|php|ps1|lua|go';
/** A relative path to a script file, optionally after a skill-dir placeholder. */
const PATH_TOKEN = new RegExp(
  String.raw`(?:\{baseDir\}|\{skillDir\}|\$\{?(?:SKILL_DIR|BASE_DIR|CLAUDE_SKILL_DIR|SKILL_ROOT)\}?|\.)?/?` +
    String.raw`((?:[\w@+-][\w.@+-]*/)*[\w@+-][\w.@+-]*\.(?:${SCRIPT_EXT}))(?![\w/])`,
  'gi',
);
const RUNNER = new RegExp(
  String.raw`(?:^|[\s;&|(\x60$])(?:sudo\s+)?(?:python3?|node|bun|deno(?:\s+run)?|tsx|ts-node|bash|sh|zsh|ruby|perl|php|pwsh|powershell|source|uv\s+run|npx\s+tsx|\.)\s+(?:-[\w-]+\s+)*["']?$`,
  'i',
);
/** Text that shows the file is created, downloaded or only an example. */
const PLACEHOLDER =
  /(?:^|\/)(?:your|my|example|sample|foo|bar|path\/to)[\w-]*[./]|<|>|\*|\.\.\.|\{(?!baseDir|skillDir)/i;
const OUTSIDE = /^(?:~|\/|\$HOME|%)/;

export interface FileReference {
  path: string;
  line: number;
  runnable: boolean;
  evidence: string;
}

/** Script paths SKILL.md names, with whether the mention is runnable (fenced code or a runner line). */
export function scriptReferences(text: string): FileReference[] {
  const fenced = fencedLineNumbers(text);
  const out: FileReference[] = [];
  text.split(/\r?\n/).forEach((line, index) => {
    const lineNumber = index + 1;
    const inFence = fenced.has(lineNumber);
    if (/^\s*```/.test(line)) return;
    for (const match of line.matchAll(PATH_TOKEN)) {
      const full = match[0];
      const path = match[1] ?? '';
      const start = match.index ?? 0;
      const before = line.slice(0, start);
      const prevChar = before.slice(-1);
      if (/[\w.:/~$%-]/.test(prevChar)) continue; // part of a URL, absolute path or longer token
      if (OUTSIDE.test(full) || PLACEHOLDER.test(path) || /node_modules\//.test(path)) continue;
      if (!path.includes('/')) continue;
      if (/^(?:dist|build|out|target|lib\/node_modules)\//.test(path)) continue; // build output
      if (/\bcd\s+\S+/.test(before) || /\b(?:do not|don't|never|instead of)\b/i.test(before))
        continue; // bare names (`node swap.js`) are usually files the user writes
      if (path.startsWith('@') || /^[^/]*\.[a-z]{2,}\//i.test(path)) continue; // npm scope or host
      const runner = RUNNER.test(before);
      const leading = inFence && /^\s*(?:\$\s+)?(?:\.\/)?$/.test(before);
      if (inFence && !runner && !leading) continue; // comments, cp, gh browse: not a run
      // Prose without a runner: only skill-local script folders count, as a passing mention.
      if (!inFence && !runner && !/^(?:scripts?|bin|tools)\//.test(path)) continue;
      out.push({
        path: path.replace(/^\.\//, ''),
        line: lineNumber,
        runnable: runner || leading,
        evidence: line,
      });
    }
  });
  return out;
}

/** Every file name in the package, for a moved-but-present match. */
function packageNames(root: string): Set<string> {
  const names = new Set<string>();
  const walk = (dir: string, depth: number): void => {
    if (depth > 8 || names.size > 20000) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      if (entry.isDirectory()) walk(posix.join(dir, entry.name), depth + 1);
      else names.add(entry.name);
    }
  };
  walk(root, 0);
  return names;
}

/** The folder comes from a download, archive or clone the same SKILL.md describes. */
function fetchedInText(text: string, path: string): boolean {
  const first = path.split('/')[0] ?? '';
  if (!first) return false;
  return text
    .split(/\r?\n/)
    .some(
      (line) =>
        line.includes(first) &&
        /\b(?:tar|unzip|clone|curl|wget|download|extract|install)\b/i.test(line) &&
        !line.includes(path),
    );
}

function createdInText(text: string, path: string): boolean {
  const name = posix.basename(path).replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    String.raw`(?:>\s*|-o\s+|-O\s+|--output[= ]|tee\s+|touch\s+|cp\s+\S+\s+|mv\s+\S+\s+|cat\s*>\s*|write[^\n]{0,40}|creat\w*[^\n]{0,40}|generat\w*[^\n]{0,40}|save[^\n]{0,30})\S*${name}`,
    'i',
  ).test(text);
}

export const ref001: Rule = {
  id: 'IH-REF-001',
  title: 'Referenced script is not in the package',
  category: 'meta',
  severity: 'medium',
  priority: 'P1',
  description:
    'SKILL.md tells the agent to run a script or file that the skill does not ship. The agent may improvise, fetch a replacement, or run whatever later appears at that path. A command or code block is graded above a passing mention.',
  remediation:
    'Ship the file in the skill, fix the path, or remove the instruction. Agents should stop and ask the user when a referenced script is missing.',
  appliesTo: ['markdown'],
  examples: {
    matches: ['python3 scripts/sync.py --all   (scripts/sync.py not in the skill)'],
    nonMatches: ['python3 scripts/sync.py   (file present)', 'python3 path/to/your_script.py'],
  },
  check(file, ctx) {
    if (!isSkillFileName(file.relativePath) || file.relativePath.includes('/')) return [];
    if (ctx.root.startsWith('(')) return []; // text scan: there is no package to compare against
    const findings: Finding[] = [];
    const seen = new Set<string>();
    let names: Set<string> | undefined;
    for (const ref of scriptReferences(file.text)) {
      if (seen.has(ref.path)) continue;
      const root = ctx.root.replace(/\\/g, '/');
      // `skills/<name>/scripts/x.py` is the installed location of this skill's own scripts/x.py.
      const local = ref.path.replace(/^(?:\.\/)?(?:[\w.-]+\/)*skills\/[\w.@-]+\//, '');
      if ([ref.path, local].some((p) => existsSync(posix.join(root, p)))) continue;
      names ??= packageNames(root);
      if (names.has(posix.basename(ref.path))) continue;
      if (createdInText(file.text, ref.path) || fetchedInText(file.text, ref.path)) continue;
      seen.add(ref.path);
      pushUnique(
        findings,
        createFinding(ref001, file, {
          line: ref.line,
          evidence: ref.evidence,
          severity: ref.runnable ? 'medium' : 'low',
          confidence: ref.runnable ? 'medium' : 'low',
          message: ref.runnable
            ? `SKILL.md runs ${ref.path}, but the skill does not ship it.`
            : `SKILL.md mentions ${ref.path}, but the skill does not ship it.`,
        }),
      );
    }
    return findings;
  },
};
