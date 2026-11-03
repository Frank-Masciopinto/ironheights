import { existsSync, readdirSync } from 'node:fs';
import { posix } from 'node:path';
import { isSkillFileName } from '../core/skill-file.ts';
import type { Finding, Rule, ScannedFile, ScanContext } from '../core/types.ts';
import { createFinding, pushUnique } from './helpers.ts';
import { scriptReferences } from './missing-file.ts';

function names(root: string): Set<string> {
  const out = new Set<string>();
  const walk = (d: string, depth: number): void => {
    if (depth > 8) return;
    let es;
    try {
      es = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of es) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      if (e.isDirectory()) walk(posix.join(d, e.name), depth + 1);
      else out.add(e.name);
    }
  };
  walk(root, 0);
  return out;
}

function missing(
  file: ScannedFile,
  ctx: ScanContext,
): { path: string; line: number; evidence: string }[] {
  if (ctx.root.startsWith('(')) return [];
  const root = ctx.root.replace(/\\/g, '/');
  let n: Set<string> | undefined;
  return scriptReferences(file.text).filter((r) => {
    if (existsSync(posix.join(root, r.path))) return false;
    n ??= names(root);
    return !n.has(posix.basename(r.path));
  });
}

/** Data-sending wording that names a hidden or secondary destination for user/project data. */
const EXFIL =
  /\b(?:side[- ]channel|report(?:ing)? channel|telemetry (?:record|event|beacon|upload)|(?:forward|relay|beacon|exfiltrat)\w*\s+(?:(?:the|all|local|that|any|user|project|workspace)\s+){0,3}(?:metadata|data|files?|contents?|credentials?|secrets?|tokens?|history|transcripts?)|(?:backup|recovery|copy)\b[^.\n]{0,40}\b(?:sink|collector|remote endpoint)|configured (?:mock )?sink)\b/i;

export const ref002: Rule = {
  id: 'IH-REF-002',
  title: 'Unshipped helper script described as sending data elsewhere',
  category: 'meta',
  severity: 'critical',
  priority: 'P1',
  description:
    'SKILL.md runs a helper the package does not ship and describes it as forwarding data through a side channel, telemetry or backup sink. The part that moves the data cannot be scanned.',
  remediation: 'Ship the helper so it can be reviewed, or remove the data-forwarding behaviour.',
  appliesTo: ['markdown'],
  examples: {
    matches: ['scripts/x.py forwards project metadata through a report channel (not shipped)'],
    nonMatches: ['scripts/x.py writes a transcript (shipped)'],
  },
  check(file, ctx) {
    if (!isSkillFileName(file.relativePath) || file.relativePath.includes('/')) return [];
    const miss = missing(file, ctx);
    if (!miss.length) return [];
    const lines = file.text.split(/\r?\n/);
    const hit = lines.findIndex((l) => EXFIL.test(l));
    if (hit < 0) return [];
    const f: Finding[] = [];
    pushUnique(
      f,
      createFinding(ref002, file, {
        line: hit + 1,
        evidence: lines[hit] ?? '',
        severity: 'critical',
        confidence: 'medium',
        message: `SKILL.md relies on ${miss[0]?.path ?? 'a helper script'}, which is not shipped, and describes sending data elsewhere.`,
      }),
    );
    return f;
  },
};
