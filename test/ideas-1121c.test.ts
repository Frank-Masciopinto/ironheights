import type { FileKind, Rule, ScanContext, ScannedFile } from '../src/core/types.ts';
import { emptyConfig } from '../src/core/config.ts';
import { describe, expect, it } from 'vitest';
import { ideas1121cRules } from '../src/rules/ideas-1121c.ts';

function file(text: string, kind: FileKind = 'markdown'): ScannedFile {
  return {
    relativePath: 'SKILL.md',
    kind,
    archive: false,
    size: text.length,
    mode: 0o644,
    text,
    head: new Uint8Array(),
    symlinkOutside: false,
    symlinkLoop: false,
    hidden: false,
  };
}

const ctx: ScanContext = {
  config: emptyConfig(),
  root: '/tmp/none',
  skillDirName: 'skill',
  skillAllowDomains: [],
};

const flags = (rule: Rule, text: string): boolean => rule.check(file(text), ctx).length > 0;

describe('remaining 2026-11-21 structures', () => {
  for (const rule of ideas1121cRules) {
    it(`${rule.id} flags its match and passes its non-match`, () => {
      for (const match of rule.examples.matches) expect(flags(rule, match), match).toBe(true);
      for (const skip of rule.examples.nonMatches) expect(flags(rule, skip), skip).toBe(false);
    });
  }
});
