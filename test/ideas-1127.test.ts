import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import type { FileKind, Rule, ScanContext, ScannedFile } from '../src/core/types.ts';
import { ideas1127Rules, priv017 } from '../src/rules/ideas-1127.ts';

function file(text: string, kind: FileKind = 'script'): ScannedFile {
  return {
    relativePath: 'scripts/apply.py',
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

const flags = (rule: Rule, text: string, kind: FileKind = 'script'): boolean =>
  rule.check(file(text, kind), ctx).length > 0;

describe('2026-11-27 persistent guard write', () => {
  for (const rule of ideas1127Rules) {
    it(`${rule.id} flags its matches and passes its non-matches`, () => {
      for (const match of rule.examples.matches) {
        expect(flags(rule, match), match).toBe(true);
      }
      for (const skip of rule.examples.nonMatches) {
        expect(flags(rule, skip), skip).toBe(false);
      }
    });
  }

  it('ignores prose and a markdown fence', () => {
    const prose = 'Set defaultMode to bypassPermissions in ~/.claude/settings.json.\n';
    expect(flags(priv017, prose, 'markdown')).toBe(false);
  });

  it('flags each persistent guard family and ignores a comment, a project write, and a restore', () => {
    expect(flags(priv017, 'echo "export NODE_TLS_REJECT_UNAUTHORIZED=0" >> ~/.bashrc\n')).toBe(
      true,
    );
    expect(flags(priv017, 'npm config set strict-ssl false\n')).toBe(true);
    expect(flags(priv017, 'git config --global http.sslVerify false\n')).toBe(true);
    expect(flags(priv017, 'pip config set global.trusted-host files.example\n')).toBe(true);
    expect(flags(priv017, 'echo "StrictHostKeyChecking no" >> ~/.ssh/config\n')).toBe(true);
    expect(flags(priv017, 'git config --global commit.gpgsign false\n')).toBe(true);
    expect(
      flags(
        priv017,
        '# git config --global http.sslVerify false\ngit config --global user.email "dev@example.com"\n',
      ),
    ).toBe(false);
    expect(
      flags(priv017, 'import requests\nrequests.get("https://api.example/", verify=False)\n'),
    ).toBe(false);
    expect(flags(priv017, 'npm config set strict-ssl false --location=project\n')).toBe(false);
    expect(
      flags(
        priv017,
        'git config --global http.sslVerify false\ngit config --global http.sslVerify true\n',
      ),
    ).toBe(false);
  });
});
