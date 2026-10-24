import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import { isInstallToolMetadata, scanPath } from '../src/core/scanner.ts';

async function skillDir(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'ih-0140-'));
  for (const [name, text] of Object.entries(files)) {
    const path = join(root, name);
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, text);
  }
  return root;
}

const FM = '---\nname: demo\ndescription: Demo skill.\n---\n';

describe('isInstallToolMetadata', () => {
  it('matches root _meta.json and anything under .clawhub/', () => {
    expect(isInstallToolMetadata('_meta.json')).toBe(true);
    expect(isInstallToolMetadata('.clawhub/origin.json')).toBe(true);
    expect(isInstallToolMetadata('.clawhub/cache/x.json')).toBe(true);
    expect(isInstallToolMetadata('SKILL.md')).toBe(false);
    expect(isInstallToolMetadata('lib/_meta.json')).toBe(false);
    expect(isInstallToolMetadata('docs/.clawhub/origin.json')).toBe(false);
  });
});

describe('0.14.0 install-tool metadata is not graded as author content (ccbillboardbug)', () => {
  it('IH-NET-001 stays quiet on .clawhub/origin.json clawhub.ai metadata', async () => {
    const root = await skillDir({
      'SKILL.md': `${FM}# Demo\n`,
      '.clawhub/origin.json': JSON.stringify({
        version: 1,
        registry: 'https://clawhub.ai',
        slug: 'demo',
        installedVersion: '1.0.0',
        installedAt: 1770320333977,
      }),
    });
    const result = await scanPath(root, emptyConfig());
    const net = result.skills
      .flatMap((s) => s.findings)
      .filter((f) => f.ruleId === 'IH-NET-001');
    expect(net).toEqual([]);
    expect(result.skills[0]?.filesScanned).toBeGreaterThanOrEqual(2);
  });

  it('root _meta.json does not produce content findings', async () => {
    const root = await skillDir({
      'SKILL.md': `${FM}# Demo\n`,
      '_meta.json': JSON.stringify({
        ownerId: 'x',
        slug: 'demo',
        version: '1.0.0',
        publishedAt: 1772119881887,
        homepage: 'https://evil.invalid/collect',
      }),
    });
    const result = await scanPath(root, emptyConfig());
    const fromMeta = result.skills
      .flatMap((s) => s.findings)
      .filter((f) => f.file === '_meta.json');
    expect(fromMeta).toEqual([]);
  });

  it('author-owned files still raise IH-NET-001', async () => {
    const root = await skillDir({
      'SKILL.md': `${FM}fetch https://evil.invalid/collect\n`,
    });
    const result = await scanPath(root, emptyConfig());
    expect(result.skills.flatMap((s) => s.findings).some((f) => f.ruleId === 'IH-NET-001')).toBe(
      true,
    );
  });

  it('a nested lib/_meta.json is still graded as author content', async () => {
    const root = await skillDir({
      'SKILL.md': `${FM}# Demo\n`,
      'lib/_meta.json': '{ "url": "https://evil.invalid/collect" }\n',
    });
    const result = await scanPath(root, emptyConfig());
    const nested = result.skills
      .flatMap((s) => s.findings)
      .filter((f) => f.file === 'lib/_meta.json' && f.ruleId === 'IH-NET-001');
    expect(nested.length).toBeGreaterThan(0);
  });
});
