import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import { scanPath } from '../src/core/scanner.ts';
import { extractUrls } from '../src/rules/network.ts';

async function skillDir(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'ih-0120-'));
  for (const [name, text] of Object.entries(files)) {
    const path = join(root, name);
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, text);
  }
  return root;
}
const FM = '---\nname: demo\ndescription: Demo skill.\n---\n';
async function hits(files: Record<string, string>, id: string) {
  const result = await scanPath(await skillDir(files), emptyConfig());
  return result.skills.flatMap((s) => s.findings).filter((f) => f.ruleId === id);
}

describe('0.12.0 IH-REF-001 missing referenced script (synapseguide, ccbillboardbug, felixnexus, fujikatsu)', () => {
  it('a command that runs a missing script is medium', async () => {
    const f = await hits(
      { 'SKILL.md': `${FM}\n\`\`\`bash\npython3 scripts/sync.py --all\n\`\`\`\n` },
      'IH-REF-001',
    );
    expect(f.map((x) => x.severity)).toEqual(['medium']);
  });
  it('a passing mention is low', async () => {
    const f = await hits(
      { 'SKILL.md': `${FM}\nThe helper is \`scripts/helper.sh\`.\n` },
      'IH-REF-001',
    );
    expect(f.map((x) => x.severity)).toEqual(['low']);
  });
  it('present files, {baseDir} and skills/<name>/ prefixes are fine', async () => {
    const f = await hits(
      {
        'SKILL.md': `${FM}\n\`\`\`bash\npython3 {baseDir}/scripts/a.py\nbash skills/demo/scripts/b.sh\nnode lib/c.js\n\`\`\`\n`,
        'scripts/a.py': '',
        'scripts/b.sh': '',
        'src/lib/c.js': '',
      },
      'IH-REF-001',
    );
    expect(f).toEqual([]);
  });
  it('placeholders, bare names, URLs, absolute paths, comments, build output and created files are quiet', async () => {
    const md = `${FM}\n\`\`\`bash\npython3 path/to/your_script.py\nnode swap.js\ncurl https://x.dev/scripts/i.sh\nbash ~/bin/t.sh\n// fixtures/data.ts\nnode dist/cli.js\ncat > tools/gen.sh <<EOF\nEOF\nbash tools/gen.sh\n\`\`\`\nDo not use \`scripts/old.py\`.\n`;
    expect(await hits({ 'SKILL.md': md }, 'IH-REF-001')).toEqual([]);
  });
  it('only the top-level SKILL.md is checked', async () => {
    expect(
      await hits({ 'SKILL.md': FM, 'docs/README.md': 'python3 scripts/x.py\n' }, 'IH-REF-001'),
    ).toEqual([]);
  });
});

describe('0.12.0 IH-EXEC-004 confirm-before-delete docs whose examples skip it (65 Maton skills)', () => {
  const md = `${FM}\n> Ask the user to confirm before every delete. \`--yes\` removes the last chance; omit it unless the user confirmed.\n\n\`\`\`bash\nmaton connection delete abc --yes\nmaton function delete f1 -y\nmaton env remove e1 --force\n\`\`\`\n`;
  it('each example is a medium finding and the guard sentence is info', async () => {
    const f = await hits({ 'SKILL.md': md }, 'IH-EXEC-004');
    expect(f.map((x) => [x.line, x.severity]).sort((a, b) => Number(a[0]) - Number(b[0]))).toEqual([
      [6, 'info'],
      [9, 'medium'],
      [10, 'medium'],
      [11, 'medium'],
    ]);
    expect(f[1]?.message).toMatch(/confirm before deleting/);
  });
  it('an example that says it runs after confirmation is not a contradiction', async () => {
    const f = await hits(
      {
        'SKILL.md': `${FM}\nConfirm before you delete.\n\n\`\`\`bash\nbsky delete <url> --yes # after verifying target\n\`\`\`\n`,
      },
      'IH-EXEC-004',
    );
    expect(f.some((x) => /confirm before deleting/.test(x.message))).toBe(false);
  });
  it('-y and --force without a confirm rule stay quiet', async () => {
    expect(
      await hits({ 'SKILL.md': `${FM}\n\`\`\`bash\ntool delete x -y\n\`\`\`\n` }, 'IH-EXEC-004'),
    ).toEqual([]);
  });
});

describe('0.12.0 precision fixes', () => {
  it('a URL stops at full-width punctuation', () => {
    expect(extractUrls('调用 https://api.vendor.com/v1，然后返回').map((u) => u.raw)).toEqual([
      'https://api.vendor.com/v1',
    ]);
  });
  it('example and localhost hosts are skipped', async () => {
    const f = await hits(
      {
        'SKILL.md': `${FM}\nexample: https://api.example.com/x and http://localhost:3000 and http://0.0.0.0:8080 and http://app.localhost\n`,
      },
      'IH-NET-001',
    );
    expect(f).toEqual([]);
  });
  it('a changelog line about a fixed bug is info; other changelog lines keep severity', async () => {
    const result = await scanPath(
      await skillDir({
        'SKILL.md': FM,
        'CHANGELOG.md':
          '- Fixed: no longer runs sudo bash install.sh\n- Now runs sudo bash setup.sh\n',
      }),
      emptyConfig(),
    );
    const f = result.skills
      .flatMap((s) => s.findings)
      .filter((x) => x.file === 'CHANGELOG.md' && x.ruleId === 'IH-PRIV-001');
    expect(f.map((x) => [x.line, x.severity]).sort((a, b) => Number(a[0]) - Number(b[0]))).toEqual([
      [1, 'info'],
      [2, 'high'],
    ]);
  });
});
