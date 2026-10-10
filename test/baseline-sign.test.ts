import { spawnSync } from 'node:child_process';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import { parseBaseline, writeBaseline } from '../src/integrity/baseline.ts';
import { loadBaselineKey } from '../src/integrity/signature.ts';
import { saveBaseline, verifyBaseline } from '../src/integrity/verify.ts';
import { runVerify } from '../src/cli/commands/baseline.ts';

describe('baseline signatures', () => {
  it('reports a rewritten baseline when the Ed25519 signature does not match', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-sig-'));
    try {
      const skill = join(root, 'skill');
      await mkdir(skill);
      await writeFile(
        join(skill, 'SKILL.md'),
        '---\nname: skill\ndescription: Demo.\n---\nhello\n',
      );
      const key = join(root, 'baseline.key');
      const generated = spawnSync(
        process.execPath,
        ['scripts/generate-baseline-key.mjs', '--alg', 'ed25519', '--out', key],
        { encoding: 'utf8' },
      );
      expect(generated.status).toBe(0);
      const home = join(root, 'home');
      const config = emptyConfig({ skillDirs: [skill], agentFiles: [] });
      await saveBaseline(config, home, new Date('2026-10-10T00:00:00.000Z'), { keyPath: key });
      const clean = await verifyBaseline(config, home, { keyPath: key });
      expect(clean.signatureChecked).toBe(true);
      expect(clean.signatureMismatch).toBe(false);
      expect(clean.baselineTampered).toBe(false);

      const saved = parseBaseline(await readFile(join(home, 'baseline.json'), 'utf8'));
      saved.toolVersion = 'tampered';
      await writeBaseline(join(home, 'baseline.json'), saved);
      const tampered = await verifyBaseline(config, home, { keyPath: key });
      expect(tampered.treeHashMismatch).toBe(false);
      expect(tampered.signatureMismatch).toBe(true);
      expect(tampered.baselineTampered).toBe(true);
      expect(tampered.findings.some((item) => item.evidence === 'signature mismatch')).toBe(true);

      const lines: string[] = [];
      const code = await runVerify({
        env: {
          IRONHEIGHTS_HOME: home,
          OPENCLAW_STATE_DIR: join(root, 'state'),
          IRONHEIGHTS_BASELINE_KEY: key,
        },
        stdout: (text) => lines.push(text),
      });
      expect(code).toBe(2);
      expect(lines.join('')).toContain('baseline: signature mismatch');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('verifies an HMAC key and refuses a group-readable key file', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-hmac-'));
    try {
      const skill = join(root, 'skill');
      await mkdir(skill);
      await writeFile(
        join(skill, 'SKILL.md'),
        '---\nname: skill\ndescription: Demo.\n---\nhello\n',
      );
      const key = join(root, 'baseline.key');
      const generated = spawnSync(
        process.execPath,
        ['scripts/generate-baseline-key.mjs', '--alg', 'hmac-sha256', '--out', key],
        { encoding: 'utf8' },
      );
      expect(generated.status).toBe(0);
      const home = join(root, 'home');
      const config = emptyConfig({ skillDirs: [skill], agentFiles: [] });
      await saveBaseline(config, home, new Date('2026-10-10T00:00:00.000Z'), { keyPath: key });
      const clean = await verifyBaseline(config, home, { keyPath: key });
      expect(clean.baselineTampered).toBe(false);
      await chmod(key, 0o644);
      if (process.platform === 'win32') {
        await expect(loadBaselineKey(key, 'verify')).resolves.toMatchObject({ alg: 'hmac-sha256' });
      } else {
        await expect(loadBaselineKey(key, 'verify')).rejects.toThrow(/group or others/);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('release checksums', () => {
  it('writes sha256sum lines for the named files', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-sum-'));
    try {
      const file = join(root, 'ironheights-0.1.5.tgz');
      await writeFile(file, 'package-bytes');
      const result = spawnSync(process.execPath, ['scripts/write-sha256sums.mjs', file], {
        encoding: 'utf8',
      });
      expect(result.status).toBe(0);
      const expected = createHash('sha256').update('package-bytes').digest('hex');
      expect(result.stdout).toBe(`${expected}  ironheights-0.1.5.tgz\n`);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
