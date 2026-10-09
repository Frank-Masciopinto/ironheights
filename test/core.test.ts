import { mkdtemp, mkdir, symlink, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emptyConfig, loadConfig } from '../src/core/config.ts';
import { scanPath } from '../src/core/scanner.ts';
import { walkSkill } from '../src/core/walker.ts';
import { exitCodeFor, scoreFindings, verdictFor } from '../src/core/verdict.ts';
import { renderHuman } from '../src/cli/output/human.ts';
import { renderJson } from '../src/cli/output/json.ts';
import { renderSarif } from '../src/cli/output/sarif.ts';
import { SAFETY_REMINDER } from '../src/version.ts';
import type { Finding } from '../src/core/types.ts';

const finding = (severity: Finding['severity'], ruleId = 'IH-TEST'): Finding => ({
  ruleId,
  severity,
  confidence: 'high',
  file: 'SKILL.md',
  line: 1,
  evidence: 'example',
  message: 'example',
  remediation: 'fix it',
});

describe('verdict', () => {
  it('scores and classifies findings', () => {
    expect(scoreFindings([finding('critical')])).toBe(100);
    expect(verdictFor([finding('critical')], { block: 80, review: 15 })).toBe('block');
    expect(verdictFor([finding('high'), finding('high')], { block: 80, review: 15 })).toBe('block');
    expect(verdictFor([finding('medium')], { block: 80, review: 15 })).toBe('review');
    expect(verdictFor([finding('low')], { block: 80, review: 15 })).toBe('no-findings');
    expect(verdictFor([finding('info')], { block: 80, review: 15 })).toBe('no-findings');
    expect(exitCodeFor('review', [finding('high')], 'critical')).toBe(0);
    expect(exitCodeFor('block', [finding('critical')], 'critical')).toBe(2);
    expect(exitCodeFor('no-findings', [], undefined)).toBe(0);
  });
});

describe('config', () => {
  it('rejects unknown keys and missing files', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-config-'));
    const file = join(dir, 'ironheights.config.json');
    await writeFile(file, '{"unknown":true}\n');
    await expect(
      loadConfig({ explicitPath: file, env: { IRONHEIGHTS_HOME: dir, OPENCLAW_STATE_DIR: dir } }),
    ).rejects.toThrow(/invalid config/);
    await expect(loadConfig({ explicitPath: join(dir, 'missing.json'), env: {} })).rejects.toThrow(
      /cannot read/,
    );
  });

  it('loads overrides', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-config-'));
    const file = join(dir, 'ironheights.config.json');
    await writeFile(
      file,
      JSON.stringify({
        skillDirs: ['/tmp/skills'],
        failOn: 'high',
        ruleOverrides: { 'IH-NET-001': { enabled: false, severity: 'low' } },
        limits: { maxFiles: 10 },
      }),
    );
    const config = await loadConfig({
      explicitPath: file,
      env: { IRONHEIGHTS_HOME: dir, OPENCLAW_STATE_DIR: dir },
    });
    expect(config.failOn).toBe('high');
    expect(config.ruleOverrides['IH-NET-001']?.enabled).toBe(false);
    expect(config.limits.maxFiles).toBe(10);
    expect(emptyConfig().thresholds.block).toBe(80);
  });
});

describe('scanner', () => {
  it('scans the benign fixture with no findings', async () => {
    const result = await scanPath(join(process.cwd(), 'test/fixtures/benign'), emptyConfig());
    expect(result.skills).toHaveLength(1);
    expect(result.skills[0]?.skillName).toBe('benign');
    expect(result.skills[0]?.findings).toEqual([]);
    expect(result.verdict).toBe('no-findings');
    const human = renderHuman(result.skills, result.verdict, false);
    expect(human).toContain('No findings');
    expect(human).toContain(SAFETY_REMINDER);
    expect(human).not.toMatch(/\bsafe\b|\bclean\b/i);
    const json = JSON.parse(
      renderJson(result.skills, result.verdict, '2026-10-09T00:00:00.000Z'),
    ) as {
      schemaVersion: number;
    };
    expect(json.schemaVersion).toBe(1);
  });

  it('scans the advisory skill with no findings', async () => {
    const result = await scanPath(join(process.cwd(), 'skill/ironheights'), emptyConfig());
    expect(result.skills[0]?.findings).toEqual([]);
  });

  it('scans 500 small files in under two seconds', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-perf-'));
    await mkdir(join(dir, 'skill'));
    await writeFile(
      join(dir, 'skill/SKILL.md'),
      '---\nname: skill\ndescription: Performance sample.\n---\nnotes\n',
    );
    await Promise.all(
      Array.from({ length: 499 }, (_, index) =>
        writeFile(join(dir, 'skill', `note-${index}.md`), 'Write a local note.\n'),
      ),
    );
    const started = Date.now();
    const result = await scanPath(join(dir, 'skill'), emptyConfig());
    expect(Date.now() - started).toBeLessThan(2000);
    expect(result.skills[0]?.filesScanned).toBe(500);
    expect(result.verdict).toBe('no-findings');
    await rm(dir, { recursive: true, force: true });
  });
});

describe('walker robustness', () => {
  it('handles empty folders, huge files, invalid utf-8, binaries, symlink loops, long lines, and odd names', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-walk-'));
    const empty = join(dir, 'empty');
    await mkdir(empty);
    const emptyWalk = await walkSkill(empty, { maxFileBytes: 100, maxFiles: 10, maxDepth: 2 }, []);
    expect(emptyWalk.files).toEqual([]);

    const huge = join(dir, 'huge');
    await mkdir(huge);
    await writeFile(join(huge, 'big.txt'), Buffer.alloc(200, 0x61));
    const hugeWalk = await walkSkill(huge, { maxFileBytes: 50, maxFiles: 10, maxDepth: 4 }, []);
    expect(hugeWalk.skipped[0]?.reason).toMatch(/exceeds/);

    const weird = join(dir, 'weird');
    await mkdir(weird);
    await writeFile(join(weird, 'bad.bin'), Buffer.from([0xff, 0xfe, 0x00, 0x41]));
    await writeFile(join(weird, 'long.txt'), `${'a'.repeat(20000)}\n`);
    await writeFile(join(weird, 'ansi\u001b[31m.md'), 'hello');
    const loopDir = join(weird, 'loop');
    await mkdir(loopDir);
    await symlink(loopDir, join(loopDir, 'self'));
    const outside = join(dir, 'outside.txt');
    await writeFile(outside, 'secret');
    await symlink(outside, join(weird, 'escape'));
    const walked = await walkSkill(
      weird,
      { maxFileBytes: 1024 * 1024, maxFiles: 20, maxDepth: 4 },
      [],
    );
    expect(
      walked.files.some((file) => file.symlinkLoop || file.relativePath.includes('self')),
    ).toBe(true);
    expect(walked.files.some((file) => file.symlinkOutside)).toBe(true);
    expect(walked.files.some((file) => file.relativePath.includes('long.txt'))).toBe(true);

    const unreadable = join(dir, 'locked');
    await mkdir(unreadable);
    const locked = join(unreadable, 'nope.txt');
    await writeFile(locked, 'hidden');
    await chmod(locked, 0o000);
    const lockedWalk = await walkSkill(
      unreadable,
      { maxFileBytes: 1000, maxFiles: 10, maxDepth: 3 },
      [],
    );
    expect(
      lockedWalk.skipped.some((item) => item.reason === 'unreadable file') ||
        lockedWalk.files.length === 0,
    ).toBe(true);
    await chmod(locked, 0o644);
    await rm(dir, { recursive: true, force: true });
  });
});

describe('output snapshots', () => {
  it('renders human, json, and sarif', () => {
    const skills = [
      {
        skillName: 'demo',
        root: '/tmp/demo',
        filesScanned: 1,
        filesSkipped: [],
        findings: [finding('high', 'IH-CRED-001')],
        score: 40,
        verdict: 'review' as const,
      },
    ];
    expect(renderHuman(skills, 'review', false)).toMatchSnapshot();
    expect(renderJson(skills, 'review', '2026-10-09T00:00:00.000Z')).toMatchSnapshot();
    expect(renderSarif(skills)).toMatchSnapshot();
  });
});
