import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(process.cwd(), 'bench/attack-lanes');

describe('attack-lanes benchmark set', () => {
  it('is pinned, has ≥1000 malicious and ≥1000 benign, covers L1–L8, and generate.py --check matches the manifest', () => {
    const labels = JSON.parse(readFileSync(join(ROOT, 'labels.json'), 'utf8')) as {
      skills: { path: string; label: string; split: string; source: string; family: string }[];
    };
    const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8')) as {
      seed: string;
      tree_sha256: string;
      sample_count: number;
    };
    const mal = labels.skills.filter((s) => s.label === 'malicious');
    const ben = labels.skills.filter((s) => s.label === 'benign');
    expect(mal.length).toBeGreaterThanOrEqual(1000);
    expect(ben.length).toBeGreaterThanOrEqual(1000);
    expect(manifest.sample_count).toBe(labels.skills.length);
    expect(manifest.seed).toBe('attack-lanes-20261115');
    expect(manifest.tree_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(labels.skills.some((s) => s.split === 'heldout')).toBe(true);
    expect(labels.skills.some((s) => s.source === 'real-derived')).toBe(true);
    for (const lane of ['L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8']) {
      expect(mal.some((s) => s.family === lane)).toBe(true);
    }
    const out = execFileSync('python3', [join(ROOT, 'generate.py'), '--check'], {
      encoding: 'utf8',
    });
    expect(out).toMatch(/^ok /);
  }, 60_000);
});
