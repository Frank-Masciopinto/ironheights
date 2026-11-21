import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(process.cwd(), 'bench/moltbook-families');

const FAMILIES = [
  'split-multifile',
  'credential-phishing',
  'purpose-mismatch',
  'mcp-poison',
  'global-persist',
  'trust-anchor',
  'staged-loader',
  'control-downgrade',
  'scope-widen',
  'concealment',
  'hidden-obfuscation',
  'lookup-input',
];

describe('moltbook-families benchmark set', () => {
  it('is pinned, pairs every attack with a twin, and generate.py --check matches the manifest', () => {
    const labels = JSON.parse(readFileSync(join(ROOT, 'labels.json'), 'utf8')) as {
      set_version: string;
      seed: string;
      labeling_notes: string;
      skills: {
        path: string;
        label: string;
        split: string;
        family: string;
        form: string;
        layout: string;
      }[];
    };
    const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8')) as {
      set_version: string;
      seed: string;
      tree_sha256: string;
      sample_count: number;
      split: string;
    };
    const malicious = labels.skills.filter((skill) => skill.label === 'malicious');
    const benign = labels.skills.filter((skill) => skill.label === 'benign');
    expect(labels.set_version).toBe('moltbook-families-v1');
    expect(labels.seed).toBe('moltbook-families-20261121');
    expect(manifest.set_version).toBe('moltbook-families-v1');
    expect(manifest.seed).toBe('moltbook-families-20261121');
    expect(manifest.split).toContain('heldout');
    expect(labels.labeling_notes.length).toBeGreaterThan(40);
    expect(malicious.length).toBe(384);
    expect(benign.length).toBe(384);
    expect(manifest.sample_count).toBe(labels.skills.length);
    expect(manifest.tree_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(labels.skills.some((skill) => skill.split === 'dev')).toBe(true);
    expect(labels.skills.some((skill) => skill.split === 'heldout')).toBe(true);
    expect(labels.skills.some((skill) => skill.form === 'prose')).toBe(true);
    expect(labels.skills.some((skill) => skill.form === 'steps')).toBe(true);
    expect(labels.skills.some((skill) => skill.layout === 'single')).toBe(true);
    expect(labels.skills.some((skill) => skill.layout === 'multi')).toBe(true);
    for (const family of FAMILIES) {
      const attacks = malicious.filter((skill) => skill.family === family);
      const twins = benign.filter((skill) => skill.family === family);
      expect(attacks.length).toBe(32);
      expect(twins.length).toBe(32);
    }
    const out = execFileSync('python3', [join(ROOT, 'generate.py'), '--check'], {
      encoding: 'utf8',
    });
    expect(out).toMatch(/^ok /);
  }, 60_000);
});
