import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Ajv } from 'ajv';
import { describe, expect, it } from 'vitest';
import { metrics, runBench } from '../bench/run.ts';
import { renderRulesDocument } from '../src/rules/docs.ts';
import { allRules } from '../src/rules/index.ts';

describe('benchmark', () => {
  it('writes metrics for the synthetic corpus', async () => {
    const output = await mkdtemp(join(tmpdir(), 'ih-bench-'));
    const external = join(output, 'external.json');
    await writeFile(
      external,
      JSON.stringify({
        tool: 'other',
        skills: [{ path: 'benign/meeting-notes', verdict: 'no-findings' }],
      }),
    );
    const report = await runBench({
      corpusDir: join(process.cwd(), 'bench/corpus'),
      externalPath: external,
      outputDir: output,
    });
    expect(report.reviewOrWorse.recall).toBeGreaterThan(0);
    expect(report.reviewOrWorse.precision).toBeGreaterThan(0);
    expect(report.block.tp + report.block.fn).toBeGreaterThan(0);
    const markdown = await readFile(join(output, 'latest.md'), 'utf8');
    expect(markdown).toContain('precision');
    expect(markdown).toContain('recall');
    expect(markdown).toContain('false-positive rate');
    expect(markdown).toContain('other');
    const schema = JSON.parse(
      await readFile(join(process.cwd(), 'bench/labels.schema.json'), 'utf8'),
    ) as object;
    const labels = JSON.parse(
      await readFile(join(process.cwd(), 'bench/corpus/labels.json'), 'utf8'),
    ) as unknown;
    const ajv = new Ajv({ allErrors: true, strict: false });
    const validate = ajv.compile(schema);
    expect(validate(labels)).toBe(true);
    expect(metrics([{ label: 'malicious', predicted: true }]).precision).toBe(1);
  });
});

describe('rules document', () => {
  it('matches the generated markdown', async () => {
    const generated = renderRulesDocument(allRules());
    const onDisk = await readFile(join(process.cwd(), 'docs/rules.md'), 'utf8');
    expect(onDisk).toBe(generated);
    for (const rule of allRules()) expect(generated).toContain(rule.id);
  });
});
