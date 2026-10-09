import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { z } from 'zod';
import { emptyConfig } from '../src/core/config.ts';
import { UsageError } from '../src/core/errors.ts';
import { scanPath } from '../src/core/scanner.ts';
import type { SkillReport, Verdict } from '../src/core/types.ts';

const LabelsSchema = z
  .object({
    skills: z.array(
      z
        .object({
          path: z.string(),
          label: z.enum(['malicious', 'benign']),
          family: z.string().optional(),
          notes: z.string().optional(),
        })
        .strict(),
    ),
  })
  .strict();

const ExternalSchema = z
  .object({
    tool: z.string(),
    skills: z.array(
      z
        .object({
          path: z.string(),
          verdict: z.enum(['no-findings', 'review', 'block']),
        })
        .strict(),
    ),
  })
  .strict();

export interface Counts {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
}

export interface BenchReport {
  corpus: string;
  skills: number;
  reviewOrWorse: Counts;
  block: Counts;
  perRule: Record<string, number>;
  missedReview: string[];
  wronglyFlaggedReview: string[];
  missedBlock: string[];
  wronglyFlaggedBlock: string[];
  external?: { tool: string; reviewOrWorse: Counts; block: Counts };
}

export async function runBench(options: {
  corpusDir: string;
  externalPath?: string;
  outputDir?: string;
}): Promise<BenchReport> {
  const corpus = resolve(options.corpusDir);
  const raw = await readFile(join(corpus, 'labels.json'), 'utf8').catch(() => {
    throw new UsageError(`labels.json not found in ${corpus}`);
  });
  const labels = LabelsSchema.parse(JSON.parse(raw) as unknown);
  const rows: Array<{
    path: string;
    label: 'malicious' | 'benign';
    verdict: Verdict;
    rules: string[];
  }> = [];
  const perRule: Record<string, number> = {};
  for (const item of labels.skills) {
    const result = await scanPath(join(corpus, item.path), emptyConfig());
    const verdict = result.verdict;
    const rules = result.skills.flatMap((skill: SkillReport) =>
      skill.findings.map((finding) => finding.ruleId),
    );
    for (const ruleId of rules) perRule[ruleId] = (perRule[ruleId] ?? 0) + 1;
    rows.push({ path: item.path, label: item.label, verdict, rules });
  }
  const review = metrics(
    rows.map((row) => ({ label: row.label, predicted: row.verdict !== 'no-findings' })),
  );
  const block = metrics(
    rows.map((row) => ({ label: row.label, predicted: row.verdict === 'block' })),
  );
  const report: BenchReport = {
    corpus,
    skills: rows.length,
    reviewOrWorse: review,
    block,
    perRule,
    missedReview: rows
      .filter((row) => row.label === 'malicious' && row.verdict === 'no-findings')
      .map((row) => row.path),
    wronglyFlaggedReview: rows
      .filter((row) => row.label === 'benign' && row.verdict !== 'no-findings')
      .map((row) => row.path),
    missedBlock: rows
      .filter((row) => row.label === 'malicious' && row.verdict !== 'block')
      .map((row) => row.path),
    wronglyFlaggedBlock: rows
      .filter((row) => row.label === 'benign' && row.verdict === 'block')
      .map((row) => row.path),
  };
  if (options.externalPath) {
    const external = ExternalSchema.parse(
      JSON.parse(await readFile(options.externalPath, 'utf8')) as unknown,
    );
    const byPath = new Map(external.skills.map((skill) => [skill.path, skill.verdict]));
    const paired = rows.map((row) => ({
      label: row.label,
      verdict: byPath.get(row.path) ?? 'no-findings',
    }));
    report.external = {
      tool: external.tool,
      reviewOrWorse: metrics(
        paired.map((row) => ({ label: row.label, predicted: row.verdict !== 'no-findings' })),
      ),
      block: metrics(
        paired.map((row) => ({ label: row.label, predicted: row.verdict === 'block' })),
      ),
    };
  }
  const outputDir = options.outputDir ?? join(process.cwd(), 'bench', 'results');
  await mkdir(outputDir, { recursive: true });
  await writeFile(join(outputDir, 'latest.json'), `${JSON.stringify(report, null, 2)}\n`);
  await writeFile(join(outputDir, 'latest.md'), renderBenchMarkdown(report));
  return report;
}

export function metrics(
  rows: Array<{ label: 'malicious' | 'benign'; predicted: boolean }>,
): Counts {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const row of rows) {
    if (row.label === 'malicious' && row.predicted) tp += 1;
    else if (row.label === 'benign' && row.predicted) fp += 1;
    else if (row.label === 'benign') tn += 1;
    else fn += 1;
  }
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  const fpr = fp + tn === 0 ? 0 : fp / (fp + tn);
  return { tp, fp, tn, fn, precision, recall, f1, fpr };
}

export function renderBenchMarkdown(report: BenchReport): string {
  const lines = [
    '# Ironheights benchmark',
    '',
    `Corpus: \`${report.corpus}\``,
    '',
    `Skills: ${report.skills}`,
    '',
    '## Positive = review or worse',
    '',
    table(report.reviewOrWorse),
    '',
    `Missed: ${list(report.missedReview)}`,
    '',
    `Wrongly flagged: ${list(report.wronglyFlaggedReview)}`,
    '',
    '## Positive = block',
    '',
    table(report.block),
    '',
    `Missed: ${list(report.missedBlock)}`,
    '',
    `Wrongly flagged: ${list(report.wronglyFlaggedBlock)}`,
    '',
    '## Per-rule hits',
    '',
  ];
  const ruleIds = Object.keys(report.perRule).sort();
  if (ruleIds.length === 0) lines.push('No rule hits.', '');
  for (const id of ruleIds) lines.push(`- ${id}: ${report.perRule[id] ?? 0}`);
  if (report.external) {
    lines.push(
      '',
      `## External tool: ${report.external.tool}`,
      '',
      '### Review or worse',
      '',
      table(report.external.reviewOrWorse),
      '',
      '### Block',
      '',
      table(report.external.block),
    );
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

function table(counts: Counts): string {
  return [
    '| metric | value |',
    '| --- | --- |',
    `| tp | ${counts.tp} |`,
    `| fp | ${counts.fp} |`,
    `| tn | ${counts.tn} |`,
    `| fn | ${counts.fn} |`,
    `| precision | ${counts.precision.toFixed(3)} |`,
    `| recall | ${counts.recall.toFixed(3)} |`,
    `| f1 | ${counts.f1.toFixed(3)} |`,
    `| false-positive rate | ${counts.fpr.toFixed(3)} |`,
  ].join('\n');
}

function list(items: string[]): string {
  return items.length === 0 ? 'none' : items.join(', ');
}

export function benchOutputDir(corpusDir: string): string {
  return dirname(resolve(corpusDir));
}
