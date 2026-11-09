import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { contentDigest } from '../../mcp/receipts.ts';
import { parseSkillMarkdown } from '../../openclaw/skill.ts';
import {
  identityDrift,
  verifyEvidence,
  type EvidenceReceipt,
  type LocalIdentity,
} from '../../provenance/local.ts';
import { UsageError } from '../../core/errors.ts';

async function identityOf(dir: string): Promise<LocalIdentity> {
  const digest = await contentDigest(dir);
  if (!digest.digest) throw new UsageError(`no files in ${dir}`);
  let text = '';
  try {
    text = await readFile(resolve(dir, 'SKILL.md'), 'utf8');
  } catch {
    text = '';
  }
  const fm = parseSkillMarkdown(text);
  return {
    name: fm.name ?? dir,
    version: fm.version ?? null,
    digest: digest.digest,
  };
}

export async function runProvenance(opts: {
  action: string;
  dir?: string;
  record?: string;
  evidence?: string;
  json?: boolean;
}): Promise<number> {
  if (opts.action === 'record') {
    if (!opts.dir) throw new UsageError('provenance record requires a directory');
    const id = await identityOf(opts.dir);
    const text = JSON.stringify(id, null, 2);
    if (opts.record) await writeFile(opts.record, text);
    else process.stdout.write(`${text}\n`);
    return 0;
  }
  if (opts.action === 'check') {
    if (!opts.dir || !opts.record)
      throw new UsageError('provenance check requires a directory and --record');
    const current = await identityOf(opts.dir);
    const previous = JSON.parse(await readFile(opts.record, 'utf8')) as LocalIdentity;
    const drift = identityDrift(previous, current);
    if (opts.json) process.stdout.write(`${JSON.stringify(drift)}\n`);
    else process.stdout.write(`${drift.kind}\n`);
    return drift.kind === 'unchanged' ? 0 : 1;
  }
  if (opts.action === 'verify-evidence') {
    if (!opts.evidence) throw new UsageError('provenance verify-evidence requires --evidence');
    const receipt = JSON.parse(await readFile(opts.evidence, 'utf8')) as EvidenceReceipt;
    const result = verifyEvidence(receipt);
    if (opts.json) process.stdout.write(`${JSON.stringify(result)}\n`);
    else if (!result.ok) process.stderr.write(`${result.problems.join('\n')}\n`);
    return result.ok ? 0 : 1;
  }
  throw new UsageError('provenance requires record, check, or verify-evidence');
}

export function skillFileSha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}
