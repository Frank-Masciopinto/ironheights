import { readFile } from 'node:fs/promises';
import type { Finding, ResolvedConfig } from '../core/types.ts';
import { UsageError } from '../core/errors.ts';
import { int001, int002, int003, int004 } from '../rules/integrity.ts';
import { clip } from '../util/text.ts';
import {
  baselineIsTampered,
  baselinePath,
  createBaseline,
  fromPortablePath,
  parseBaseline,
  toPortablePath,
  writeBaseline,
} from './baseline.ts';
import type { Baseline } from '../core/types.ts';

export interface VerifyResult {
  baselineTampered: boolean;
  added: string[];
  modified: string[];
  removed: string[];
  modeChanged: string[];
  findings: Finding[];
}

export async function saveBaseline(
  config: ResolvedConfig,
  home: string,
  now = new Date(),
): Promise<Baseline> {
  const roots = [...config.skillDirs, ...config.agentFiles];
  const baseline = await createBaseline(roots, now);
  if (baseline.roots.length === 0) throw new UsageError('no baseline roots exist');
  await writeBaseline(baselinePath(home), baseline);
  return baseline;
}

export async function loadBaseline(home: string): Promise<Baseline> {
  const raw = await readFile(baselinePath(home), 'utf8');
  return parseBaseline(raw);
}

export async function verifyBaseline(config: ResolvedConfig, home: string): Promise<VerifyResult> {
  const saved = await loadBaseline(home);
  const tampered = baselineIsTampered(saved);
  const roots = saved.roots.map(fromPortablePath);
  const current = await createBaseline(roots);
  const added: string[] = [];
  const modified: string[] = [];
  const removed: string[] = [];
  const modeChanged: string[] = [];
  const findings: Finding[] = [];

  if (tampered) {
    findings.push(
      finding(
        int001,
        'baseline.json',
        'Baseline treeHash does not match the recorded file hashes.',
        'treeHash mismatch',
        'critical',
      ),
    );
  }

  const agent = new Set(config.agentFiles.map(toPortablePath));
  const agentDirs = config.agentFiles
    .map(toPortablePath)
    .filter((path) => !path.endsWith('.md') && !path.endsWith('.json') && !path.endsWith('.env'));

  for (const [path, record] of Object.entries(current.files)) {
    const previous = saved.files[path];
    if (!previous) {
      added.push(path);
      const rule = isAgent(path, agent, agentDirs) ? int004 : int002;
      findings.push(finding(rule, path, 'Path was not in the baseline.', path));
      continue;
    }
    if (previous.sha256 !== record.sha256) {
      modified.push(path);
      const rule = isAgent(path, agent, agentDirs) ? int004 : int001;
      findings.push(
        finding(rule, path, 'File content changed since the baseline.', record.sha256.slice(0, 12)),
      );
    } else if (previous.mode !== record.mode) {
      modeChanged.push(path);
      const rule = isAgent(path, agent, agentDirs) ? int004 : int001;
      findings.push(
        finding(
          rule,
          path,
          'File mode changed since the baseline.',
          `${previous.mode.toString(8)} -> ${record.mode.toString(8)}`,
        ),
      );
    }
  }
  for (const path of Object.keys(saved.files)) {
    if (current.files[path]) continue;
    removed.push(path);
    const rule = isAgent(path, agent, agentDirs) ? int004 : int003;
    findings.push(finding(rule, path, 'Path from the baseline is missing.', path));
  }

  return { baselineTampered: tampered, added, modified, removed, modeChanged, findings };
}

function isAgent(path: string, files: Set<string>, dirs: string[]): boolean {
  if (files.has(path)) return true;
  return dirs.some((dir) => path === dir || path.startsWith(`${dir}/`));
}

function finding(
  rule: { id: string; severity: Finding['severity']; remediation: string },
  file: string,
  message: string,
  evidence: string,
  severity?: Finding['severity'],
): Finding {
  return {
    ruleId: rule.id,
    severity: severity ?? rule.severity,
    confidence: 'high',
    file: clip(file, 300),
    evidence: clip(evidence),
    message,
    remediation: rule.remediation,
  };
}
