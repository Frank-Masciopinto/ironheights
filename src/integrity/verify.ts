import { readFile, rm } from 'node:fs/promises';
import type { Finding, ResolvedConfig } from '../core/types.ts';
import { UsageError } from '../core/errors.ts';
import { int001, int002, int003, int004 } from '../rules/integrity.ts';
import { writeAtomic } from '../util/atomic.ts';
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
import { loadBaselineKey, signBaselineBytes, verifyBaselineBytes } from './signature.ts';
import type { Baseline } from '../core/types.ts';

export interface VerifyResult {
  baselineTampered: boolean;
  treeHashMismatch: boolean;
  signatureChecked: boolean;
  signatureMismatch: boolean;
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
  options: { keyPath?: string } = {},
): Promise<Baseline> {
  const roots = [...config.skillDirs, ...config.agentFiles];
  const baseline = await createBaseline(roots, now);
  if (baseline.roots.length === 0) throw new UsageError('no baseline roots exist');
  const filePath = baselinePath(home);
  await writeBaseline(filePath, baseline);
  const sigPath = `${filePath}.sig`;
  if (options.keyPath) {
    const key = await loadBaselineKey(options.keyPath, 'sign');
    const body = await readFile(filePath, 'utf8');
    await writeAtomic(sigPath, signBaselineBytes(body, key), 0o600);
  } else {
    await rm(sigPath, { force: true });
  }
  return baseline;
}

export async function loadBaseline(home: string): Promise<Baseline> {
  const raw = await readFile(baselinePath(home), 'utf8');
  return parseBaseline(raw);
}

export async function verifyBaseline(
  config: ResolvedConfig,
  home: string,
  options: { keyPath?: string } = {},
): Promise<VerifyResult> {
  const filePath = baselinePath(home);
  const raw = await readFile(filePath, 'utf8');
  const saved = parseBaseline(raw);
  const treeHashMismatch = baselineIsTampered(saved);
  const signature = await checkSignature(raw, `${filePath}.sig`, options.keyPath);
  const roots = saved.roots.map((portable) => fromPortablePath(portable));
  const current = await createBaseline(roots);
  const added: string[] = [];
  const modified: string[] = [];
  const removed: string[] = [];
  const modeChanged: string[] = [];
  const findings: Finding[] = [];

  if (treeHashMismatch) {
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
  if (signature.mismatch) {
    findings.push(
      finding(
        int001,
        'baseline.json',
        'Baseline signature is missing or invalid.',
        'signature mismatch',
        'critical',
      ),
    );
  }

  const agent = new Set(config.agentFiles.map((file) => toPortablePath(file)));
  const agentDirs = config.agentFiles
    .map((file) => toPortablePath(file))
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

  return {
    baselineTampered: treeHashMismatch || signature.mismatch,
    treeHashMismatch,
    signatureChecked: signature.checked,
    signatureMismatch: signature.mismatch,
    added,
    modified,
    removed,
    modeChanged,
    findings,
  };
}

async function checkSignature(
  raw: string,
  sigPath: string,
  keyPath: string | undefined,
): Promise<{ checked: boolean; mismatch: boolean }> {
  if (!keyPath) return { checked: false, mismatch: false };
  const key = await loadBaselineKey(keyPath, 'verify');
  let sigText: string;
  try {
    sigText = await readFile(sigPath, 'utf8');
  } catch {
    return { checked: true, mismatch: true };
  }
  return { checked: true, mismatch: !verifyBaselineBytes(raw, sigText, key) };
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
