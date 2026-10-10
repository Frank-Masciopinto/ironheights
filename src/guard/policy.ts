import picomatch from 'picomatch';
import { hostAllowed } from '../rules/network.ts';
import { clip } from '../util/text.ts';
import { redactSecrets } from './redact.ts';
import { collectViolations } from './signals.ts';
import type {
  GuardAllow,
  GuardDecision,
  GuardMode,
  ResolvedGuardPolicy,
  SuppressedViolation,
  ToolCall,
  Violation,
} from './types.ts';

const MAX_REASON = 600;

/**
 * Pure policy evaluation. The same call and policy always produce the same
 * decision. It does not read the clock, the filesystem, or the network.
 * An explicit allow entry suppresses only the violations it matches.
 * Other violations on the same call still stand.
 */
export function evaluateToolCall(call: ToolCall, policy: ResolvedGuardPolicy): GuardDecision {
  try {
    return decide(call, policy, collectViolations(call, policy));
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown error';
    return errorDecision(policy.mode, message);
  }
}

export function errorDecision(mode: GuardMode, message: string): GuardDecision {
  const wouldBlock = mode === 'enforce';
  const reason = clip(
    redactSecrets(
      wouldBlock
        ? `ironheights: blocked in enforce because the guard could not evaluate this tool call (${message}). The guard returned a block.`
        : `ironheights: guard evaluation failed (${message}). Monitor mode recorded the error and allowed the tool call.`,
    ),
    MAX_REASON,
  );
  return {
    action: actionFor(mode, wouldBlock),
    mode,
    wouldBlock,
    violations: [],
    allowed: [],
    reason,
  };
}

function decide(call: ToolCall, policy: ResolvedGuardPolicy, found: Violation[]): GuardDecision {
  const violations: Violation[] = [];
  const allowed: SuppressedViolation[] = [];
  for (const violation of found) {
    const match = policy.allow.find((entry) => allowMatches(entry, violation, call, policy));
    if (match) {
      allowed.push({
        ruleId: violation.ruleId,
        allowId: match.id,
        ...(violation.host ? { host: violation.host } : {}),
        ...(violation.path ? { path: violation.path } : {}),
      });
      continue;
    }
    violations.push(violation);
  }
  const wouldBlock = violations.length > 0;
  return {
    action: actionFor(policy.mode, wouldBlock),
    mode: policy.mode,
    wouldBlock,
    violations,
    allowed,
    reason: reasonFor(policy.mode, violations, allowed),
  };
}

function actionFor(mode: GuardMode, wouldBlock: boolean): 'allow' | 'block' {
  switch (mode) {
    case 'monitor':
      return 'allow';
    case 'enforce':
      return wouldBlock ? 'block' : 'allow';
    default: {
      const _never: never = mode;
      return _never;
    }
  }
}

function reasonFor(
  mode: GuardMode,
  violations: Violation[],
  allowed: SuppressedViolation[],
): string {
  if (violations.length === 0 && allowed.length === 0) return 'ironheights: allowed';
  if (violations.length === 0) {
    const ids = allowed.map((item) => item.allowId).join(', ');
    return clip(`ironheights: allowed by policy (${ids})`, MAX_REASON);
  }
  const details = violations.map((item) => `${item.ruleId}: ${item.message}`).join(' ');
  const prefix =
    mode === 'enforce'
      ? 'ironheights: blocked in enforce.'
      : 'ironheights: would block in enforce.';
  const suffix =
    mode === 'enforce'
      ? 'Approve a specific case by adding an allow entry with a reason to the guard policy. The guard returned a block.'
      : 'Monitor mode only recorded this call. Add an allow entry with a reason before switching to enforce.';
  return clip(redactSecrets(`${prefix} ${details} ${suffix}`), MAX_REASON);
}

function allowMatches(
  entry: GuardAllow,
  violation: Violation,
  call: ToolCall,
  policy: ResolvedGuardPolicy,
): boolean {
  if (entry.rule && entry.rule !== violation.ruleId) return false;
  if (entry.tool && entry.tool !== call.toolName) return false;
  if (entry.skill && entry.skill !== call.skill) return false;
  if (entry.host) {
    if (!violation.host || !hostAllowed(violation.host, [entry.host])) return false;
  }
  if (entry.path) {
    if (!violation.path || !pathMatches(entry.path, violation.path, policy)) return false;
  }
  return true;
}

function pathMatches(glob: string, full: string, policy: ResolvedGuardPolicy): boolean {
  let matcher: (value: string) => boolean;
  try {
    matcher = picomatch(glob, { dot: true });
  } catch {
    return false;
  }
  const candidates = [full];
  const home = policy.homeDir.replace(/\\/g, '/').replace(/\/$/, '');
  if (home && full.startsWith(`${home}/`)) candidates.push(full.slice(home.length + 1));
  if (full.startsWith('/')) candidates.push(full.slice(1));
  return candidates.some((candidate) => {
    try {
      return matcher(candidate);
    } catch {
      return false;
    }
  });
}
