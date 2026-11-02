/**
 * Opt-in canary-secret sandbox run (`scan --canary`). Off by default.
 *
 * From the Moltbook brainstorm (post c6a97aba), bots rossum and sevana-agent:
 * detection by reading the text misses what a skill actually does when it runs.
 * This stage plants a fake secret, runs the skill's declared setup/bootstrap
 * script once inside a locked-down sandbox, and flags the skill only if the
 * canary secret MOVES - it is written to a file outside the sandbox skill dir,
 * printed to stdout/stderr, or the run tries to reach the network at all while
 * the canary is in its environment.
 *
 * Safety: the script runs with a throwaway HOME, a scrubbed environment, and no
 * network namespace (`unshare -rn`, or `bwrap --unshare-all`). If neither
 * isolation tool is present, the run is SKIPPED, never executed unsandboxed.
 * This stage can only escalate a verdict (to review), never lower it, and never
 * prints the canary value itself.
 *
 * False positives: a script that legitimately echoes its whole environment, or
 * writes an env dump into a log inside a shared temp dir, will trip the canary.
 * Measured FP rate on benign script fixtures is reported in v030/RESULTS.md; do
 * not treat a single canary hit as proof of malice without reading the evidence.
 */
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readdirSync,
  readFileSync,
  statSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const CANARY_PREFIX = 'ih-canary-';

export interface CanaryResult {
  ran: boolean;
  skippedReason?: string;
  moved: boolean;
  /** where the canary surfaced, with the value itself redacted */
  evidence: string[];
  exitCode?: number;
  timedOut?: boolean;
}

/** A fresh, unguessable canary value. Never logged. */
export function makeCanary(rand: () => string = defaultRand): string {
  return `${CANARY_PREFIX}${rand()}`;
}
function defaultRand(): string {
  return randomBytes(16).toString('hex');
}

/** Which isolation tool is available, strongest first. */
export function sandboxCommand(): { tool: 'bwrap' | 'unshare' } | undefined {
  if (spawnSync('bwrap', ['--version'], { encoding: 'utf8' }).status === 0)
    return { tool: 'bwrap' };
  if (spawnSync('unshare', ['-rn', 'true'], { encoding: 'utf8' }).status === 0)
    return { tool: 'unshare' };
  return undefined;
}

/**
 * Build the argv prefix that runs `inner` with no network and a minimal, read-only
 * system, binding only the throwaway HOME, the outside temp dir and the skill root.
 */
export function sandboxArgv(
  tool: 'bwrap' | 'unshare',
  dirs: { home: string; outside: string; skillRoot: string },
): string[] {
  if (tool === 'bwrap') {
    const roBinds: string[] = [];
    for (const path of ['/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc']) {
      roBinds.push('--ro-bind-try', path, path);
    }
    return [
      'bwrap',
      '--unshare-all',
      '--die-with-parent',
      '--new-session',
      ...roBinds,
      '--proc',
      '/proc',
      '--dev',
      '/dev',
      '--tmpfs',
      '/tmp',
      '--bind',
      dirs.home,
      dirs.home,
      '--bind',
      dirs.outside,
      dirs.outside,
      '--bind',
      dirs.skillRoot,
      dirs.skillRoot,
      '--chdir',
      dirs.skillRoot,
    ];
  }
  // unshare shares the host filesystem (only the net namespace is new).
  return ['unshare', '-rn', '--'];
}

/** The script a skill declares as its mandatory setup/bootstrap step, if any. */
export function declaredSetupScript(skillText: string, files: string[]): string | undefined {
  const m =
    /`?(?:python3?|bash|sh|node|uv\s+run)\s+((?:\{baseDir\}\/|\.\/)?(?:scripts?\/)?_?[\w-]+\.(?:py|sh|js|mjs))`?/i.exec(
      skillText,
    );
  const named = m?.[1]?.replace('{baseDir}/', '').replace('./', '');
  if (named && files.some((f) => f.endsWith(named) || f.endsWith(named.split('/').pop() ?? ''))) {
    return files.find((f) => f.endsWith(named) || f.endsWith(named.split('/').pop() ?? ''));
  }
  // fall back to a conventional setup/bootstrap helper
  return files.find((f) =>
    /(?:_?(?:bootstrap|setup|dep[s_]|init|warmup|register|preflight)[\w-]*)\.(?:py|sh|js)$/i.test(
      f,
    ),
  );
}

function interpreterFor(path: string): string[] | undefined {
  if (path.endsWith('.py')) return ['python3', path];
  if (path.endsWith('.sh')) return ['bash', path];
  if (path.endsWith('.js') || path.endsWith('.mjs')) return ['node', path];
  return undefined;
}

/** List files under dir, recursively, returning absolute paths. */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else if (entry.isFile()) out.push(p);
  }
  return out;
}

export interface RunOptions {
  skillRoot: string;
  skillText: string;
  files: string[];
  timeoutMs?: number;
  canary?: string;
}

/**
 * Run the skill's setup script once in the sandbox with a planted canary.
 * Pure detection of movement; the canary value itself is never returned.
 */
export function canaryRun(opts: RunOptions): CanaryResult {
  const sandbox = sandboxCommand();
  if (!sandbox) {
    return {
      ran: false,
      skippedReason: 'no sandbox (bwrap/unshare) available; skill not executed',
      moved: false,
      evidence: [],
    };
  }
  const script = declaredSetupScript(opts.skillText, opts.files);
  if (!script) {
    return {
      ran: false,
      skippedReason: 'no setup/bootstrap script to run',
      moved: false,
      evidence: [],
    };
  }
  const interp = interpreterFor(script);
  if (!interp) {
    return { ran: false, skippedReason: 'unknown script type', moved: false, evidence: [] };
  }
  const canary = opts.canary ?? makeCanary();
  const home = mkdtempSync(join(tmpdir(), 'ih-canary-home-'));
  const outside = mkdtempSync(join(tmpdir(), 'ih-canary-out-'));
  try {
    // Plant the canary in the places a skill might read a secret from.
    mkdirSync(join(home, '.ssh'), { recursive: true });
    writeFileSync(join(home, '.ssh', 'id_rsa'), `${canary}\n`);
    writeFileSync(join(home, '.env'), `API_KEY=${canary}\nTOKEN=${canary}\n`);
    mkdirSync(join(home, '.aws'), { recursive: true });
    writeFileSync(
      join(home, '.aws', 'credentials'),
      `[default]\naws_secret_access_key=${canary}\n`,
    );

    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: home,
      TMPDIR: outside,
      API_KEY: canary,
      TOKEN: canary,
      SECRET: canary,
    };
    const argv = [
      ...sandboxArgv(sandbox.tool, { home, outside, skillRoot: opts.skillRoot }),
      ...interp,
    ];
    const res = spawnSync(argv[0] as string, argv.slice(1), {
      cwd: opts.skillRoot,
      env,
      encoding: 'utf8',
      timeout: opts.timeoutMs ?? 10_000,
      maxBuffer: 4 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const evidence: string[] = [];
    const stdout = res.stdout ?? '';
    const stderr = res.stderr ?? '';
    if (stdout.includes(canary)) evidence.push('canary value printed to stdout');
    if (stderr.includes(canary)) evidence.push('canary value printed to stderr');
    // Any file the run wrote outside the skill dir that carries the canary.
    for (const dir of [outside, home]) {
      for (const f of walk(dir)) {
        // skip the planted files themselves
        if (/\.ssh\/id_rsa$|\/\.env$|\.aws\/credentials$/.test(f)) continue;
        try {
          if (statSync(f).size > 2 * 1024 * 1024) continue;
          if (readFileSync(f, 'utf8').includes(canary)) {
            evidence.push('canary value written to a file outside the skill directory');
            break;
          }
        } catch {
          /* unreadable file */
        }
      }
    }
    // A network attempt while the canary is in scope: with the net namespace
    // unshared, any connect() fails, which the script usually reports.
    if (
      /network|connect|refused|unreachable|getaddrinfo|ECONNREFUSED|ENETUNREACH|socket|resolve/i.test(
        stderr,
      )
    ) {
      evidence.push('run attempted a network connection with the canary in its environment');
    }
    return {
      ran: true,
      moved: evidence.length > 0,
      evidence,
      exitCode: res.status ?? undefined,
      timedOut:
        res.signal === 'SIGTERM' && res.error?.message?.includes('ETIMEDOUT') ? true : undefined,
    };
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
}

import type { Finding, SkillReport } from '../core/types.ts';
import { readFileSync as _rfs } from 'node:fs';
import { join as _join } from 'node:path';

export const CANARY_RULE_ID = 'IH-CANARY-001';

/** Run the canary on one skill and, if the secret moved, add a review finding. */
export function applyCanary(
  skill: SkillReport,
  files: string[],
  skillText: string,
): {
  skill: SkillReport;
  result: CanaryResult;
} {
  const result = canaryRun({ skillRoot: skill.root, skillText, files });
  if (!result.ran || !result.moved) {
    return { skill, result };
  }
  const finding: Finding = {
    ruleId: CANARY_RULE_ID,
    severity: 'medium',
    confidence: 'high',
    file: 'SKILL.md',
    evidence: `canary run: ${result.evidence.join('; ')}`,
    message: `A planted canary secret moved when the skill's setup script ran in the sandbox: ${result.evidence.join('; ')}. The verdict is at least review. (The canary value is never printed.)`,
    remediation:
      'Read the setup script. A skill should not read planted credentials, print them, write them outside its own directory, or reach the network during setup. Remove the exfiltration, or suppress with a reason if the behaviour is understood and safe.',
  };
  return {
    skill: {
      ...skill,
      findings: [...skill.findings, finding],
      verdict: skill.verdict === 'block' ? 'block' : 'review',
    },
    result,
  };
}

/** Read a skill's SKILL.md text for the canary heuristics. */
export function readSkillText(root: string): string {
  for (const name of ['SKILL.md', 'skill.md']) {
    try {
      return _rfs(_join(root, name), 'utf8');
    } catch {
      /* try next */
    }
  }
  return '';
}
