import { loadConfig } from '../core/config.ts';
import { compareSeverity } from '../core/verdict.ts';
import { hostAllowed } from '../rules/network.ts';
import { normalizeForCompare, homeDirectory } from '../util/paths.ts';
import { sep } from 'node:path';
import { DEFAULT_GUARD_PRIORITY } from '../guard/priority.ts';
import { resolveToken, type Detection } from './detect.ts';
import { KNOWN_TOOLS } from './registry.ts';
import type { CoexistFinding, DetectedTool } from './types.ts';

export interface ConflictOptions {
  env?: NodeJS.ProcessEnv;
  /** Ironheights config file for the false-trust check. */
  config?: string;
}

const PRIORITY_FACT =
  'OpenClaw runs higher priorities first (default 0) and `block: true` stops lower-priority handlers, so the guard with the higher priority decides and the other does not see that call.';

export async function analyzeConflicts(
  detection: Detection,
  options: ConflictOptions = {},
): Promise<CoexistFinding[]> {
  const env = options.env ?? process.env;
  const active = detection.tools.filter((tool) => tool.status !== 'disabled');
  const findings: CoexistFinding[] = [];
  const push = (finding: CoexistFinding | undefined): void => {
    if (finding) findings.push(finding);
  };
  push(duplicateGuards(detection, active));
  push(guardBlocksOthers(detection, active));
  push(overlappingOwners(detection, active));
  push(configRewriters(active));
  push(pathCollisions(detection, active, env));
  push(networkOverlap(active));
  push(scheduledScans(active));
  push(instructionOverlap(active));
  push(trafficProxy(detection, active));
  push(await falseTrust(options));
  push(pluginAllowlist(detection));
  return findings.sort(
    (a, b) => compareSeverity(a.severity, b.severity) || a.id.localeCompare(b.id),
  );
}

function names(tools: DetectedTool[]): string {
  return tools.map((tool) => tool.name).join(', ');
}

function duplicateGuards(detection: Detection, active: DetectedTool[]): CoexistFinding | undefined {
  const self = detection.self;
  if (self.pluginEnabled !== true) return undefined;
  const others = active.filter(
    (tool) =>
      tool.registersBeforeToolCall === 'yes' ||
      (tool.registersBeforeToolCall === 'unknown' &&
        tool.kind === 'runtime-guard' &&
        tool.confidence !== 'low'),
  );
  if (others.length === 0) return undefined;
  const oursBlocks = self.mode === 'enforce';
  const theirsBlock = others.some((tool) => tool.canBlock !== 'no');
  const theirsSure = others.some((tool) => tool.canBlock === 'yes');
  const severity = oursBlocks && theirsBlock ? 'medium' : theirsSure ? 'low' : 'info';
  const uncertain = others.filter((tool) => tool.registersBeforeToolCall !== 'yes');
  const detail = [
    `Ironheights guard is enabled (mode ${self.mode}, priority ${self.priority}) and ${names(others)} ${others.length === 1 ? 'also guards' : 'also guard'} tool calls.`,
    PRIORITY_FACT,
    oursBlocks && theirsBlock
      ? 'Both can block. You may see two different block reasons, and each audit log is missing the calls the other blocked first.'
      : oursBlocks
        ? 'Only Ironheights can block, so nothing doubles up, but the other guard may log fewer calls.'
        : 'Ironheights only logs in monitor mode, so it never adds a block.',
    uncertain.length > 0
      ? `For ${names(uncertain)} it is not known from files whether the hook is registered or what mode it runs in.`
      : '',
  ]
    .filter(Boolean)
    .join(' ');
  return {
    id: 'IH-COEX-001',
    class: 'two-tool-call-guards',
    severity,
    title: 'More than one tool-call guard is active',
    detail,
    tools: others.map((tool) => tool.id),
    fix: [
      'Pick one tool to own blocking. Keep Ironheights in monitor mode (the default) if the other guard enforces.',
      `Ironheights priority is ${self.priority}${self.priority === DEFAULT_GUARD_PRIORITY ? ', the default' : ` (default ${DEFAULT_GUARD_PRIORITY})`}. Set plugins.entries.ironheights-guard.config.priority only if you need a different order.`,
      "Run `ironheights guard log` and the other tool's log side by side after a test call to confirm each sees what you expect.",
    ],
    snippet: oursBlocks
      ? '{ plugins: { entries: { "ironheights-guard": { enabled: true, config: { mode: "monitor" } } } } }'
      : undefined,
  };
}

function guardBlocksOthers(
  detection: Detection,
  active: DetectedTool[],
): CoexistFinding | undefined {
  const self = detection.self;
  if (self.pluginEnabled !== true) return undefined;
  const netTools = active.filter((tool) =>
    (tool.traits.hosts ?? []).some((host) => !hostAllowed(host, self.effectiveAllowDomains)),
  );
  const writeTools = active.filter(
    (tool) => tool.traits.writesSkillDirs === true || tool.traits.restoresFiles === true,
  );
  if (netTools.length === 0 && writeTools.length === 0) return undefined;
  const enforcing = self.mode === 'enforce';
  const hostList = [
    ...new Set(
      netTools.flatMap((tool) =>
        (tool.traits.hosts ?? []).filter((host) => !hostAllowed(host, self.effectiveAllowDomains)),
      ),
    ),
  ];
  const parts: string[] = [];
  if (netTools.length > 0) {
    parts.push(
      `${names(netTools)} contact${netTools.length === 1 ? 's' : ''} ${hostList.join(', ')}, which is not on the Ironheights guard allowlist (IH-GUARD-NET).`,
    );
  }
  if (writeTools.length > 0) {
    parts.push(
      `${names(writeTools)} write${writeTools.length === 1 ? 's' : ''} or restore${writeTools.length === 1 ? 's' : ''} skill folders or agent identity files (IH-GUARD-WRITE).`,
    );
  }
  parts.push(
    enforcing
      ? 'In enforce mode the guard blocks those calls.'
      : 'In monitor mode these calls are only logged as would-block. They would be blocked in enforce mode.',
  );
  const snippetParts: string[] = [];
  if (hostList.length > 0) {
    snippetParts.push(
      `{ "version": 1, "allowDomains": [${hostList.map((h) => JSON.stringify(h)).join(', ')}] }`,
    );
  }
  if (writeTools.length > 0) {
    snippetParts.push(
      '{ "id": "allow-<tool>-restore", "rule": "IH-GUARD-WRITE", "path": "<the exact file or folder>", "reason": "<tool> restores this on purpose" }',
    );
  }
  return {
    id: 'IH-COEX-002',
    class: 'guard-blocks-other-tool',
    severity: enforcing ? 'medium' : 'info',
    title: 'The Ironheights guard may block another security tool',
    detail: parts.join(' '),
    tools: [...new Set([...netTools, ...writeTools].map((tool) => tool.id))],
    fix: [
      'Keep the guard in monitor mode while both tools run, or add an allow entry for the exact host or path with a reason.',
      'An allowDomains entry is global: any tool call may then reach that host. Remove it when you remove the tool. Ironheights never adds it for you.',
      'Do not allow by skill name. A tool call can claim any skill name.',
    ],
    snippet: snippetParts.join('\n'),
  };
}

function overlappingOwners(
  detection: Detection,
  active: DetectedTool[],
): CoexistFinding | undefined {
  const owners = active.filter((tool) => tool.traits.restoresFiles === true);
  if (owners.length === 0) return undefined;
  const baseline = detection.self.baselineExists;
  return {
    id: 'IH-COEX-003',
    class: 'two-owners-of-files',
    severity: baseline ? 'medium' : 'info',
    title: 'Another tool restores or removes files Ironheights watches',
    detail: [
      `${names(owners)} can restore or remove agent files or skills on its own.`,
      baseline
        ? 'An Ironheights baseline exists, so a restore will show up as drift in `ironheights verify`, and an update you accept may be reverted by the other tool.'
        : 'No Ironheights baseline exists yet. If you create one, a restore by the other tool will show up as drift in `ironheights verify`.',
    ].join(' '),
    tools: owners.map((tool) => tool.id),
    fix: [
      'Let one tool own each set of files. For example, Ironheights baseline for skills and the other tool for SOUL.md and AGENTS.md.',
      'After either tool changes files on purpose, re-run `ironheights baseline create`.',
      'Do not run two tools that auto-remove skills on a finding against the same skills folder.',
    ],
  };
}

function configRewriters(active: DetectedTool[]): CoexistFinding | undefined {
  const writers = active.filter((tool) => tool.traits.writesConfig === true);
  if (writers.length === 0) return undefined;
  return {
    id: 'IH-COEX-004',
    class: 'config-rewriting',
    severity: 'low',
    title: 'Another tool can rewrite OpenClaw config or file permissions',
    detail: `${names(writers)} can change OpenClaw config, policy files or file permissions. Ironheights never writes openclaw.json. It writes only under its own home folder, plus skills you install with safe-install and folders you move with quarantine.`,
    tools: writers.map((tool) => tool.id),
    fix: [
      'Keep a copy of openclaw.json before running a hardening or --fix mode.',
      'Run `ironheights audit-config` afterwards and check that plugins.entries.ironheights-guard is still enabled.',
      'Run one such tool at a time.',
    ],
  };
}

function overlaps(a: string, b: string): boolean {
  const x = normalizeForCompare(a);
  const y = normalizeForCompare(b);
  if (x === y) return true;
  const xs = x.endsWith(sep) ? x : `${x}${sep}`;
  const ys = y.endsWith(sep) ? y : `${y}${sep}`;
  return xs.startsWith(ys) || ys.startsWith(xs);
}

function pathCollisions(
  detection: Detection,
  active: DetectedTool[],
  env: NodeJS.ProcessEnv,
): CoexistFinding | undefined {
  const home = homeDirectory(env);
  const ours = [detection.self.home, detection.self.policyPath, detection.self.logPath];
  const theirs: Array<{ tool: string; path: string }> = [];
  for (const tool of active) {
    const known = KNOWN_TOOLS.find((item) => item.id === tool.id);
    for (const raw of known?.match.statePaths ?? []) {
      theirs.push({ tool: tool.name, path: resolveToken(raw, detection.located.stateDir, home) });
    }
    for (const item of tool.evidence) {
      if (item.path && (item.kind === 'plugin-manifest' || item.kind === 'state-path')) {
        theirs.push({ tool: tool.name, path: item.path });
      }
    }
  }
  const clashes: string[] = [];
  const clashTools = new Set<string>();
  for (const mine of ours) {
    for (const other of theirs) {
      if (overlaps(mine, other.path)) {
        clashes.push(`${mine} and ${other.path} (${other.tool})`);
        clashTools.add(other.tool);
      }
    }
  }
  const insideState = overlaps(detection.self.home, detection.located.stateDir);
  if (clashes.length === 0 && !insideState) return undefined;
  const lines = [...new Set(clashes)];
  if (insideState && clashes.length === 0) {
    lines.push(
      `${detection.self.home} is inside or contains the OpenClaw state folder ${detection.located.stateDir}`,
    );
  }
  return {
    id: 'IH-COEX-005',
    class: 'shared-state-paths',
    severity: 'medium',
    title: 'Ironheights files share a folder with another tool',
    detail: `Overlap: ${lines.join('; ')}. Generic file names such as guard.log.jsonl and baseline.json can then collide with other tools or be cleaned up by them.`,
    tools: tools(active, clashTools),
    fix: [
      'Unset IRONHEIGHTS_HOME or point it at a folder only Ironheights uses, for example ~/.ironheights.',
      "Move the guard policy and log paths out of the other tool's folder.",
    ],
  };
}

function tools(active: DetectedTool[], displayNames: Set<string>): string[] {
  return active.filter((tool) => displayNames.has(tool.name)).map((tool) => tool.id);
}

function networkOverlap(active: DetectedTool[]): CoexistFinding | undefined {
  const net = active.filter(
    (tool) => (tool.traits.hosts ?? []).length > 0 || tool.traits.uploadsContent === true,
  );
  if (net.length === 0) return undefined;
  const uploaders = net.filter((tool) => tool.traits.uploadsContent === true);
  const hosts = [...new Set(net.flatMap((tool) => tool.traits.hosts ?? []))];
  return {
    id: 'IH-COEX-006',
    class: 'double-network-use',
    severity: 'info',
    title: 'Other tools use the network or a vendor service',
    detail: [
      `${names(net)} ${net.length === 1 ? 'uses' : 'use'} the network${hosts.length > 0 ? ` (${hosts.join(', ')})` : ''}.`,
      uploaders.length > 0
        ? `${names(uploaders)} can send skill content to a vendor service. Ironheights does not: it sends nothing unless you run fetch, safe-install, advisories update, --online, or --llm with a remote server.`
        : '',
      'Running fetch or safe-install next to a tool that also downloads from ClawHub makes two downloads of the same skill, and can hit rate limits.',
    ]
      .filter(Boolean)
      .join(' '),
    tools: net.map((tool) => tool.id),
    fix: [
      'Let one tool download. Use `ironheights fetch` or `safe-install` for the download, or scan the files the other tool already staged.',
      'If a tool uploads skill content and you need that to stay local, check its settings for an offline switch.',
    ],
  };
}

function scheduledScans(active: DetectedTool[]): CoexistFinding | undefined {
  const scheduled = active.filter((tool) => tool.traits.schedules === true);
  if (scheduled.length === 0) return undefined;
  return {
    id: 'IH-COEX-007',
    class: 'scheduled-scans',
    severity: 'info',
    title: 'Other tools run on a schedule',
    detail: `${names(scheduled)} ${scheduled.length === 1 ? 'is' : 'are'} known to run scans or checks on a schedule. Cron jobs and timers are not read, so this is based on the tool's documentation.`,
    tools: scheduled.map((tool) => tool.id),
    fix: [
      "If you schedule `ironheights scan --all`, pick a minute that is not on the hour and not the other tool's time.",
      "Check the other tool's docs for its schedule.",
    ],
  };
}

function instructionOverlap(active: DetectedTool[]): CoexistFinding | undefined {
  const skills = active.filter(
    (tool) =>
      (tool.kind === 'instruction-skill' ||
        tool.kind === 'skill-scanner' ||
        tool.kind === 'cloud-lookup') &&
      tool.evidence.some((item) => item.kind === 'skill-dir' || item.kind === 'skill-name'),
  );
  const imperative = skills.filter((tool) => tool.traits.imperativeActivation === true);
  if (skills.length < 2 && imperative.length === 0) return undefined;
  return {
    id: 'IH-COEX-008',
    class: 'instruction-overlap',
    severity: 'low',
    title: 'Several skills tell the agent to scan or vet installs',
    detail: [
      `${names(skills)} ${skills.length === 1 ? 'is a skill that instructs' : 'are skills that instruct'} the agent to check skills.`,
      imperative.length > 0
        ? `${names(imperative)} tells the agent to scan every install with no exceptions.`
        : '',
      'The agent may run each of them, get different answers, and pick one. An instruction in a skill is advice to the model, not enforcement.',
    ]
      .filter(Boolean)
      .join(' '),
    tools: skills.map((tool) => tool.id),
    fix: [
      'Decide which verdict wins. A deterministic result such as `ironheights safe-install` should outrank a checklist the model applies.',
      'Remove skills that duplicate each other.',
    ],
  };
}

function trafficProxy(detection: Detection, active: DetectedTool[]): CoexistFinding | undefined {
  const proxyTool = active.filter((tool) => tool.traits.interceptsTraffic === true);
  if (proxyTool.length === 0 && detection.proxyEnv.length === 0) return undefined;
  return {
    id: 'IH-COEX-009',
    class: 'traffic-intercepting-proxy',
    severity: 'info',
    title: 'A local proxy may sit between the agent and the network',
    detail: [
      proxyTool.length > 0 ? `${names(proxyTool)} runs a local proxy.` : '',
      detection.proxyEnv.length > 0 ? `Proxy variables set: ${detection.proxyEnv.join(', ')}.` : '',
      "Ironheights network commands use Node's built-in fetch, which does not read HTTP_PROXY or HTTPS_PROXY unless NODE_USE_ENV_PROXY is set, so they do not go through the proxy and the proxy does not see them. A proxy that installs its own root certificate can also make other HTTPS clients fail.",
    ]
      .filter(Boolean)
      .join(' '),
    tools: proxyTool.map((tool) => tool.id),
    fix: [
      'If you want Ironheights traffic inspected by the proxy, set NODE_USE_ENV_PROXY=1 when you run fetch, safe-install, or advisories update.',
      'If a download fails with a certificate error, run it without the proxy variables.',
    ],
  };
}

async function falseTrust(options: ConflictOptions): Promise<CoexistFinding | undefined> {
  let config;
  try {
    config = await loadConfig({
      ...(options.config ? { explicitPath: options.config } : {}),
      ...(options.env ? { env: options.env } : {}),
    });
  } catch {
    return undefined;
  }
  const slugs = new Map<string, string>();
  for (const tool of KNOWN_TOOLS) {
    for (const slug of tool.match.skillSlugs ?? []) slugs.set(slug, tool.name);
  }
  const hits: string[] = [];
  const check = (label: string, value: string | undefined): void => {
    if (!value) return;
    const segments = value
      .toLowerCase()
      .split(/[\\/*?{}[\],!]+/)
      .filter(Boolean);
    for (const segment of segments) {
      const name = slugs.get(segment);
      if (name) {
        hits.push(`${label} "${value}" names ${name}`);
        return;
      }
    }
  };
  for (const glob of config.ignoreGlobs) check('ignoreGlobs', glob);
  for (const dir of config.ignoreDirs) check('ignoreDirs', dir.path);
  for (const item of config.suppressions) check('suppressions', item.path);
  if (hits.length === 0) return undefined;
  return {
    id: 'IH-COEX-010',
    class: 'false-trust',
    severity: 'medium',
    title: "Your Ironheights config exempts a path by a security tool's name",
    detail: `${hits.join('; ')}. A folder can be given any name, so a malicious skill named like a security tool would be skipped or silenced too. Ironheights does not exempt tools by name on its own.`,
    tools: [],
    fix: [
      'Scan the tool, read the findings, and suppress only the specific rule, file and line with a reason.',
      'Run `ironheights baseline create` so later changes to the tool show up in `verify`.',
      'Remove the broad ignore.',
    ],
  };
}

function pluginAllowlist(detection: Detection): CoexistFinding | undefined {
  const self = detection.self;
  if (self.pluginEnabled !== true) return undefined;
  if (self.pluginListedInAllow !== false && !self.pluginDenied) return undefined;
  const reason = self.pluginDenied
    ? 'plugins.deny lists ironheights-guard'
    : 'plugins.allow is set and does not list ironheights-guard';
  return {
    id: 'IH-COEX-011',
    class: 'plugin-allowlist',
    severity: 'low',
    title: 'The Ironheights guard is enabled but OpenClaw may not load it',
    detail: `${reason}. OpenClaw applies plugins.allow and plugins.deny on top of plugins.entries, so the guard would not run. A security plugin install that sets plugins.allow can cause this.`,
    tools: [],
    fix: [
      self.pluginDenied
        ? 'Remove ironheights-guard from plugins.deny.'
        : 'Add "ironheights-guard" to plugins.allow.',
      'Run `openclaw plugins inspect ironheights-guard --runtime --json` to confirm it loads.',
    ],
    snippet: self.pluginDenied
      ? undefined
      : '{ plugins: { allow: [/* existing ids */ "ironheights-guard"] } }',
  };
}
