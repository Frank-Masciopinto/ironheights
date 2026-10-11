/**
 * Known security tools. Facts come from public listings, repositories and
 * package files read on the dates in `observed`. A tool is listed only when
 * its public page or files were read. No entry is an allowlist: a match tells
 * `coexist` what to look for, and tells `scan` to add a note. It never lowers
 * a severity or a verdict.
 *
 * Path tokens: `{state}` is the OpenClaw state directory, `{home}` the user's
 * home directory.
 */

export type ToolKind =
  | 'runtime-guard'
  | 'skill-scanner'
  | 'instruction-skill'
  | 'config-auditor'
  | 'integrity-monitor'
  | 'cloud-lookup'
  | 'advisory-feed'
  | 'traffic-proxy'
  | 'secret-scanner';

export type Tri = 'yes' | 'no' | 'unknown';

export interface ToolTraits {
  /** Registers an OpenClaw `before_tool_call` hook. */
  beforeToolCall: Tri;
  /** Mode used when the OpenClaw config does not set one. */
  defaultMode?: string;
  /** Plugin config values that mean "never blocks". */
  nonBlockingModes?: string[];
  /** Restores or removes files on its own (identity files, skills). */
  restoresFiles?: boolean;
  /** Edits OpenClaw config or file permissions. */
  writesConfig?: boolean;
  /** Sends skill content to a vendor. */
  uploadsContent?: boolean;
  /** Runs on a schedule (cron, daily patrol). */
  schedules?: boolean;
  /** Skill text tells the agent to scan every install with no exceptions. */
  imperativeActivation?: boolean;
  /** Sits between the agent and the network. */
  interceptsTraffic?: boolean;
  /** Writes into skill folders or identity files while it works. */
  writesSkillDirs?: boolean;
  /** Hosts it contacts. Only hosts seen in its own files. */
  hosts?: string[];
}

export interface ToolMatch {
  /** Skill folder names or `SKILL.md` `name:` values, lower case. */
  skillSlugs?: string[];
  /** Plugin ids from `openclaw.plugin.json` or `plugins.entries`. */
  pluginIds?: string[];
  /** npm package names read from a plugin's `package.json`. */
  npmPackages?: string[];
  /** Internal hook folder names (`HOOK.md`). */
  hookNames?: string[];
  /** State paths that exist when the tool has run. */
  statePaths?: string[];
  /** Executable names looked up on PATH. Nothing is run. */
  bins?: string[];
  /** Text found in `.pre-commit-config.yaml`, workflows, or `.git/hooks/pre-commit`. */
  ciTokens?: string[];
  /** Text found in `mcp.servers` command or args. */
  mcpTokens?: string[];
}

export interface KnownTool {
  id: string;
  name: string;
  kind: ToolKind;
  match: ToolMatch;
  traits: ToolTraits;
  /** Public pages or files this entry was read from. */
  sources: string[];
  observed: string;
}

const OBSERVED = '2026-10-10';
const CH = 'https://clawhub.ai';

export const KNOWN_TOOLS: readonly KnownTool[] = [
  {
    id: 'guard-scanner',
    name: 'guard-scanner',
    kind: 'runtime-guard',
    match: {
      skillSlugs: ['guard-scanner'],
      pluginIds: ['guard-scanner'],
      npmPackages: ['@guava-parity/guard-scanner'],
      statePaths: ['{state}/guard-scanner'],
      mcpTokens: ['@guava-parity/guard-scanner'],
    },
    traits: {
      beforeToolCall: 'yes',
      defaultMode: 'enforce',
      nonBlockingModes: ['monitor'],
    },
    sources: [
      `${CH}/koatora20/skills/guard-scanner`,
      'plugin manifest openclaw.plugin.json in the listing: mode monitor|enforce|strict, default enforce, audit log ~/.openclaw/guard-scanner/audit.jsonl',
    ],
    observed: OBSERVED,
  },
  {
    id: 'agentguard',
    name: 'GoPlus AgentGuard',
    kind: 'runtime-guard',
    match: {
      skillSlugs: ['agentguard'],
      npmPackages: ['@goplus/agentguard'],
      statePaths: ['{home}/.agentguard'],
      bins: ['agentguard'],
      mcpTokens: ['@goplus/agentguard', 'agentguard-mcp'],
    },
    traits: { beforeToolCall: 'unknown', schedules: true },
    sources: [
      `${CH}/0xbeekeeper/skills/security`,
      'https://github.com/GoPlusSecurity/agentguard',
      'package.json: bin agentguard, agentguard-mcp; openclaw.extensions ./dist/openclaw.js',
      'SKILL.md: audit.jsonl and config.json under ~/.agentguard/, daily patrol',
    ],
    observed: OBSERVED,
  },
  {
    id: 'moltguard',
    name: 'MoltGuard (OpenGuardrails)',
    kind: 'runtime-guard',
    match: {
      skillSlugs: ['moltguard'],
      pluginIds: ['moltguard'],
      npmPackages: ['@openguardrails/moltguard'],
      statePaths: ['{state}/credentials/moltguard'],
    },
    traits: { beforeToolCall: 'unknown', uploadsContent: true },
    sources: [
      `${CH}/thomaslwang/skills/moltguard`,
      'https://github.com/openguardrails/openguardrails',
      'SKILL.md: openclaw plugins install @openguardrails/moltguard, ~/.openclaw/extensions/moltguard, detection performed by a hosted Core with an API key',
    ],
    observed: OBSERVED,
  },
  {
    id: 'secureclaw',
    name: 'SecureClaw (Adversa AI)',
    kind: 'config-auditor',
    match: {
      skillSlugs: ['secureclaw', 'secureclaw-skill'],
      pluginIds: ['secureclaw'],
      statePaths: ['{state}/.secureclaw'],
    },
    traits: { beforeToolCall: 'unknown', writesConfig: true },
    sources: [
      `${CH}/adversa-ai/skills/secureclaw-skill`,
      'https://github.com/adversa-ai/secureclaw',
      'README: audit, automated hardening fixes with backup and rollback, plugin and skill layers',
    ],
    observed: OBSERVED,
  },
  {
    id: 'openclaw-shield',
    name: 'openclaw-shield',
    kind: 'runtime-guard',
    match: { skillSlugs: ['openclaw-shield'] },
    traits: { beforeToolCall: 'unknown' },
    sources: [`${CH}/pfaria32/skills/openclaw-shield`],
    observed: OBSERVED,
  },
  {
    id: 'clawsec-suite',
    name: 'ClawSec suite (Prompt Security)',
    kind: 'advisory-feed',
    match: {
      skillSlugs: ['clawsec-suite', 'clawsec-feed'],
      hookNames: ['clawsec-advisory-guardian'],
      statePaths: ['{state}/clawsec-suite-feed-state.json'],
    },
    traits: {
      beforeToolCall: 'no',
      schedules: true,
      writesSkillDirs: true,
      hosts: ['clawsec.prompt.security'],
    },
    sources: [
      `${CH}/davida-ps/skills/clawsec-suite`,
      'https://github.com/prompt-security/clawsec',
      'HOOK.md: internal hook on agent:bootstrap and command:new, state file ~/.openclaw/clawsec-suite-feed-state.json, optional openclaw cron, guarded installer uses npx clawhub',
    ],
    observed: OBSERVED,
  },
  {
    id: 'soul-guardian',
    name: 'soul-guardian (Prompt Security)',
    kind: 'integrity-monitor',
    match: { skillSlugs: ['soul-guardian'] },
    traits: { beforeToolCall: 'no', restoresFiles: true, schedules: true },
    sources: [
      `${CH}/davida-ps/skills/soul-guardian`,
      'listing: drift detection and auto-restore for SOUL.md, AGENTS.md and related files, launchd scheduling',
    ],
    observed: OBSERVED,
  },
  {
    id: 'openclaw-audit-watchdog',
    name: 'openclaw-audit-watchdog (Prompt Security)',
    kind: 'config-auditor',
    match: {
      skillSlugs: ['openclaw-audit-watchdog'],
      statePaths: ['{state}/security-audit.json'],
    },
    traits: { beforeToolCall: 'no', schedules: true },
    sources: [`${CH}/davida-ps/skills/openclaw-audit-watchdog`],
    observed: OBSERVED,
  },
  {
    id: 'clawsec-monitor',
    name: 'ClawSec Monitor (proxy)',
    kind: 'traffic-proxy',
    match: { skillSlugs: ['clawsec'] },
    traits: { beforeToolCall: 'no', interceptsTraffic: true },
    sources: [
      `${CH}/chrisochrisochriso-cmyk/skills/clawsec`,
      'skill.md: local HTTP/HTTPS proxy on port 8888, JSONL threat log',
    ],
    observed: OBSERVED,
  },
  {
    id: 'skill-vetter',
    name: 'skill-vetter',
    kind: 'instruction-skill',
    match: { skillSlugs: ['skill-vetter', 'skill-vetter-v2', 'skill-vetter-1-0-0'] },
    traits: { beforeToolCall: 'no' },
    sources: [`${CH}/spclaudehome/skills/skill-vetter`],
    observed: OBSERVED,
  },
  {
    id: 'openclaw-skill-vetter',
    name: 'openclaw-skill-vetter',
    kind: 'instruction-skill',
    match: { skillSlugs: ['openclaw-skill-vetter'] },
    traits: { beforeToolCall: 'no' },
    sources: [`${CH}/donovanpankratz-del/skills/openclaw-skill-vetter`],
    observed: OBSERVED,
  },
  {
    id: 'skill-vetting',
    name: 'skill-vetting',
    kind: 'skill-scanner',
    match: { skillSlugs: ['skill-vetting'] },
    traits: { beforeToolCall: 'no', hosts: ['clawhub.ai'] },
    sources: [`${CH}/eddygk/skills/skill-vetting`],
    observed: OBSERVED,
  },
  {
    id: 'skillscan',
    name: 'SkillScan (tokauth)',
    kind: 'skill-scanner',
    match: { skillSlugs: ['skillscan'] },
    traits: {
      beforeToolCall: 'no',
      uploadsContent: true,
      imperativeActivation: true,
      hosts: ['skillscan.tokauth.com'],
    },
    sources: [
      `${CH}/tokauthai/skills/skillscan`,
      'SKILL.md: "Every new skill MUST pass SkillScan before use ... No exceptions"; skill directory is uploaded to skillscan.tokauth.com',
    ],
    observed: OBSERVED,
  },
  {
    id: 'skill-guard',
    name: 'skill-guard (jamesouttake)',
    kind: 'skill-scanner',
    match: { skillSlugs: ['skill-guard'], bins: ['snyk-agent-scan'] },
    traits: {
      beforeToolCall: 'no',
      uploadsContent: true,
      restoresFiles: true,
      writesSkillDirs: true,
      hosts: ['clawhub.ai'],
    },
    sources: [
      `${CH}/jamesouttake/skills/skill-guard`,
      'SKILL.md: stages, scans with snyk-agent-scan via uvx, installs; keeps a backup and rolls back',
    ],
    observed: OBSERVED,
  },
  {
    id: 'skillvet',
    name: 'skillvet',
    kind: 'skill-scanner',
    match: { skillSlugs: ['skillvet'], ciTokens: ['skillvet'] },
    traits: {
      beforeToolCall: 'no',
      writesSkillDirs: true,
      restoresFiles: true,
      hosts: ['clawhub.ai'],
    },
    sources: [
      `${CH}/oakencore/skills/skillvet`,
      'SKILL.md: safe-install.sh and scan-remote.sh use the clawdhub CLI, pre-commit hook, safe-install removes a skill on a critical finding',
    ],
    observed: OBSERVED,
  },
  {
    id: 'clawdefender',
    name: 'clawdefender',
    kind: 'skill-scanner',
    match: { skillSlugs: ['clawdefender'] },
    traits: { beforeToolCall: 'no' },
    sources: [`${CH}/nukewire/skills/clawdefender`],
    observed: OBSERVED,
  },
  {
    id: 'yoder-skill-auditor',
    name: 'yoder-skill-auditor',
    kind: 'skill-scanner',
    match: { skillSlugs: ['yoder-skill-auditor'] },
    traits: { beforeToolCall: 'no' },
    sources: [`${CH}/yoder-bawt/skills/yoder-skill-auditor`],
    observed: OBSERVED,
  },
  {
    id: 'edgeone-clawscan',
    name: 'edgeone-clawscan (Tencent Zhuque Lab)',
    kind: 'skill-scanner',
    match: { skillSlugs: ['edgeone-clawscan'] },
    traits: { beforeToolCall: 'no', uploadsContent: true, hosts: ['matrix.tencent.com'] },
    sources: [
      `${CH}/aigsec/skills/edgeone-clawscan`,
      'SKILL.md: optional cloud lookup that can be switched off with AIG_CLOUD_LOOKUP=off',
    ],
    observed: OBSERVED,
  },
  {
    id: 'clawdex',
    name: 'clawdex (Koi)',
    kind: 'cloud-lookup',
    match: { skillSlugs: ['clawdex'] },
    traits: { beforeToolCall: 'no', hosts: ['clawdex.koi.security'] },
    sources: [
      `${CH}/wearekoi/skills/clawdex`,
      'SKILL.md: looks up a skill name at clawdex.koi.security',
    ],
    observed: OBSERVED,
  },
  {
    id: 'skillscanner-gendigital',
    name: 'skillscanner (Gen Digital)',
    kind: 'cloud-lookup',
    match: { skillSlugs: ['skillscanner'] },
    traits: { beforeToolCall: 'no', hosts: ['ai.gendigital.com'] },
    sources: [
      `${CH}/rexshang/skills/skillscanner`,
      'SKILL.md: POSTs a skill URL to ai.gendigital.com',
    ],
    observed: OBSERVED,
  },
  {
    id: 'moltthreats',
    name: 'moltthreats (PromptIntel)',
    kind: 'advisory-feed',
    match: { skillSlugs: ['moltthreats'] },
    traits: {
      beforeToolCall: 'no',
      writesConfig: true,
      hosts: ['api.promptintel.novahunting.ai'],
    },
    sources: [
      `${CH}/fr0gger/skills/moltthreats`,
      'SKILL.md: fetches a threat feed and writes a local SHIELD.md policy',
    ],
    observed: OBSERVED,
  },
  {
    id: 'safe-exec',
    name: 'safe-exec',
    kind: 'runtime-guard',
    match: {
      skillSlugs: ['safe-exec'],
      statePaths: ['{state}/safe-exec-audit.log', '{state}/safe-exec-rules.json'],
      bins: ['safe-exec'],
    },
    traits: { beforeToolCall: 'no' },
    sources: [
      `${CH}/ottttto/skills/safe-exec`,
      'SKILL.md: wrapper script, audit log ~/.openclaw/safe-exec-audit.log, rules ~/.openclaw/safe-exec-rules.json',
    ],
    observed: OBSERVED,
  },
  {
    id: 'security-audit',
    name: 'security-audit (chandrasekar-r)',
    kind: 'config-auditor',
    match: { skillSlugs: ['security-audit'] },
    traits: { beforeToolCall: 'no', writesConfig: true },
    sources: [
      `${CH}/chandrasekar-r/skills/security-audit`,
      'listing: --fix mode changes file permissions and creates .gitignore',
    ],
    observed: OBSERVED,
  },
  {
    id: 'clawseccheck',
    name: 'clawseccheck',
    kind: 'config-auditor',
    match: { skillSlugs: ['clawseccheck'] },
    traits: { beforeToolCall: 'no' },
    sources: [`${CH}/gl0di/skills/clawseccheck`],
    observed: OBSERVED,
  },
  {
    id: 'prompt-guard',
    name: 'prompt-guard',
    kind: 'instruction-skill',
    match: { skillSlugs: ['prompt-guard'] },
    traits: { beforeToolCall: 'no' },
    sources: [`${CH}/seojoonkim/skills/prompt-guard`],
    observed: OBSERVED,
  },
  {
    id: 'security-sentinel',
    name: 'security-sentinel',
    kind: 'instruction-skill',
    match: { skillSlugs: ['security-sentinel', 'security-sentinel-skill'] },
    traits: { beforeToolCall: 'no' },
    sources: [`${CH}/georges91560/skills/security-sentinel-skill`],
    observed: OBSERVED,
  },
  {
    id: 'cisco-skill-scanner',
    name: 'Cisco skill-scanner',
    kind: 'skill-scanner',
    match: {
      bins: ['skill-scanner', 'skill-scanner-pre-commit'],
      ciTokens: ['skill-scanner', 'cisco-ai-defense/skill-scanner'],
    },
    traits: { beforeToolCall: 'no' },
    sources: [
      'https://github.com/cisco-ai-defense/skill-scanner',
      'pyproject.toml: package cisco-ai-skill-scanner, scripts skill-scanner, skill-scanner-api, skill-scanner-pre-commit',
    ],
    observed: OBSERVED,
  },
  {
    id: 'snyk-agent-scan',
    name: 'Snyk agent-scan',
    kind: 'skill-scanner',
    match: {
      bins: ['snyk-agent-scan'],
      ciTokens: ['snyk-agent-scan'],
      mcpTokens: ['snyk-agent-scan'],
    },
    traits: { beforeToolCall: 'no', uploadsContent: true },
    sources: [
      'https://github.com/snyk/agent-scan',
      'README: run with uvx snyk-agent-scan, needs SNYK_TOKEN',
    ],
    observed: OBSERVED,
  },
  {
    id: 'gitleaks',
    name: 'gitleaks',
    kind: 'secret-scanner',
    match: { bins: ['gitleaks'], ciTokens: ['gitleaks'] },
    traits: { beforeToolCall: 'no' },
    sources: [
      'https://github.com/gitleaks/gitleaks',
      'README: pre-commit hook id gitleaks, GitHub Action gitleaks-action',
    ],
    observed: OBSERVED,
  },
  {
    id: 'ggshield',
    name: 'GitGuardian ggshield',
    kind: 'secret-scanner',
    match: { skillSlugs: ['ggshield-scanner'], bins: ['ggshield'], ciTokens: ['ggshield'] },
    traits: { beforeToolCall: 'no' },
    sources: [
      `${CH}/amascia-gg/skills/ggshield-scanner`,
      'https://github.com/GitGuardian/ggshield-skill',
    ],
    observed: OBSERVED,
  },
];

export const IRONHEIGHTS_PLUGIN_ID = 'ironheights-guard';

export function toolById(id: string): KnownTool | undefined {
  return KNOWN_TOOLS.find((tool) => tool.id === id);
}

/** Skill folder names that identify a known tool. Lower case. */
export function toolForSkillName(name: string): KnownTool | undefined {
  const key = name.trim().toLowerCase();
  if (key.length === 0) return undefined;
  return KNOWN_TOOLS.find((tool) => tool.match.skillSlugs?.includes(key));
}
