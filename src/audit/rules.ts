import type { Rule } from '../core/types.ts';

/**
 * Config rules run only from `audit-config`. They are not content rules:
 * `check` stays empty so a skill scan never emits IH-CFG findings.
 * Match / no-match examples are config shapes, not skill lines.
 */

function configRule(rule: Omit<Rule, 'check'>): Rule {
  return { ...rule, check: () => [] };
}

export const cfg001: Rule = configRule({
  id: 'IH-CFG-001',
  title: 'Gateway bind is not loopback',
  category: 'config',
  severity: 'high',
  priority: 'P0',
  description:
    "gateway.bind is lan, tailnet, custom, auto, or an all-interfaces address, or gateway.tailscale.mode is funnel. OpenClaw's native check gateway.bind_no_auth covers a remote bind without a shared secret, and gateway.tailscale_funnel covers public Funnel. This rule only reads the config value. It does not probe the listener. auto is medium because the effective bind is chosen at runtime. Funnel and 0.0.0.0 are critical.",
  remediation:
    'Prefer gateway.bind "loopback". If the Gateway must leave the machine, require token or password auth and firewall the port. Do not use Tailscale Funnel for a Gateway you have not locked down. Run openclaw security audit for a live check.',
  appliesTo: ['config'],
  examples: {
    matches: [
      'gateway.bind: "lan"',
      'gateway.bind: "custom", gateway.customBindHost: "0.0.0.0"',
      'gateway.tailscale.mode: "funnel"',
    ],
    nonMatches: [
      'gateway.bind: "loopback"',
      'gateway.bind omitted (OpenClaw default is loopback)',
      'gateway.bind: "custom", gateway.customBindHost: "127.0.0.1"',
    ],
  },
});

export const cfg002: Rule = configRule({
  id: 'IH-CFG-002',
  title: 'Gateway auth is missing or a placeholder',
  category: 'config',
  severity: 'critical',
  priority: 'P0',
  description:
    "gateway.auth.mode is none or trusted-proxy, a non-loopback bind has no auth object, or the token or password in the file is empty or a known placeholder. Native checks gateway.bind_no_auth, gateway.loopback_no_auth, gateway.token_placeholder_value, and gateway.trusted_proxy_auth overlap this rule. A loopback bind that omits auth is not flagged: OpenClaw's default is authenticated, and the token may live in OPENCLAW_GATEWAY_TOKEN, which this command does not read. trusted-proxy is critical because the proxy becomes the auth boundary; proxy IPs and headers are left to the native audit.",
  remediation:
    'Set gateway.auth.mode to token or password and store the secret in the environment or a SecretRef, not as a placeholder. For trusted-proxy, run openclaw security audit and keep gateway.trustedProxies tight. This command never prints the secret.',
  appliesTo: ['config'],
  examples: {
    matches: [
      'gateway.auth.mode: "none"',
      'gateway.bind: "lan" with no gateway.auth',
      'gateway.auth.token: "replace-with-long-random-token"',
      'gateway.auth.mode: "trusted-proxy"',
    ],
    nonMatches: [
      'gateway.auth.mode: "token", gateway.auth.token: "${OPENCLAW_GATEWAY_TOKEN}"',
      'gateway.bind: "loopback" and gateway.auth omitted',
      'gateway.auth: { mode: "token" } with the secret only in the environment',
    ],
  },
});

export const cfg003: Rule = configRule({
  id: 'IH-CFG-003',
  title: 'DM policy is open',
  category: 'config',
  severity: 'critical',
  priority: 'P0',
  description:
    'A channel dmPolicy (or dm.policy) is open, so anyone can DM the agent. This matches the native check channels.<channel>.dm.open. Mutable allowFrom entries and name matching are not reimplemented.',
  remediation:
    'Set dmPolicy to pairing or allowlist. Open is a last resort in the OpenClaw docs. Run openclaw security audit before exposing a bot.',
  appliesTo: ['config'],
  examples: {
    matches: ['channels.telegram.dmPolicy: "open"', 'channels.discord.dm.policy: "open"'],
    nonMatches: [
      'channels.telegram.dmPolicy: "pairing"',
      'channels.telegram.dmPolicy: "allowlist"',
      'channels.telegram.dmPolicy: "disabled"',
    ],
  },
});

export const cfg004: Rule = configRule({
  id: 'IH-CFG-004',
  title: 'Group policy is open',
  category: 'config',
  severity: 'high',
  priority: 'P0',
  description:
    'A channel groupPolicy is open, so any member of a group can talk to the agent. Severity rises to critical when the same config also enables host exec, elevated tools, or an open DM policy. Native security.exposure.open_groups_with_elevated and security.exposure.open_channels_with_exec cover the live combination; this rule only reads the file.',
  remediation:
    'Set groupPolicy to allowlist and require mentions. Do not combine an open room with tools.exec.security full or tools.elevated.',
  appliesTo: ['config'],
  examples: {
    matches: ['channels.telegram.groupPolicy: "open"', 'channels.discord.groupPolicy: "open"'],
    nonMatches: [
      'channels.telegram.groupPolicy: "allowlist"',
      'channels.telegram.groupPolicy: "disabled"',
    ],
  },
});

export const cfg005: Rule = configRule({
  id: 'IH-CFG-005',
  title: 'Plaintext secret in OpenClaw config',
  category: 'config',
  severity: 'high',
  priority: 'P1',
  description:
    'A token, password, secret, or API key is a literal string in the config file. ${ENV} references and SecretRef objects (source env, file, exec, or store) are not literals. Placeholder literals are reported as IH-CFG-002 instead. Evidence is the key path plus <redacted>. Native config.secrets.gateway_password_in_config and config.secrets.hooks_token_in_config are the overlapping checks; other secret keys in the file are reported here too.',
  remediation:
    'Remove the literal. Use a SecretRef or an environment variable. Rotate the value if the file was copied or committed. This command does not print the value.',
  appliesTo: ['config'],
  examples: {
    matches: ['hooks.token: "a-real-token-value"', 'gateway.auth.password: "correct-horse"'],
    nonMatches: [
      'gateway.auth.token: "${OPENCLAW_GATEWAY_TOKEN}"',
      'gateway.auth.token: { source: "env", provider: "default", id: "OPENCLAW_GATEWAY_TOKEN" }',
      'gateway.auth.mode: "token"',
    ],
  },
});

export const cfg006: Rule = configRule({
  id: 'IH-CFG-006',
  title: 'OpenClaw config permissions',
  category: 'config',
  severity: 'critical',
  priority: 'P0',
  description:
    "On POSIX, the config file is group-writable, world-writable, world-readable, or group-readable. A symlink is reported at medium severity because OpenClaw documents that a symlinked openclaw.json is unsupported. Native checks fs.config.perms_world_readable, fs.config.perms_writable, fs.config.perms_group_readable, and fs.config.symlink. Windows ACLs are not Unix mode bits. This rule does not report permission findings on Windows and does not run icacls. OpenClaw's audit does.",
  remediation:
    'On POSIX, chmod 600 the config file and do not symlink it. On Windows, run openclaw security audit so ACL resets can be reviewed. This command never changes permissions.',
  appliesTo: ['config'],
  examples: {
    matches: ['openclaw.json mode 0644', 'openclaw.json mode 0666', 'openclaw.json is a symlink'],
    nonMatches: ['openclaw.json mode 0600', 'openclaw.json mode 0400'],
  },
});

export const cfg007: Rule = configRule({
  id: 'IH-CFG-007',
  title: 'Dangerous tool permissions',
  category: 'config',
  severity: 'high',
  priority: 'P1',
  description:
    'tools.exec.security or an agent exec security is full, exec ask is off while security is not deny, or tools.elevated is enabled. Elevated allowFrom containing * is critical. Native tools.exec.security_full_configured and tools.elevated.allowFrom.<channel>.wildcard overlap this rule. Interpreter allowlists, safeBins, and approval-file drift are left to the native audit.',
  remediation:
    'Set tools.exec.security to deny or allowlist, set tools.exec.ask to always, and keep tools.elevated.enabled false unless allowFrom is a named list without *.',
  appliesTo: ['config'],
  examples: {
    matches: [
      'tools.exec.security: "full"',
      'tools.exec.security: "allowlist", tools.exec.ask: "off"',
      'tools.elevated.enabled: true, tools.elevated.allowFrom.telegram: ["*"]',
    ],
    nonMatches: [
      'tools.exec.security: "deny", tools.exec.ask: "always"',
      'tools.elevated.enabled: false',
      'tools.exec.security: "allowlist", tools.exec.ask: "always"',
    ],
  },
});

export const cfg008: Rule = configRule({
  id: 'IH-CFG-008',
  title: 'Skills load from an extra directory',
  category: 'config',
  severity: 'medium',
  priority: 'P1',
  description:
    'skills.load.extraDirs or skills.load.allowSymlinkTargets is set. Extra directories are the lowest-precedence skill roots and are trusted by the operator. OpenClaw tells you to keep allowSymlinkTargets narrow. A home directory, a filesystem root, or a path that contains .. is critical. Other extra directories are medium. The native audit does not have this check; it does have skills.workspace.symlink_escape, which walks the workspace and is not repeated here.',
  remediation:
    'Remove extra directories you do not trust. Do not point extraDirs or allowSymlinkTargets at ~, /, or a drive root. Scan those directories with ironheights scan before loading them.',
  appliesTo: ['config'],
  examples: {
    matches: [
      'skills.load.extraDirs: ["~/Projects/untrusted/skills"]',
      'skills.load.extraDirs: ["~"]',
      'skills.load.allowSymlinkTargets: ["/"]',
    ],
    nonMatches: ['skills.load.extraDirs omitted', 'skills.load.extraDirs: []'],
  },
});

export const cfg009: Rule = configRule({
  id: 'IH-CFG-009',
  title: 'Sandbox disabled while tools can act',
  category: 'config',
  severity: 'medium',
  priority: 'P1',
  description:
    'Sandbox mode is off, or sandbox.docker is set while mode is off, and the file also enables host exec, elevated tools, or an open room. A personal agent with sandbox off and tools.exec.security deny is a documented OpenClaw pattern and stays quiet. Native sandbox.docker_config_mode_off and the security.exposure.open_groups_with_runtime_or_fs checks overlap the noisy cases. Docker bind mounts, seccomp, and AppArmor are not reimplemented.',
  remediation:
    'Set agents.defaults.sandbox.mode to all for any agent that can exec or that strangers can message. Otherwise set tools.exec.security to deny. Run openclaw security audit for sandbox mount checks.',
  appliesTo: ['config'],
  examples: {
    matches: [
      'agents.defaults.sandbox.mode: "off" and tools.exec.security: "full"',
      'sandbox.docker is set and sandbox.mode: "off"',
    ],
    nonMatches: [
      'agents.defaults.sandbox.mode: "all"',
      'sandbox.mode omitted and tools.exec.security: "deny"',
      'sandbox.mode: "off" and tools.elevated.enabled: false and tools.exec.security: "deny"',
    ],
  },
});

export const configRules: Rule[] = [
  cfg001,
  cfg002,
  cfg003,
  cfg004,
  cfg005,
  cfg006,
  cfg007,
  cfg008,
  cfg009,
];
