import { open, readdir, stat } from 'node:fs/promises';
import { delimiter, join, basename } from 'node:path';
import { ironheightsHome } from '../core/config.ts';
import { GUARD_PLUGIN_ID } from '../guard/types.ts';
import { loadGuardRuntime } from '../guard/load.ts';
import { priorityFromConfig } from '../guard/priority.ts';
import { locateOpenClaw, parseJson5, type OpenClawLocations } from '../openclaw/locate.ts';
import { parseSkillMarkdown } from '../openclaw/skill.ts';
import { expandUserPath, homeDirectory } from '../util/paths.ts';
import { baselinePath } from '../integrity/baseline.ts';
import { KNOWN_TOOLS, IRONHEIGHTS_PLUGIN_ID, type KnownTool, type Tri } from './registry.ts';
import type { Confidence, DetectedTool, Evidence, GuardSelfState, ToolStatus } from './types.ts';

const MAX_FILE_BYTES = 256 * 1024;
const MAX_CODE_BYTES = 512 * 1024;
const MAX_DIR_ENTRIES = 2000;
const MAX_SKILL_MD_READS = 800;
const MAX_PATH_DIRS = 64;
const MAX_WORKFLOWS = 50;

export interface DetectOptions {
  env?: NodeJS.ProcessEnv;
  /** OpenClaw config file. Overrides OPENCLAW_CONFIG_PATH. */
  openclawConfig?: string;
  /** Project folder whose CI files are read. Default: the current directory. */
  repoDir?: string;
  /** Skip the project CI files. The OpenClaw plugin uses this at startup. */
  skipRepo?: boolean;
  platform?: NodeJS.Platform;
}

export interface Detection {
  located: OpenClawLocations;
  config: Record<string, unknown> | undefined;
  tools: DetectedTool[];
  proxyEnv: string[];
  self: GuardSelfState;
  notes: string[];
}

interface Hit {
  tool: KnownTool;
  evidence: Evidence;
  status?: ToolStatus;
  mode?: string;
}

export async function detectCoexistence(options: DetectOptions = {}): Promise<Detection> {
  const env: NodeJS.ProcessEnv = { ...(options.env ?? process.env) };
  if (options.openclawConfig) env.OPENCLAW_CONFIG_PATH = options.openclawConfig;
  const platform = options.platform ?? process.platform;
  const notes: string[] = [];
  const located = await locateOpenClaw(env);
  const config = await readOpenClawConfig(located, notes);
  const home = homeDirectory(env, platform);
  const hits: Hit[] = [];
  const unlisted = new Map<string, DetectedTool>();

  const plugins = asRecord(config?.plugins);
  const entries = asRecord(plugins?.entries) ?? {};
  const skillEntries = asRecord(asRecord(config?.skills)?.entries) ?? {};

  await detectPlugins({
    located,
    plugins,
    entries,
    hits,
    unlisted,
    notes,
    config,
    env,
  });
  await detectSkills(located, skillEntries, hits);
  await detectHooks(located, config, hits);
  await detectStatePaths(located.stateDir, home, hits);
  await detectBins(env, platform, hits);
  if (!options.skipRepo) await detectRepoFiles(options.repoDir ?? process.cwd(), hits, notes);
  detectMcp(config, hits);

  const tools = mergeHits(hits);
  tools.push(...unlisted.values());
  tools.sort((a, b) => a.name.localeCompare(b.name));
  const self = await selfState({ env, located, plugins, entries, home });
  return {
    located,
    config,
    tools,
    proxyEnv: proxyVariables(env),
    self,
    notes,
  };
}

async function readOpenClawConfig(
  located: OpenClawLocations,
  notes: string[],
): Promise<Record<string, unknown> | undefined> {
  if (!located.configFound) {
    notes.push('OpenClaw config was not found. Plugin and hook settings could not be read.');
    return undefined;
  }
  const text = await readBounded(located.configPath, MAX_FILE_BYTES * 4);
  if (text === undefined) {
    notes.push('OpenClaw config could not be read.');
    return undefined;
  }
  try {
    const parsed = parseJson5(text);
    return asRecord(parsed);
  } catch {
    notes.push('OpenClaw config could not be parsed. Plugin and hook settings were not read.');
    return undefined;
  }
}

// ---- plugins ---------------------------------------------------------------

interface PluginContext {
  located: OpenClawLocations;
  plugins: Record<string, unknown> | undefined;
  entries: Record<string, unknown>;
  hits: Hit[];
  unlisted: Map<string, DetectedTool>;
  notes: string[];
  config: Record<string, unknown> | undefined;
  env: NodeJS.ProcessEnv;
}

async function detectPlugins(ctx: PluginContext): Promise<void> {
  const dirs: string[] = [];
  const extensions = join(ctx.located.stateDir, 'extensions');
  for (const name of await listDirs(extensions)) dirs.push(join(extensions, name));
  const load = asRecord(ctx.plugins?.load);
  const loadPaths = Array.isArray(load?.paths) ? load.paths : [];
  for (const raw of loadPaths) {
    if (typeof raw !== 'string') continue;
    const expanded = expandUserPath(raw, ctx.env);
    if (await isDir(expanded)) dirs.push(expanded);
  }
  const seenIds = new Set<string>();
  for (const dir of dirs) {
    const manifestText = await readBounded(join(dir, 'openclaw.plugin.json'), MAX_FILE_BYTES);
    const pkgText = await readBounded(join(dir, 'package.json'), MAX_FILE_BYTES);
    if (manifestText === undefined && pkgText === undefined) continue;
    const manifest = tryParse(manifestText, true);
    const pkg = tryParse(pkgText, false);
    const id = (typeof manifest?.id === 'string' ? manifest.id : basename(dir)).trim();
    const npmName = typeof pkg?.name === 'string' ? pkg.name : undefined;
    if (
      id === IRONHEIGHTS_PLUGIN_ID ||
      npmName === 'ironheights' ||
      basename(dir) === 'ironheights'
    ) {
      continue;
    }
    seenIds.add(id.toLowerCase());
    const entry = asRecord(ctx.entries[id]);
    const status = statusFromEntry(entry);
    const mode = modeFromEntry(entry);
    const known = KNOWN_TOOLS.find(
      (tool) =>
        tool.match.pluginIds?.includes(id.toLowerCase()) ||
        (npmName !== undefined && tool.match.npmPackages?.includes(npmName)) ||
        tool.match.pluginIds?.includes(basename(dir).toLowerCase()),
    );
    const hint = await hooksBeforeToolCall(dir, pkg);
    const evidence: Evidence[] = [
      { kind: 'plugin-manifest', detail: `plugin id ${id}`, path: dir },
    ];
    if (hint)
      evidence.push({
        kind: 'code-hint',
        detail: 'entry file mentions before_tool_call',
        path: hint,
      });
    if (known) {
      ctx.hits.push({
        tool: known,
        evidence: evidence[0] as Evidence,
        ...(status ? { status } : {}),
        ...(mode ? { mode } : {}),
      });
      if (hint) {
        ctx.hits.push({ tool: known, evidence: evidence[1] as Evidence });
      }
      continue;
    }
    if (!hint) continue;
    ctx.unlisted.set(`unlisted:${id.toLowerCase()}`, {
      id: `unlisted:${id}`,
      name: id,
      listed: false,
      kind: 'unlisted-plugin',
      confidence: 'low',
      status: status ?? 'present',
      ...(mode ? { mode, modeSource: 'config' as const } : {}),
      registersBeforeToolCall: 'yes',
      canBlock: canBlock(mode, undefined, undefined),
      traits: { beforeToolCall: 'yes' },
      evidence,
      sources: [],
    });
  }
  // Config entries for known plugins that are not on disk under extensions/.
  for (const [id, raw] of Object.entries(ctx.entries)) {
    if (id === IRONHEIGHTS_PLUGIN_ID || seenIds.has(id.toLowerCase())) continue;
    const known = KNOWN_TOOLS.find((tool) => tool.match.pluginIds?.includes(id.toLowerCase()));
    if (!known) continue;
    const entry = asRecord(raw);
    const status = statusFromEntry(entry);
    const mode = modeFromEntry(entry);
    ctx.hits.push({
      tool: known,
      evidence: { kind: 'plugin-config', detail: `plugins.entries.${id}` },
      ...(status ? { status } : {}),
      ...(mode ? { mode } : {}),
    });
  }
}

async function hooksBeforeToolCall(
  dir: string,
  pkg: Record<string, unknown> | undefined,
): Promise<string | undefined> {
  const openclaw = asRecord(pkg?.openclaw);
  const listed = Array.isArray(openclaw?.extensions) ? openclaw.extensions : [];
  const candidates = listed.filter((item): item is string => typeof item === 'string').slice(0, 4);
  for (const rel of candidates) {
    const full = join(dir, ...rel.split('/'));
    const text = await readBounded(full, MAX_CODE_BYTES);
    if (text !== undefined && /\bbefore_tool_call\b/.test(text)) return full;
  }
  return undefined;
}

// ---- skills, hooks, state, bins, repo, mcp ---------------------------------

async function detectSkills(
  located: OpenClawLocations,
  skillEntries: Record<string, unknown>,
  hits: Hit[],
): Promise<void> {
  let skillMdReads = 0;
  const seen = new Set<string>();
  for (const dir of located.skillDirs) {
    if (!dir.exists) continue;
    for (const name of await listDirs(dir.path)) {
      const key = `${dir.path}\n${name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const slug = name.toLowerCase();
      const full = join(dir.path, name);
      const byDir = KNOWN_TOOLS.find((tool) => tool.match.skillSlugs?.includes(slug));
      if (byDir) {
        hits.push({
          tool: byDir,
          evidence: {
            kind: 'skill-dir',
            detail: `skill folder ${name} in ${dir.source}`,
            path: full,
          },
          ...skillStatus(skillEntries, name),
        });
        continue;
      }
      if (skillMdReads >= MAX_SKILL_MD_READS) continue;
      skillMdReads += 1;
      const text = await readBounded(join(full, 'SKILL.md'), 16 * 1024);
      if (text === undefined) continue;
      let declared: string | undefined;
      try {
        declared = parseSkillMarkdown(text)?.name;
      } catch {
        declared = undefined;
      }
      if (!declared) continue;
      const byName = KNOWN_TOOLS.find((tool) =>
        tool.match.skillSlugs?.includes(declared.trim().toLowerCase()),
      );
      if (byName) {
        hits.push({
          tool: byName,
          evidence: {
            kind: 'skill-name',
            detail: `SKILL.md name "${declared.trim().slice(0, 60)}" in folder ${name}`,
            path: full,
          },
          ...skillStatus(skillEntries, name),
        });
      }
    }
  }
}

function skillStatus(entries: Record<string, unknown>, name: string): { status?: ToolStatus } {
  const entry = asRecord(entries[name]);
  return entry?.enabled === false ? { status: 'disabled' } : {};
}

async function detectHooks(
  located: OpenClawLocations,
  config: Record<string, unknown> | undefined,
  hits: Hit[],
): Promise<void> {
  const roots = [join(located.stateDir, 'hooks')];
  if (located.workspace) roots.push(join(located.workspace, 'hooks'));
  const internal = asRecord(asRecord(config?.hooks)?.internal);
  const entries = asRecord(internal?.entries) ?? {};
  for (const root of roots) {
    for (const name of await listDirs(root)) {
      const full = join(root, name);
      if ((await readBounded(join(full, 'HOOK.md'), 8 * 1024)) === undefined) continue;
      const tool = KNOWN_TOOLS.find((item) => item.match.hookNames?.includes(name.toLowerCase()));
      if (!tool) continue;
      const entry = asRecord(entries[name]);
      hits.push({
        tool,
        evidence: { kind: 'hook-dir', detail: `internal hook ${name}`, path: full },
        ...(entry?.enabled === false ? { status: 'disabled' as const } : {}),
      });
    }
  }
  for (const [name, raw] of Object.entries(entries)) {
    const tool = KNOWN_TOOLS.find((item) => item.match.hookNames?.includes(name.toLowerCase()));
    if (!tool) continue;
    const entry = asRecord(raw);
    hits.push({
      tool,
      evidence: { kind: 'hook-config', detail: `hooks.internal.entries.${name}` },
      ...(entry?.enabled === false ? { status: 'disabled' as const } : {}),
    });
  }
}

async function detectStatePaths(stateDir: string, home: string, hits: Hit[]): Promise<void> {
  for (const tool of KNOWN_TOOLS) {
    for (const raw of tool.match.statePaths ?? []) {
      const path = resolveToken(raw, stateDir, home);
      if (await exists(path)) {
        hits.push({ tool, evidence: { kind: 'state-path', detail: 'state path exists', path } });
      }
    }
  }
}

async function detectBins(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  hits: Hit[],
): Promise<void> {
  const pathValue = envGet(env, 'PATH');
  if (!pathValue) return;
  const dirs = pathValue
    .split(platform === 'win32' ? ';' : delimiter)
    .filter(Boolean)
    .slice(0, MAX_PATH_DIRS);
  const exts =
    platform === 'win32'
      ? (envGet(env, 'PATHEXT') ?? '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean).concat('')
      : [''];
  for (const tool of KNOWN_TOOLS) {
    for (const bin of tool.match.bins ?? []) {
      const found = await findBin(dirs, bin, exts);
      if (found) {
        hits.push({
          tool,
          evidence: { kind: 'cli-on-path', detail: `${bin} on PATH`, path: found },
        });
      }
    }
  }
}

async function findBin(dirs: string[], bin: string, exts: string[]): Promise<string | undefined> {
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = join(dir, `${bin}${ext}`);
      try {
        const info = await stat(candidate);
        if (info.isFile()) return candidate;
      } catch {
        // Not here.
      }
    }
  }
  return undefined;
}

async function detectRepoFiles(repoDir: string, hits: Hit[], notes: string[]): Promise<void> {
  const files: string[] = [
    join(repoDir, '.pre-commit-config.yaml'),
    join(repoDir, '.git', 'hooks', 'pre-commit'),
  ];
  const workflows = join(repoDir, '.github', 'workflows');
  try {
    const names = (await readdir(workflows))
      .filter((name) => /\.ya?ml$/i.test(name))
      .slice(0, MAX_WORKFLOWS);
    for (const name of names) files.push(join(workflows, name));
  } catch {
    // No workflows folder.
  }
  let read = 0;
  for (const file of files) {
    const text = await readBounded(file, MAX_FILE_BYTES);
    if (text === undefined) continue;
    read += 1;
    const lower = text.toLowerCase();
    for (const tool of KNOWN_TOOLS) {
      for (const token of tool.match.ciTokens ?? []) {
        if (lower.includes(token.toLowerCase())) {
          hits.push({
            tool,
            evidence: { kind: 'repo-ci', detail: `mentions ${token}`, path: file },
          });
          break;
        }
      }
    }
  }
  if (read === 0) notes.push(`No pre-commit or CI files were found in ${repoDir}.`);
}

function detectMcp(config: Record<string, unknown> | undefined, hits: Hit[]): void {
  const servers = asRecord(asRecord(config?.mcp)?.servers);
  if (!servers) return;
  for (const [name, raw] of Object.entries(servers)) {
    const entry = asRecord(raw);
    if (!entry) continue;
    const text = JSON.stringify({
      command: entry.command,
      args: entry.args,
      url: entry.url,
    }).toLowerCase();
    for (const tool of KNOWN_TOOLS) {
      const token = (tool.match.mcpTokens ?? []).find((item) => text.includes(item.toLowerCase()));
      if (token) {
        hits.push({
          tool,
          evidence: { kind: 'mcp-server', detail: `mcp.servers.${name} runs ${token}` },
        });
      }
    }
  }
}

// ---- merge and self state --------------------------------------------------

function mergeHits(hits: Hit[]): DetectedTool[] {
  const byId = new Map<string, DetectedTool>();
  for (const hit of hits) {
    const existing = byId.get(hit.tool.id);
    const tool =
      existing ??
      ({
        id: hit.tool.id,
        name: hit.tool.name,
        listed: true,
        kind: hit.tool.kind,
        confidence: 'low',
        status: 'present',
        registersBeforeToolCall: hit.tool.traits.beforeToolCall,
        canBlock: 'unknown',
        traits: hit.tool.traits,
        evidence: [],
        sources: hit.tool.sources,
      } satisfies DetectedTool);
    if (
      !tool.evidence.some(
        (item) =>
          item.kind === hit.evidence.kind &&
          item.detail === hit.evidence.detail &&
          item.path === hit.evidence.path,
      )
    ) {
      tool.evidence.push(hit.evidence);
    }
    if (hit.status === 'enabled' || (hit.status === 'disabled' && tool.status !== 'enabled')) {
      tool.status = hit.status;
    }
    if (hit.mode) {
      tool.mode = hit.mode;
      tool.modeSource = 'config';
    }
    tool.confidence = strongest(tool.confidence, confidenceOf(hit.evidence));
    if (hit.evidence.kind === 'code-hint') tool.registersBeforeToolCall = 'yes';
    byId.set(hit.tool.id, tool);
  }
  const result = [...byId.values()];
  for (const tool of result) {
    const known = KNOWN_TOOLS.find((item) => item.id === tool.id);
    if (!tool.mode && known?.traits.defaultMode && tool.registersBeforeToolCall !== 'no') {
      tool.mode = known.traits.defaultMode;
      tool.modeSource = 'default';
    }
    tool.canBlock =
      tool.registersBeforeToolCall === 'no'
        ? 'no'
        : canBlock(
            tool.modeSource === 'config' ? tool.mode : undefined,
            known?.traits.defaultMode,
            known?.traits.nonBlockingModes,
          );
  }
  return result;
}

const GENERIC_NON_BLOCKING = ['monitor', 'audit', 'log', 'observe', 'report', 'warn'];

function canBlock(
  configMode: string | undefined,
  defaultMode: string | undefined,
  nonBlocking: string[] | undefined,
): Tri {
  const mode = (configMode ?? defaultMode)?.toLowerCase();
  if (!mode) return 'unknown';
  if ((nonBlocking ?? GENERIC_NON_BLOCKING).includes(mode)) return 'no';
  if (/^(enforce|strict|block|deny)/.test(mode)) return 'yes';
  return nonBlocking ? 'yes' : 'unknown';
}

function confidenceOf(evidence: Evidence): Confidence {
  switch (evidence.kind) {
    case 'plugin-manifest':
    case 'plugin-config':
      return 'high';
    case 'state-path':
    case 'code-hint':
      return 'low';
    default:
      return 'medium';
  }
}

function strongest(a: Confidence, b: Confidence): Confidence {
  const rank: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };
  return rank[b] > rank[a] ? b : a;
}

async function selfState(input: {
  env: NodeJS.ProcessEnv;
  located: OpenClawLocations;
  plugins: Record<string, unknown> | undefined;
  entries: Record<string, unknown>;
  home: string;
}): Promise<GuardSelfState> {
  const entry = asRecord(input.entries[GUARD_PLUGIN_ID]);
  const pluginConfig = asRecord(entry?.config);
  const pluginMode =
    pluginConfig?.mode === 'monitor' || pluginConfig?.mode === 'enforce'
      ? pluginConfig.mode
      : undefined;
  const priority = priorityFromConfig(pluginConfig);
  const policyPathOverride =
    typeof pluginConfig?.policyPath === 'string' && pluginConfig.policyPath.length > 0
      ? pluginConfig.policyPath
      : undefined;
  const loaded = await loadGuardRuntime({
    env: input.env,
    ...(policyPathOverride ? { policyPath: policyPathOverride } : {}),
    ...(pluginMode ? { modeOverride: pluginMode } : {}),
  });
  const allow = Array.isArray(input.plugins?.allow) ? input.plugins.allow : undefined;
  const deny = Array.isArray(input.plugins?.deny) ? input.plugins.deny : [];
  const home = ironheightsHome(input.env);
  return {
    pluginEnabled: entry ? entry.enabled === true : input.located.configParsed ? false : 'unknown',
    pluginListedInAllow: allow ? allow.includes(GUARD_PLUGIN_ID) : 'not-set',
    pluginDenied: deny.includes(GUARD_PLUGIN_ID),
    mode: loaded.policy.mode,
    modeSource: describeModeSource(loaded.modeSource),
    priority,
    policyPath: loaded.policyPath,
    logPath: loaded.log.path,
    home,
    baselineExists: await exists(baselinePath(home)),
    effectiveAllowDomains: loaded.policy.globalAllowDomains,
  };
}

// ---- helpers ---------------------------------------------------------------

function statusFromEntry(entry: Record<string, unknown> | undefined): ToolStatus | undefined {
  if (!entry) return undefined;
  if (entry.enabled === true) return 'enabled';
  if (entry.enabled === false) return 'disabled';
  return undefined;
}

function modeFromEntry(entry: Record<string, unknown> | undefined): string | undefined {
  const config = asRecord(entry?.config);
  return typeof config?.mode === 'string' ? config.mode.slice(0, 40) : undefined;
}

function proxyVariables(env: NodeJS.ProcessEnv): string[] {
  const found: string[] = [];
  for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) {
    const value = envGet(env, name);
    if (!value) continue;
    try {
      const url = new URL(value.includes('://') ? value : `http://${value}`);
      const host = url.hostname.replace(/^\[|\]$/g, '');
      if (host === 'localhost' || host === '::1' || /^127\./.test(host)) {
        found.push(`${name}=${url.protocol}//${url.host}`);
      }
    } catch {
      // Not a URL. Ignore it.
    }
  }
  return found;
}

function envGet(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const key = Object.keys(env).find((item) => item.toLowerCase() === name.toLowerCase());
  const value = key ? env[key] : undefined;
  return value && value.length > 0 ? value : undefined;
}

export function resolveToken(raw: string, stateDir: string, home: string): string {
  if (raw.startsWith('{state}')) return join(stateDir, ...raw.slice(7).split('/').filter(Boolean));
  if (raw.startsWith('{home}')) return join(home, ...raw.slice(6).split('/').filter(Boolean));
  return raw;
}

async function readBounded(path: string, maxBytes: number): Promise<string | undefined> {
  let handle;
  try {
    handle = await open(path, 'r');
    const info = await handle.stat();
    if (!info.isFile()) return undefined;
    const length = Math.min(info.size, maxBytes);
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, 0);
    return buffer.toString('utf8');
  } catch {
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function listDirs(path: string): Promise<string[]> {
  try {
    const entries = await readdir(path, { withFileTypes: true });
    const names: string[] = [];
    for (const entry of entries.slice(0, MAX_DIR_ENTRIES)) {
      if (entry.isDirectory()) names.push(entry.name);
      else if (entry.isSymbolicLink() && (await isDir(join(path, entry.name))))
        names.push(entry.name);
    }
    return names;
  } catch {
    return [];
  }
}

async function isDir(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function tryParse(text: string | undefined, json5: boolean): Record<string, unknown> | undefined {
  if (text === undefined) return undefined;
  try {
    return asRecord(json5 ? parseJson5(text) : (JSON.parse(text) as unknown));
  } catch {
    return undefined;
  }
}

function describeModeSource(source: string): string {
  if (source === 'override') return 'plugin config';
  if (source === 'policy') return 'policy file';
  return 'default';
}
