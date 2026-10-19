import { fencedLineNumbers } from '../util/text.ts';

/**
 * A package the skill installs from outside its own folder. Ironheights scans the skill's
 * files only, so the code in these packages was not read.
 */
export interface UnscannedDependency {
  manager: 'npm' | 'pypi' | 'brew' | 'go' | 'cargo' | 'system';
  name: string;
  /** The version or tag as written, if any (`1.2.3`, `latest`, `^2`). */
  version?: string;
  /** True only for an exact version (npm `@1.2.3`, pip `==1.2.3`, go `@v1.2.3`, cargo `@1.2.3`). */
  pinned: boolean;
  /** `frontmatter` for a metadata install entry, `instructions` for an install command in SKILL.md. */
  source: 'frontmatter' | 'instructions';
  file: string;
  line?: number;
}

const MAX_DEPENDENCIES = 50;

/** Install entries from `metadata.<agent>.install` in SKILL.md frontmatter. */
export function dependenciesFromFrontmatter(
  record: Record<string, unknown>,
  file: string,
): UnscannedDependency[] {
  const found: UnscannedDependency[] = [];
  let metadata: unknown = record.metadata;
  if (typeof metadata === 'string') {
    try {
      metadata = JSON.parse(metadata) as unknown;
    } catch {
      metadata = undefined;
    }
  }
  const blocks: unknown[] = [];
  if (isRecord(metadata)) {
    for (const value of Object.values(metadata)) {
      if (isRecord(value) && Array.isArray(value.install)) blocks.push(...value.install);
    }
  }
  if (Array.isArray(record.install)) blocks.push(...record.install);
  for (const entry of blocks.slice(0, MAX_DEPENDENCIES)) {
    if (!isRecord(entry)) continue;
    const kind = str(entry.kind) ?? str(entry.type);
    const rawPkg = str(entry.package) ?? str(entry.formula) ?? str(entry.module);
    const pkgs = rawPkg ? packageArgs(rawPkg.split(/\s+/)) : [];
    const pkg = pkgs[0];
    const list = Array.isArray(entry.packages)
      ? entry.packages.filter((item): item is string => typeof item === 'string')
      : [];
    switch (kind?.toLowerCase()) {
      case 'node':
      case 'npm':
      case 'pnpm':
      case 'bun':
        for (const name of pkgs) push(found, npmDependency(name, 'frontmatter', file));
        break;
      case 'uv':
      case 'pip':
      case 'pipx':
      case 'python':
        for (const name of pkgs) push(found, pypiDependency(name, 'frontmatter', file));
        break;
      case 'brew':
        if (pkg) push(found, brewDependency(pkg, 'frontmatter', file));
        break;
      case 'go':
        if (pkg) push(found, goDependency(pkg, 'frontmatter', file));
        break;
      case 'cargo':
        if (pkg) push(found, cargoDependency(pkg, 'frontmatter', file));
        break;
      case 'apt':
      case 'dnf':
      case 'yum':
      case 'apk':
        for (const name of [...pkgs, ...packageArgs(list)]) {
          push(found, { manager: 'system', name, pinned: false, source: 'frontmatter', file });
        }
        break;
      default:
        break;
    }
  }
  return found;
}

const SHELL_SPLIT = /\s*(?:&&|\|\||;|\|)\s*/;

/**
 * Install commands in SKILL.md: `npm install -g`, `npx`, `pip install`, `uv tool install`, `uvx`,
 * `pipx install`, `brew install`, `go install`, `cargo install`. Requirements files, local paths
 * and project installs (`npm install` with no package) are not listed: they install what the
 * skill ships, which the scan reads.
 */
export function dependenciesFromInstructions(text: string, file: string): UnscannedDependency[] {
  const found: UnscannedDependency[] = [];
  const fenced = fencedLineNumbers(text);
  const lines = text.split(/\r?\n/);
  let inFrontmatter = lines[0]?.trim() === '---';
  for (let i = 0; i < lines.length && found.length < MAX_DEPENDENCIES; i += 1) {
    const raw = lines[i] ?? '';
    if (inFrontmatter) {
      if (i > 0 && raw.trim() === '---') inFrontmatter = false;
      continue;
    }
    const lineNumber = i + 1;
    const line = (fenced.has(lineNumber) ? raw : inlineCode(raw)).slice(0, 2000);
    for (const segment of line.split(SHELL_SPLIT)) {
      for (const dep of parseCommand(segment.trim(), file, lineNumber)) push(found, dep);
    }
  }
  return found;
}

function inlineCode(line: string): string {
  return [...line.matchAll(/`([^`]{1,400})`/g)].map((match) => match[1] ?? '').join(' ; ');
}

function parseCommand(segment: string, file: string, line: number): UnscannedDependency[] {
  const words = segment
    .replace(/^\$\s+/, '')
    .replace(/^sudo\s+/, '')
    .split(/\s+/)
    .filter(Boolean);
  if (words.length < 2) return [];
  const [tool, sub] = [words[0] ?? '', words[1] ?? ''];
  const args = (from: number): string[] => packageArgs(words.slice(from));
  if (/^(?:npm|pnpm|yarn|bun)$/.test(tool)) {
    const installs = ['install', 'i', 'add'];
    const global = words.includes('-g') || words.includes('--global') || sub === 'global';
    if (tool === 'yarn' && sub === 'global' && words[2] === 'add') {
      return args(3).map((name) => npmDependency(name, 'instructions', file, line));
    }
    if (installs.includes(sub) && global) {
      return args(2).map((name) => npmDependency(name, 'instructions', file, line));
    }
    if ((tool === 'pnpm' && sub === 'dlx') || (tool === 'bun' && sub === 'x')) {
      return args(2)
        .slice(0, 1)
        .map((name) => npmDependency(name, 'instructions', file, line));
    }
    return [];
  }
  if (tool === 'npx' || tool === 'bunx') {
    const pkgFlag = words.findIndex((word) => word === '-p' || word === '--package');
    if (pkgFlag > 0 && words[pkgFlag + 1]) {
      return [npmDependency(words[pkgFlag + 1] ?? '', 'instructions', file, line)].filter(
        (dep) => dep.name !== '',
      );
    }
    return args(1)
      .slice(0, 1)
      .map((name) => npmDependency(name, 'instructions', file, line));
  }
  if (/^pip3?$/.test(tool) || (tool === 'python3' && sub === '-m' && words[2] === 'pip')) {
    const offset = tool === 'python3' ? 3 : 1;
    if (words[offset] !== 'install') return [];
    if (words.some((word) => word === '-r' || word === '--requirement' || word === '-e')) return [];
    return args(offset + 1).map((name) => pypiDependency(name, 'instructions', file, line));
  }
  if (tool === 'uv' && (sub === 'pip' || sub === 'tool')) {
    if (words[2] !== 'install') return [];
    if (words.some((word) => word === '-r' || word === '-e')) return [];
    return args(3).map((name) => pypiDependency(name, 'instructions', file, line));
  }
  if (tool === 'pipx' && sub === 'install') {
    return args(2).map((name) => pypiDependency(name, 'instructions', file, line));
  }
  if (tool === 'uvx' || (tool === 'pipx' && sub === 'run')) {
    return args(tool === 'uvx' ? 1 : 2)
      .slice(0, 1)
      .map((name) => pypiDependency(name, 'instructions', file, line));
  }
  if (tool === 'brew' && sub === 'install') {
    return args(2).map((name) => brewDependency(name, 'instructions', file, line));
  }
  if (tool === 'go' && sub === 'install') {
    return args(2)
      .filter((name) => name.includes('/'))
      .map((name) => goDependency(name, 'instructions', file, line));
  }
  if (tool === 'cargo' && sub === 'install') {
    return args(2).map((name) => cargoDependency(name, 'instructions', file, line));
  }
  return [];
}

/** Drop flags and anything that is not a plausible registry package name. */
function packageArgs(words: string[]): string[] {
  const out: string[] = [];
  for (const word of words) {
    const clean = word.replace(/^["']|["'),]$/g, '');
    if (clean === '' || clean.startsWith('-')) continue;
    if (/^(?:\.|\/|~|\$|<|\{|https?:|git\+|git:|github:|gitlab:|file:|link:)/.test(clean)) break;
    if (/[\\*{}$`]/.test(clean) || /\.(?:txt|toml|cfg|whl|tgz|tar\.gz|zip|json)$/i.test(clean)) {
      break;
    }
    if (!/^[@a-z0-9]/i.test(clean)) break;
    out.push(clean);
    if (out.length >= 10) break;
  }
  return out;
}

const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/;

export function npmDependency(
  spec: string,
  source: UnscannedDependency['source'],
  file: string,
  line?: number,
): UnscannedDependency {
  const scoped = spec.startsWith('@');
  const at = spec.indexOf('@', scoped ? 1 : 0);
  const name = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : undefined;
  return withLine(
    {
      manager: 'npm',
      name,
      ...(version ? { version } : {}),
      pinned: version !== undefined && EXACT_SEMVER.test(version),
      source,
      file,
    },
    line,
  );
}

export function pypiDependency(
  spec: string,
  source: UnscannedDependency['source'],
  file: string,
  line?: number,
): UnscannedDependency {
  const match =
    /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(===?|>=|<=|~=|!=|>|<|@)?\s*(.*)$/.exec(spec);
  const name = match?.[1] ?? spec;
  const op = match?.[2];
  const version = match?.[3] ? match[3] : undefined;
  return withLine(
    {
      manager: 'pypi',
      name,
      ...(version ? { version: `${op ?? ''}${version}` } : {}),
      pinned: (op === '==' || op === '===') && version !== undefined && !version.includes('*'),
      source,
      file,
    },
    line,
  );
}

function brewDependency(
  spec: string,
  source: UnscannedDependency['source'],
  file: string,
  line?: number,
): UnscannedDependency {
  // Homebrew installs the formula's current version; a formula name cannot pin it.
  return withLine({ manager: 'brew', name: spec, pinned: false, source, file }, line);
}

function goDependency(
  spec: string,
  source: UnscannedDependency['source'],
  file: string,
  line?: number,
): UnscannedDependency {
  const at = spec.lastIndexOf('@');
  const name = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : undefined;
  return withLine(
    {
      manager: 'go',
      name,
      ...(version ? { version } : {}),
      pinned: version !== undefined && EXACT_SEMVER.test(version),
      source,
      file,
    },
    line,
  );
}

function cargoDependency(
  spec: string,
  source: UnscannedDependency['source'],
  file: string,
  line?: number,
): UnscannedDependency {
  const at = spec.indexOf('@');
  const name = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : undefined;
  return withLine(
    {
      manager: 'cargo',
      name,
      ...(version ? { version } : {}),
      pinned: version !== undefined && EXACT_SEMVER.test(version),
      source,
      file,
    },
    line,
  );
}

function withLine(dep: UnscannedDependency, line?: number): UnscannedDependency {
  return line === undefined ? dep : { ...dep, line };
}

function push(list: UnscannedDependency[], dep: UnscannedDependency): void {
  if (!dep.name || dep.name.length > 214 || !/^@?[\w.+-]+(?:\/[\w.+-]+)*$/.test(dep.name)) return;
  if (list.some((item) => item.manager === dep.manager && item.name === dep.name)) return;
  if (list.length < MAX_DEPENDENCIES) list.push(dep);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

export function describeDependency(dep: UnscannedDependency): string {
  const version = dep.version ? `@${dep.version}` : '';
  const pin =
    dep.manager === 'brew' || dep.manager === 'system'
      ? 'version not pinnable'
      : dep.pinned
        ? 'version pinned'
        : dep.version
          ? 'version not pinned exactly'
          : 'version not pinned';
  const where = dep.line ? `${dep.file}:${dep.line}` : `${dep.file} frontmatter`;
  return `${dep.manager} ${dep.name}${version} (${pin}) at ${where}`;
}
