import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, realpath, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { z } from 'zod';
import { UsageError } from '../core/errors.ts';
import { pinnedGet, formatRequestPlan } from './http.ts';
import { pathContainsSymlink, safeRelativeParts, writeRegularFileInside } from './safe-path.ts';
import { stripLongPath } from '../util/paths.ts';

export const CLAWHUB_ORIGIN = 'https://clawhub.ai';
export const CLAWHUB_HOST = 'clawhub.ai';

/** Hard caps. Config may only make these smaller. */
export const FETCH_HARD_MAX_FILE_BYTES = 10 * 1024 * 1024;
export const FETCH_HARD_MAX_TOTAL_BYTES = 32 * 1024 * 1024;
export const FETCH_HARD_MAX_FILES = 2000;
const METADATA_MAX_BYTES = 2 * 1024 * 1024;

export const NETWORK_BANNER =
  'This command contacts the network. Scans stay local. Besides fetch, safe-install, advisories update, --online, scan --llm, and review, the only network call is a version check every 6 hours (off with IRONHEIGHTS_NO_UPDATE=1).\n';

const REF =
  /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([a-z0-9](?:[a-z0-9-]{0,63}))(?:@([0-9A-Za-z][0-9A-Za-z.+-]{0,63}))?$/;

const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/;
const SHA256 = /^[a-f0-9]{64}$/;

const SkillResponseSchema = z
  .object({
    skill: z.object({ slug: z.string() }).passthrough(),
    latestVersion: z.object({ version: z.string() }).passthrough(),
    owner: z.object({ handle: z.string() }).passthrough(),
  })
  .passthrough();

const VersionResponseSchema = z
  .object({
    version: z
      .object({
        version: z.string(),
        files: z.array(
          z
            .object({
              path: z.string(),
              size: z.number().int().nonnegative(),
              sha256: z.string(),
            })
            .passthrough(),
        ),
      })
      .passthrough(),
  })
  .passthrough();

export interface SkillRef {
  owner: string;
  slug: string;
  version?: string;
}

export interface FetchLimits {
  maxFileBytes: number;
  maxFiles: number;
  maxDepth: number;
}

export interface DownloadResult {
  dir: string;
  version: string;
  fileCount: number;
}

export function parseSkillRef(input: string): SkillRef {
  const match = REF.exec(input);
  const owner = match?.[1];
  const slug = match?.[2];
  const version = match?.[3];
  if (!owner || !slug) throw new UsageError('expected <owner>/<slug> or <owner>/<slug>@<version>');
  if (version && !VERSION.test(version)) throw new UsageError('refusing version');
  return { owner, slug, ...(version ? { version } : {}) };
}

export function effectiveFetchLimits(limits: FetchLimits): FetchLimits {
  return {
    maxFileBytes: Math.min(limits.maxFileBytes, FETCH_HARD_MAX_FILE_BYTES),
    maxFiles: Math.min(limits.maxFiles, FETCH_HARD_MAX_FILES),
    maxDepth: Math.min(Math.max(limits.maxDepth, 1), 20),
  };
}

export function clawhubSkillUrl(slug: string, owner: string): string {
  const url = new URL(`/api/v1/skills/${encodeURIComponent(slug)}`, CLAWHUB_ORIGIN);
  url.searchParams.set('owner', owner);
  return url.toString();
}

export function clawhubVersionUrl(slug: string, version: string, owner: string): string {
  const url = new URL(
    `/api/v1/skills/${encodeURIComponent(slug)}/versions/${encodeURIComponent(version)}`,
    CLAWHUB_ORIGIN,
  );
  url.searchParams.set('owner', owner);
  return url.toString();
}

export function clawhubFileUrl(
  slug: string,
  version: string,
  owner: string,
  filePath: string,
): string {
  const url = new URL(`/api/v1/skills/${encodeURIComponent(slug)}/file`, CLAWHUB_ORIGIN);
  url.searchParams.set('owner', owner);
  url.searchParams.set('path', filePath);
  url.searchParams.set('version', version);
  return url.toString();
}

/**
 * Download a ClawHub skill as regular files. Nothing is executed and archives
 * are stored as bytes, never extracted.
 */
export async function downloadSkill(options: {
  ref: SkillRef;
  limits: FetchLimits;
  outDir?: string;
  log: (text: string) => void;
  fetchImpl?: typeof fetch;
}): Promise<DownloadResult> {
  const limits = effectiveFetchLimits(options.limits);
  const { ref } = options;
  const staging = await prepareStaging(ref.slug, options.outDir);
  try {
    options.log(`fetch ${ref.owner}/${ref.slug}${ref.version ? `@${ref.version}` : ''}\n`);
    options.log(NETWORK_BANNER);
    const listed = await fetchFileList(ref, options.log, options.fetchImpl);
    const files = validateFileList(listed.files, limits);
    const fileUrls = files.map((file) =>
      clawhubFileUrl(ref.slug, listed.version, ref.owner, file.path),
    );
    options.log(formatRequestPlan(fileUrls));
    for (const file of files) {
      const url = clawhubFileUrl(ref.slug, listed.version, ref.owner, file.path);
      const response = await pinnedGet(url, CLAWHUB_HOST, {
        maxBytes: limits.maxFileBytes,
        ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      });
      if (response.body.byteLength !== file.size) {
        throw new UsageError(`downloaded size does not match the file list: ${file.path}`);
      }
      const hash = createHash('sha256').update(response.body).digest('hex');
      if (hash !== file.sha256)
        throw new UsageError(`downloaded hash does not match the file list: ${file.path}`);
      // Store the bytes. Do not inflate zip, gzip, or tar members.
      await writeRegularFileInside(staging.dir, file.path, response.body, limits.maxDepth);
    }
    return { dir: staging.dir, version: listed.version, fileCount: files.length };
  } catch (error) {
    await cleanupStaging(staging);
    throw error;
  }
}

interface ListedFile {
  path: string;
  size: number;
  sha256: string;
}

async function fetchFileList(
  ref: SkillRef,
  log: (text: string) => void,
  fetchImpl: typeof fetch | undefined,
): Promise<{ version: string; files: ListedFile[] }> {
  const skillUrl = clawhubSkillUrl(ref.slug, ref.owner);
  const get = (url: string, maxBytes: number) =>
    pinnedGet(url, CLAWHUB_HOST, { maxBytes, ...(fetchImpl ? { fetchImpl } : {}) });

  if (ref.version) {
    const versionUrl = clawhubVersionUrl(ref.slug, ref.version, ref.owner);
    log(formatRequestPlan([skillUrl, versionUrl]));
    const skill = await readSkill(await get(skillUrl, METADATA_MAX_BYTES));
    confirmIdentity(ref, skill.slug, skill.owner);
    const version = await readVersion(await get(versionUrl, METADATA_MAX_BYTES));
    if (version.version !== ref.version)
      throw new UsageError('ClawHub returned a different version');
    return version;
  }

  log(formatRequestPlan([skillUrl]));
  const skill = await readSkill(await get(skillUrl, METADATA_MAX_BYTES));
  confirmIdentity(ref, skill.slug, skill.owner);
  if (!VERSION.test(skill.latestVersion)) throw new UsageError('refusing version from ClawHub');
  const versionUrl = clawhubVersionUrl(ref.slug, skill.latestVersion, ref.owner);
  log(formatRequestPlan([versionUrl]));
  const version = await readVersion(await get(versionUrl, METADATA_MAX_BYTES));
  if (version.version !== skill.latestVersion)
    throw new UsageError('ClawHub returned a different version');
  return version;
}

function confirmIdentity(ref: SkillRef, slug: string, owner: string): void {
  if (slug !== ref.slug || owner !== ref.owner) {
    throw new UsageError('ClawHub owner or slug did not match the requested skill');
  }
}

function readSkill(response: { body: Uint8Array }): {
  slug: string;
  owner: string;
  latestVersion: string;
} {
  const parsed = parseJson(
    response.body,
    SkillResponseSchema,
    'ClawHub skill response was not understood',
  );
  return {
    slug: parsed.skill.slug,
    owner: parsed.owner.handle,
    latestVersion: parsed.latestVersion.version,
  };
}

function readVersion(response: { body: Uint8Array }): { version: string; files: ListedFile[] } {
  const parsed = parseJson(
    response.body,
    VersionResponseSchema,
    'ClawHub version response was not understood',
  );
  return {
    version: parsed.version.version,
    files: parsed.version.files.map((file) => ({
      path: file.path,
      size: file.size,
      sha256: file.sha256,
    })),
  };
}

function parseJson<T>(body: Uint8Array, schema: z.ZodType<T>, message: string): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(body)) as unknown;
  } catch {
    throw new UsageError(message);
  }
  const result = schema.safeParse(parsed);
  if (!result.success) throw new UsageError(message);
  return result.data;
}

function validateFileList(files: ListedFile[], limits: FetchLimits): ListedFile[] {
  if (files.length > limits.maxFiles) {
    throw new UsageError(`refusing skill with more than ${limits.maxFiles} files`);
  }
  let total = 0;
  const seen = new Set<string>();
  for (const file of files) {
    if (file.path.includes('\\')) throw new UsageError(`refusing path traversal: ${file.path}`);
    safeRelativeParts(file.path, limits.maxDepth);
    if (!SHA256.test(file.sha256)) throw new UsageError(`refusing file hash: ${file.path}`);
    if (file.size > limits.maxFileBytes) {
      throw new UsageError(`refusing file larger than ${limits.maxFileBytes} bytes: ${file.path}`);
    }
    total += file.size;
    if (total > FETCH_HARD_MAX_TOTAL_BYTES) {
      throw new UsageError(`refusing skill larger than ${FETCH_HARD_MAX_TOTAL_BYTES} bytes`);
    }
    if (seen.has(file.path)) throw new UsageError(`refusing duplicate path: ${file.path}`);
    seen.add(file.path);
  }
  return files;
}

interface Staging {
  dir: string;
  parent: string;
  createdParent: boolean;
}

async function prepareStaging(slug: string, outDir: string | undefined): Promise<Staging> {
  if (!outDir) {
    const parent = await mkdtemp(join(tmpdir(), 'ironheights-fetch-'));
    const dir = join(parent, slug);
    await mkdir(dir, { mode: 0o700 });
    return { dir, parent, createdParent: true };
  }
  const resolved = resolve(outDir);
  let info;
  try {
    info = await lstat(resolved);
  } catch (error) {
    if (!isEnoent(error)) throw error;
    await mkdir(resolved, { recursive: true, mode: 0o700 });
    return { dir: resolved, parent: resolved, createdParent: true };
  }
  if (info.isSymbolicLink()) throw new UsageError('refusing staging directory that is a symlink');
  if (!info.isDirectory()) throw new UsageError('staging path is not a directory');
  if (await pathContainsSymlink(resolved)) {
    throw new UsageError('refusing staging directory that is reached through a symlink');
  }
  const real = stripLongPath(await realpath(resolved));
  const entries = await readdir(real);
  if (entries.length > 0) throw new UsageError('staging directory is not empty');
  return { dir: real, parent: real, createdParent: false };
}

async function cleanupStaging(staging: Staging): Promise<void> {
  if (staging.createdParent) {
    await rm(staging.parent, { recursive: true, force: true });
    return;
  }
  await rm(staging.dir, { recursive: true, force: true });
  await mkdir(staging.dir, { mode: 0o700 });
}

function isEnoent(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
