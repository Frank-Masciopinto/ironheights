import type { UnscannedDependency } from '../core/dependencies.ts';
import { TOOL_VERSION, REPOSITORY_URL } from '../version.ts';

export type RegistryStatus = 'exists' | 'missing' | 'unknown';

export interface RegistryCheckResult {
  dependency: UnscannedDependency;
  status: RegistryStatus;
  /** Why the status is unknown (offline, timeout, unexpected HTTP status). */
  detail?: string;
}

const TIMEOUT_MS = 5_000;
const MAX_CHECKS = 25;

/** The exact registry URL for a package name, or undefined when the manager is not checked. */
export function registryUrl(dep: UnscannedDependency): URL | undefined {
  if (dep.manager === 'npm') {
    if (!/^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i.test(dep.name)) return undefined;
    return new URL(`https://registry.npmjs.org/${dep.name.replace('/', '%2F')}`);
  }
  if (dep.manager === 'pypi') {
    if (!/^[a-z0-9][\w.-]*$/i.test(dep.name)) return undefined;
    return new URL(`https://pypi.org/pypi/${encodeURIComponent(dep.name)}/json`);
  }
  return undefined;
}

/**
 * Ask npm and PyPI whether each install name exists. Only a 404 counts as missing. A network
 * error, timeout, redirect or other status is `unknown`, so an offline scan never reports a
 * package as missing. Bodies are not read.
 */
export async function checkRegistry(
  deps: readonly UnscannedDependency[],
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<RegistryCheckResult[]> {
  const targets = deps.filter((dep) => registryUrl(dep) !== undefined).slice(0, MAX_CHECKS);
  return Promise.all(
    targets.map(async (dependency): Promise<RegistryCheckResult> => {
      const url = registryUrl(dependency);
      if (!url) return { dependency, status: 'unknown', detail: 'not checkable' };
      try {
        const response = await fetchImpl(url.toString(), {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(TIMEOUT_MS),
          headers: {
            accept: 'application/json',
            'user-agent': `ironheights/${TOOL_VERSION} (+${REPOSITORY_URL})`,
          },
        });
        await response.body?.cancel().catch(() => undefined);
        if (response.status === 404) return { dependency, status: 'missing' };
        if (response.status >= 200 && response.status < 300) {
          return { dependency, status: 'exists' };
        }
        return { dependency, status: 'unknown', detail: `HTTP ${response.status}` };
      } catch (error) {
        const detail = error instanceof Error ? error.message : 'request failed';
        return { dependency, status: 'unknown', detail: detail.slice(0, 120) };
      }
    }),
  );
}
