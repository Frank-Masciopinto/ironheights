/**
 * Cloud metadata reach and reachable-host diff for the posture report (0.31.0).
 *
 * The metadata row is its own result. Cells that this run did not test stay
 * `untested` and are never copied from another environment or an earlier report.
 * The probe runs only when the caller opts in.
 */
export const METADATA_HOST = '169.254.169.254';
const METADATA_URL = `http://${METADATA_HOST}/latest/meta-data/`;
const HOP_HEADER = 'x-aws-ec2-metadata-hop-limit';

export type ReachCell = 'reachable' | 'unreachable' | 'untested';
export type ImdsCell = 'required' | 'not-required' | 'untested';

export interface CloudMetadataRow {
  target: typeof METADATA_HOST;
  /** Environment this row was measured in. It is not reused for a different one. */
  environment: string;
  reachable: ReachCell;
  imdsv2: ImdsCell;
  hopLimit: number | 'untested';
}

export interface HostRef {
  host: string;
  skill?: string;
  repo?: string;
  /** Set when the source names a process. Omitted when it does not. */
  process?: string;
}

export interface HostDiff {
  measuredEnvironment: string;
  previousEnvironment: string | null;
  added: HostRef[];
  removed: HostRef[];
  unchanged: HostRef[];
}

export function untestedMetadata(environment: string): CloudMetadataRow {
  return {
    target: METADATA_HOST,
    environment,
    reachable: 'untested',
    imdsv2: 'untested',
    hopLimit: 'untested',
  };
}

function hopOf(headers: Headers | undefined): number | 'untested' {
  const raw = headers?.get(HOP_HEADER);
  if (!raw) return 'untested';
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) return 'untested';
  return n;
}

/**
 * Probe the link-local metadata address. Redirects are not followed. A failure to
 * connect is `unreachable`; an HTTP answer is `reachable`. IMDSv2 is `required` only
 * on the AWS 401-without-a-token response, and `not-required` only when a tokenless
 * GET returns 200. Anything else, including hop limit when the header is absent,
 * stays `untested`.
 */
export async function probeCloudMetadata(
  environment: string,
  opts: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<CloudMetadataRow> {
  const row = untestedMetadata(environment);
  const fetchImpl = opts.fetchImpl ?? fetch;
  let res: Response;
  try {
    res = await fetchImpl(METADATA_URL, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(opts.timeoutMs ?? 1500),
    });
  } catch {
    row.reachable = 'unreachable';
    return row;
  }
  row.reachable = 'reachable';
  row.hopLimit = hopOf(res.headers);
  if (res.status === 401) row.imdsv2 = 'required';
  else if (res.status === 200) row.imdsv2 = 'not-required';
  return row;
}

const keyOf = (h: HostRef): string =>
  `${h.host.toLowerCase()}\0${h.skill ?? ''}\0${h.repo ?? ''}\0${h.process ?? ''}`;

/** Diff two host lists. Attribution is kept from the side that named the skill or process. */
export function diffHosts(
  current: HostRef[],
  previous: HostRef[],
  measuredEnvironment: string,
  previousEnvironment: string | null,
): HostDiff {
  const prev = new Map(previous.map((h) => [keyOf(h), h]));
  const now = new Map(current.map((h) => [keyOf(h), h]));
  const added: HostRef[] = [];
  const removed: HostRef[] = [];
  const unchanged: HostRef[] = [];
  for (const [k, h] of now) {
    if (prev.has(k)) unchanged.push(h);
    else added.push(h);
  }
  for (const [k, h] of prev) if (!now.has(k)) removed.push(h);
  const byHost = (a: HostRef, b: HostRef): number =>
    a.host.localeCompare(b.host) || (a.skill ?? '').localeCompare(b.skill ?? '');
  added.sort(byHost);
  removed.sort(byHost);
  unchanged.sort(byHost);
  return { measuredEnvironment, previousEnvironment, added, removed, unchanged };
}
