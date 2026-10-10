import { NetworkError, UsageError } from '../core/errors.ts';
import { TOOL_VERSION, REPOSITORY_URL } from '../version.ts';

const REQUEST_TIMEOUT_MS = 20_000;

export interface PinnedGetOptions {
  fetchImpl?: typeof fetch;
  maxBytes: number;
}

export interface PinnedResponse {
  url: string;
  body: Uint8Array;
}

/**
 * GET one https URL on an exact host. Redirects are refused. The response
 * body is capped. This is the only HTTP helper the CLI uses.
 */
export async function pinnedGet(
  rawUrl: string,
  host: string,
  options: PinnedGetOptions,
): Promise<PinnedResponse> {
  const url = assertPinnedUrl(rawUrl, host);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  let response: Response;
  try {
    response = await fetchImpl(url.toString(), {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      headers: {
        accept: 'application/octet-stream, application/json;q=0.9, */*;q=0.1',
        'user-agent': `ironheights/${TOOL_VERSION} (+${REPOSITORY_URL})`,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'request failed';
    throw new NetworkError(`request failed for ${url.toString()}: ${message}`);
  }
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new UsageError(`refusing redirect from ${url.toString()}`);
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new NetworkError(`GET ${url.toString()} returned ${response.status}`);
  }
  const body = await readCapped(response, options.maxBytes, url.toString());
  return { url: url.toString(), body };
}

export function assertPinnedUrl(rawUrl: string, host: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UsageError('refusing URL');
  }
  if (url.protocol !== 'https:') throw new UsageError(`refusing non-https URL: ${url.origin}`);
  if (url.username !== '' || url.password !== '')
    throw new UsageError('refusing URL with userinfo');
  if (url.hostname !== host) throw new UsageError(`refusing host ${url.hostname}`);
  if (url.port !== '' && url.port !== '443') throw new UsageError('refusing non-443 port');
  return url;
}

export function formatRequestPlan(urls: readonly string[]): string {
  return `Requesting:\n${urls.map((url) => `  GET ${url}`).join('\n')}\n`;
}

async function readCapped(response: Response, maxBytes: number, url: string): Promise<Uint8Array> {
  const declared = Number(response.headers.get('content-length') ?? '');
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel();
    throw new UsageError(`response exceeds ${maxBytes} bytes: ${url}`);
  }
  if (!response.body) {
    const buffered = new Uint8Array(await response.arrayBuffer());
    if (buffered.byteLength > maxBytes)
      throw new UsageError(`response exceeds ${maxBytes} bytes: ${url}`);
    return buffered;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const step = await reader.read();
      if (step.done) break;
      total += step.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new UsageError(`response exceeds ${maxBytes} bytes: ${url}`);
      }
      chunks.push(step.value);
    }
  } catch (error) {
    if (error instanceof UsageError || error instanceof NetworkError) throw error;
    throw new NetworkError(`request failed for ${url}`);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}
