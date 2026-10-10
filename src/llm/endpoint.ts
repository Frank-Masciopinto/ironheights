import { UsageError } from '../core/errors.ts';

export type LlmApi = 'ollama' | 'openai';

export interface ResolvedEndpoint {
  requestUrl: string;
  api: LlmApi;
  local: boolean;
  host: string;
}

export class EndpointError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EndpointError';
  }
}

/**
 * Loopback only. A name that merely ends in `.localhost`, or a public host
 * that happens to resolve to 127.0.0.1, still needs `--llm-consent`.
 */
export function isLocalHost(hostname: string): boolean {
  const host = hostname.replace(/\.$/, '').toLowerCase();
  if (host === 'localhost' || host === '::1' || host === '0.0.0.0' || host === '::ffff:127.0.0.1') {
    return true;
  }
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  if (!parts.every((part) => /^\d{1,3}$/.test(part))) return false;
  const nums = parts.map((part) => Number(part));
  if (nums.some((num) => num > 255)) return false;
  return nums[0] === 127;
}

export function parseLlmApi(value: string | undefined): LlmApi | undefined {
  switch (value) {
    case undefined:
      return undefined;
    case 'ollama':
    case 'openai':
      return value;
    default:
      throw new UsageError('--llm-api must be ollama or openai');
  }
}

export function resolveEndpoint(rawUrl: string, api: LlmApi | undefined): ResolvedEndpoint {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new EndpointError('model URL is not a valid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new EndpointError('model URL must be http or https');
  }
  if (url.username.length > 0 || url.password.length > 0) {
    throw new EndpointError('model URL must not contain a username or password');
  }
  if (hasSecretQuery(url)) {
    throw new EndpointError('put the API key in IRONHEIGHTS_LLM_API_KEY, not the model URL');
  }
  url.hash = '';
  const local = isLocalHost(url.hostname);
  const chosen = inferApi(url, local, api);
  return {
    requestUrl: applyPath(url, chosen),
    api: chosen,
    local,
    host: url.hostname,
  };
}

function inferApi(url: URL, local: boolean, requested: LlmApi | undefined): LlmApi {
  if (requested) return requested;
  const path = url.pathname.replace(/\/+$/, '');
  if (path.endsWith('/chat/completions') || path.endsWith('/v1')) return 'openai';
  if (path.endsWith('/api/chat')) return 'ollama';
  return local ? 'ollama' : 'openai';
}

function applyPath(url: URL, api: LlmApi): string {
  const path = url.pathname.replace(/\/+$/, '');
  switch (api) {
    case 'ollama':
      if (path.endsWith('/api/chat')) return url.toString();
      url.pathname = path === '' ? '/api/chat' : `${path}/api/chat`;
      return url.toString();
    case 'openai':
      if (path.endsWith('/chat/completions')) return url.toString();
      if (path.endsWith('/v1')) {
        url.pathname = `${path}/chat/completions`;
        return url.toString();
      }
      url.pathname = path === '' ? '/v1/chat/completions' : `${path}/v1/chat/completions`;
      return url.toString();
    default: {
      const neverApi: never = api;
      return neverApi;
    }
  }
}

function hasSecretQuery(url: URL): boolean {
  for (const key of url.searchParams.keys()) {
    const name = key.toLowerCase().replace(/-/g, '_');
    if (
      name === 'key' ||
      name === 'api_key' ||
      name === 'apikey' ||
      name === 'token' ||
      name === 'access_token' ||
      name === 'secret'
    ) {
      return true;
    }
  }
  return false;
}
