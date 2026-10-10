import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { clip } from '../util/text.ts';
import { LLM_MAX_RESPONSE_BYTES } from './constants.ts';

export interface PostOptions {
  requestUrl: string;
  wire: string;
  apiKey?: string;
  timeoutMs: number;
  maxResponseBytes?: number;
}

export type PostResult = { ok: true; body: string } | { ok: false; reason: string };

export async function postJson(options: PostOptions): Promise<PostResult> {
  const maxResponseBytes = options.maxResponseBytes ?? LLM_MAX_RESPONSE_BYTES;
  let url: URL;
  try {
    url = new URL(options.requestUrl);
  } catch {
    return { ok: false, reason: 'model URL is not a valid URL' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: 'model URL must be http or https' };
  }
  const headers: Record<string, string> = {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(options.wire)),
    connection: 'close',
    'user-agent': 'ironheights',
  };
  if (options.apiKey) headers.authorization = `Bearer ${options.apiKey}`;
  const transport = url.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: PostResult): void => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const req = transport(url, { method: 'POST', headers, timeout: options.timeoutMs }, (res) => {
      const status = res.statusCode ?? 0;
      if (status >= 300 && status < 400) {
        res.resume();
        finish({
          ok: false,
          reason: 'the model server returned a redirect, which ironheights does not follow',
        });
        return;
      }
      if (status < 200 || status >= 300) {
        res.resume();
        finish({ ok: false, reason: `the model server returned HTTP ${status}` });
        return;
      }
      const chunks: Buffer[] = [];
      let total = 0;
      res.on('data', (chunk: Buffer) => {
        if (settled) return;
        total += chunk.length;
        if (total > maxResponseBytes) {
          finish({ ok: false, reason: `response exceeds ${maxResponseBytes} bytes` });
          res.destroy();
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (settled) return;
        finish({ ok: true, body: Buffer.concat(chunks).toString('utf8') });
      });
      res.on('error', () => {
        if (settled) return;
        finish({ ok: false, reason: 'could not read the model response' });
      });
    });
    req.setTimeout(options.timeoutMs);
    req.on('timeout', () => {
      finish({ ok: false, reason: `timed out after ${options.timeoutMs}ms` });
      req.destroy();
    });
    req.on('error', (error) => {
      finish({
        ok: false,
        reason: `could not reach the model server (${clip(error.message, 160)})`,
      });
    });
    req.write(options.wire);
    req.end();
  });
}
