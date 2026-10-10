import { z } from 'zod';
import { NetworkError } from '../core/errors.ts';

const HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const HASH = /^(?:sha256:)?[a-f0-9]{64}$/;
const HTTPS_URL = /^https:\/\/[^\s]+$/;

function isIocHost(value: string): boolean {
  return HOST.test(value) || IPV4.test(value);
}

export const AdvisoryEntrySchema = z
  .object({
    id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/),
    skill: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
    owner: z
      .string()
      .regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/)
      .optional(),
    versions: z.array(z.string().regex(/^[A-Za-z0-9*][A-Za-z0-9.+-]{0,63}$/)).max(50),
    contentHashes: z.array(z.string().regex(HASH)).max(50),
    campaign: z.string().min(1).max(200),
    iocHosts: z.array(z.string().refine(isIocHost, 'must be a hostname or IPv4 address')).max(50),
    sources: z.array(z.string().regex(HTTPS_URL).max(300)).min(1).max(20),
    firstSeen: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    status: z.string().min(1).max(80),
  })
  .strict();

export const AdvisoryDocumentSchema = z
  .object({
    schemaVersion: z.literal(1),
    generatedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/),
    advisories: z.array(AdvisoryEntrySchema).max(5000),
  })
  .strict();

export type AdvisoryEntry = z.infer<typeof AdvisoryEntrySchema>;
export type AdvisoryDocument = z.infer<typeof AdvisoryDocumentSchema>;

export function parseAdvisoryDocument(raw: string): AdvisoryDocument {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new NetworkError('advisory feed is not valid JSON');
  }
  const result = AdvisoryDocumentSchema.safeParse(parsed);
  if (!result.success) {
    const issue = result.error.issues[0];
    const path = issue?.path.join('.') || '(root)';
    throw new NetworkError(`advisory feed does not match the schema at ${path}`);
  }
  return result.data;
}

export function normalizeContentHash(value: string): string {
  return value.replace(/^sha256:/, '').toLowerCase();
}
