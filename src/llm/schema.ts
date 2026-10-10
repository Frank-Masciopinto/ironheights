import { z } from 'zod';
import type { LlmApi } from './endpoint.ts';
import { LLM_MAX_NOTES } from './constants.ts';

const noteSchema = z
  .object({
    summary: z.string().min(1).max(400),
    concern: z.string().min(1).max(400),
    confidence: z.enum(['low', 'medium', 'high']),
    file: z.string().max(300).optional(),
  })
  .strict();

const responseSchema = z
  .object({
    notes: z.array(noteSchema).max(LLM_MAX_NOTES),
  })
  .strict();

export type ReviewNote = z.infer<typeof noteSchema>;

export type ParseResult = { ok: true; notes: ReviewNote[] } | { ok: false; reason: string };

/** Accept only a single JSON object of the review schema. Discard everything else. */
export function parseReviewNotes(content: string): ParseResult {
  const trimmed = content.replace(/^\uFEFF/, '').trim();
  if (trimmed.length === 0) return { ok: false, reason: 'model output was empty' };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed) as unknown;
  } catch {
    return { ok: false, reason: 'model output was not JSON' };
  }
  const result = responseSchema.safeParse(parsed);
  if (!result.success) return { ok: false, reason: 'model output did not match the review schema' };
  return { ok: true, notes: result.data.notes };
}

export function modelText(
  api: LlmApi,
  raw: string,
): { ok: true; text: string } | { ok: false; reason: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return { ok: false, reason: 'the model server response was not JSON' };
  }
  const text = extractContent(api, parsed);
  if (text === undefined) {
    return { ok: false, reason: 'the model server response did not include message text' };
  }
  return { ok: true, text };
}

function extractContent(api: LlmApi, payload: unknown): string | undefined {
  switch (api) {
    case 'ollama':
      return stringField(recordField(payload, 'message'), 'content');
    case 'openai': {
      const choices = recordField(payload, 'choices');
      if (!Array.isArray(choices) || choices.length === 0) return undefined;
      return stringField(recordField(choices[0], 'message'), 'content');
    }
    default: {
      const neverApi: never = api;
      return neverApi;
    }
  }
}

function recordField(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return (value as Record<string, unknown>)[key];
}

function stringField(value: unknown, key: string): string | undefined {
  const field = recordField(value, key);
  return typeof field === 'string' ? field : undefined;
}
