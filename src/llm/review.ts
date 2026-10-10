import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { extensionOf } from '../core/filetype.ts';
import { walkSkill } from '../core/walker.ts';
import type { ResolvedConfig, ScannedFile, SkillReport } from '../core/types.ts';
import { LLM_API_KEY_ENV, LLM_RULE_ID, clampInputChars, skipNote } from './constants.ts';
import { postJson, type PostOptions, type PostResult } from './client.ts';
import { EndpointError, resolveEndpoint, type LlmApi, type ResolvedEndpoint } from './endpoint.ts';
import { attachAdvisoryFindings, notesToFindings } from './findings.ts';
import { formatNotice } from './notice.ts';
import { buildChat } from './prompt.ts';
import { modelText, parseReviewNotes } from './schema.ts';

export interface LlmSkillReview {
  skillName: string;
  status: 'ok' | 'skipped' | 'dry-run';
  endpoint: string;
  model: string;
  api: LlmApi;
  redactedSecrets: number;
  reason?: string;
}

export interface LlmReviewReport {
  enabled: true;
  advisory: true;
  status: 'ok' | 'skipped' | 'dry-run' | 'partial';
  reviews: LlmSkillReview[];
}

export interface ReviewInput {
  skills: SkillReport[];
  config: ResolvedConfig;
  url?: string;
  model?: string;
  api?: LlmApi;
  consent: boolean;
  dryRun: boolean;
  env: NodeJS.ProcessEnv;
  emit: (text: string) => void;
  post?: (options: PostOptions) => Promise<PostResult>;
}

export async function reviewSkills(
  input: ReviewInput,
): Promise<{ skills: SkillReport[]; report: LlmReviewReport }> {
  if (input.skills.length === 0) {
    input.emit(`${skipNote('no skill to review')}\n`);
    return {
      skills: input.skills,
      report: { enabled: true, advisory: true, status: 'skipped', reviews: [] },
    };
  }
  const skills: SkillReport[] = [];
  const reviews: LlmSkillReview[] = [];
  for (const skill of input.skills) {
    try {
      const result = await reviewOne(skill, input);
      skills.push(result.skill);
      reviews.push(result.review);
    } catch {
      input.emit(`${skipNote('model review failed')}\n`);
      skills.push(skill);
      reviews.push(
        skipped(skill.skillName, 'model review failed', {
          model: input.model ?? input.config.llm.model,
        }),
      );
    }
  }
  return {
    skills,
    report: { enabled: true, advisory: true, status: aggregateStatus(reviews), reviews },
  };
}

async function reviewOne(
  skill: SkillReport,
  input: ReviewInput,
): Promise<{ skill: SkillReport; review: LlmSkillReview }> {
  const model = input.model ?? input.config.llm.model;
  const rawUrl = input.url ?? input.config.llm.url;
  let endpoint: ResolvedEndpoint;
  try {
    endpoint = resolveEndpoint(rawUrl, input.api ?? input.config.llm.api);
  } catch (error) {
    const reason = error instanceof EndpointError ? error.message : 'invalid model URL';
    return finish(input, skill, skipped(skill.skillName, reason, { model }));
  }
  const base = {
    endpoint: endpoint.requestUrl,
    model,
    api: endpoint.api,
  };
  if (!input.dryRun && !endpoint.local && !input.consent) {
    return finish(
      input,
      skill,
      skipped(
        skill.skillName,
        `refusing to send skill text to ${endpoint.host} without --llm-consent`,
        base,
      ),
    );
  }
  const apiKey = readApiKey(input.env);
  if (!input.dryRun && !endpoint.local && !apiKey) {
    return finish(
      input,
      skill,
      skipped(
        skill.skillName,
        `refusing to send skill text to ${endpoint.host} without ${LLM_API_KEY_ENV}`,
        base,
      ),
    );
  }
  let files;
  try {
    files = await walkSkill(
      skill.root,
      input.config.limits,
      input.config.ignoreGlobs,
      input.config.ignoreDirs,
    );
  } catch {
    return finish(
      input,
      skill,
      skipped(skill.skillName, 'could not read the skill files again', base),
    );
  }
  const hydrated = await hydrateSkillText(
    skill.root,
    files.files,
    input.config.limits.maxFileBytes,
  );
  const built = buildChat({
    api: endpoint.api,
    model,
    skillName: skill.skillName,
    files: hydrated,
    findings: skill.findings.filter((finding) => finding.ruleId !== LLM_RULE_ID),
    skipped: skill.filesSkipped,
    maxInputChars: clampInputChars(input.config.llm.maxInputChars),
    ...(apiKey ? { apiKey } : {}),
  });
  const notice = formatNotice({
    endpoint,
    model,
    authorization: Boolean(apiKey),
    redactedSecrets: built.redactedSecrets,
    textChars: built.textChars,
    maxInputChars: built.maxInputChars,
    dryRun: input.dryRun,
    wire: built.wire,
  });
  input.emit(`${notice}\n`);
  if (input.dryRun) {
    return {
      skill,
      review: {
        skillName: skill.skillName,
        status: 'dry-run',
        endpoint: endpoint.requestUrl,
        model,
        api: endpoint.api,
        redactedSecrets: built.redactedSecrets,
      },
    };
  }
  const posted = await (input.post ?? postJson)({
    requestUrl: endpoint.requestUrl,
    wire: built.wire,
    timeoutMs: input.config.llm.timeoutMs,
    ...(apiKey ? { apiKey } : {}),
  });
  if (!posted.ok) {
    input.emit(`${skipNote(posted.reason)}\n`);
    return {
      skill,
      review: skipped(skill.skillName, posted.reason, {
        ...base,
        redactedSecrets: built.redactedSecrets,
      }),
    };
  }
  const content = modelText(endpoint.api, posted.body);
  if (!content.ok) {
    input.emit(`${skipNote(content.reason)}\n`);
    return {
      skill,
      review: skipped(skill.skillName, content.reason, {
        ...base,
        redactedSecrets: built.redactedSecrets,
      }),
    };
  }
  const parsed = parseReviewNotes(content.text);
  if (!parsed.ok) {
    input.emit(`${skipNote(parsed.reason)}\n`);
    return {
      skill,
      review: skipped(skill.skillName, parsed.reason, {
        ...base,
        redactedSecrets: built.redactedSecrets,
      }),
    };
  }
  const advisory = notesToFindings(parsed.notes, built.files);
  return {
    skill: attachAdvisoryFindings(skill, advisory),
    review: {
      skillName: skill.skillName,
      status: 'ok',
      endpoint: endpoint.requestUrl,
      model,
      api: endpoint.api,
      redactedSecrets: built.redactedSecrets,
    },
  };
}

function finish(
  input: ReviewInput,
  skill: SkillReport,
  review: LlmSkillReview,
): { skill: SkillReport; review: LlmSkillReview } {
  if (review.reason) input.emit(`${skipNote(review.reason)}\n`);
  return { skill, review };
}

function skipped(
  skillName: string,
  reason: string,
  partial: {
    endpoint?: string;
    model?: string;
    api?: LlmApi;
    redactedSecrets?: number;
  },
): LlmSkillReview {
  return {
    skillName,
    status: 'skipped',
    endpoint: partial.endpoint ?? 'unset',
    model: partial.model ?? 'unset',
    api: partial.api ?? 'ollama',
    redactedSecrets: partial.redactedSecrets ?? 0,
    reason,
  };
}

function aggregateStatus(reviews: LlmSkillReview[]): LlmReviewReport['status'] {
  if (reviews.length === 0) return 'skipped';
  const statuses = new Set(reviews.map((review) => review.status));
  if (statuses.size === 1) {
    const only = reviews[0]?.status ?? 'skipped';
    switch (only) {
      case 'ok':
      case 'skipped':
      case 'dry-run':
        return only;
      default: {
        const neverStatus: never = only;
        return neverStatus;
      }
    }
  }
  return 'partial';
}

const TEXT_EXTENSIONS = new Set([
  'md',
  'mdx',
  'markdown',
  'txt',
  'json',
  'js',
  'mjs',
  'cjs',
  'ts',
  'tsx',
  'py',
  'sh',
  'bash',
  'yml',
  'yaml',
]);

/**
 * The walker leaves text empty when a file contains a null byte. Read those
 * text extensions again so the null cannot hide the rest of the skill from
 * the review. Sanitize strips the null before the request is built.
 */
async function hydrateSkillText(
  root: string,
  files: ScannedFile[],
  maxFileBytes: number,
): Promise<ScannedFile[]> {
  const hydrated: ScannedFile[] = [];
  for (const file of files) {
    if (
      file.text.length > 0 ||
      file.archive ||
      file.symlinkOutside ||
      file.symlinkLoop ||
      file.size > maxFileBytes
    ) {
      hydrated.push(file);
      continue;
    }
    if (file.relativePath.startsWith('/') || file.relativePath.split('/').includes('..')) {
      hydrated.push(file);
      continue;
    }
    if (!TEXT_EXTENSIONS.has(extensionOf(file.relativePath))) {
      hydrated.push(file);
      continue;
    }
    try {
      const bytes = await readFile(join(root, file.relativePath));
      const text = new TextDecoder('utf-8', { fatal: false }).decode(
        bytes.subarray(0, maxFileBytes),
      );
      hydrated.push({ ...file, text });
    } catch {
      hydrated.push(file);
    }
  }
  return hydrated;
}

function readApiKey(env: NodeJS.ProcessEnv): string | undefined {
  const value = env[LLM_API_KEY_ENV];
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}
