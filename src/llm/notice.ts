import { LLM_API_KEY_ENV } from './constants.ts';
import type { ResolvedEndpoint } from './endpoint.ts';

export function formatNotice(input: {
  endpoint: ResolvedEndpoint;
  model: string;
  authorization: boolean;
  redactedSecrets: number;
  textChars: number;
  maxInputChars: number;
  dryRun: boolean;
  wire: string;
}): string {
  return [
    'LLM review notice',
    `POST ${input.endpoint.requestUrl}`,
    `API: ${input.endpoint.api}`,
    `Model: ${input.model}`,
    `Host: ${input.endpoint.host} (${input.endpoint.local ? 'localhost' : 'non-localhost'})`,
    `Authorization: ${
      input.authorization ? `${LLM_API_KEY_ENV} is set (value not printed)` : 'absent'
    }`,
    `Secrets redacted: ${input.redactedSecrets}`,
    `Skill text characters: ${input.textChars} (cap ${input.maxInputChars})`,
    input.dryRun
      ? 'Dry-run: the body below was not sent.'
      : 'The body below is exactly what will be sent.',
    'Request body:',
    input.wire,
  ].join('\n');
}
