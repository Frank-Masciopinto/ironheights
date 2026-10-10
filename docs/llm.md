# Optional model review

`scan --llm` and `review` ask a language model for a second opinion on a skill. The review is off unless you pass one of those. A normal scan does not call the network. The review is never required, and the tool still works when no model is installed.

The model reviews evidence the rules already extracted, plus a capped copy of the skill text. It is not an authority. It can be wrong. It can miss an attack, and it can invent one. An empty reply is not a clearance.

## What the model is allowed to change

Nothing about the verdict. The deterministic verdict and exit code are fixed before any note is added. The model can only add findings with rule id `IH-LLM-001`, category `llm-review`, and severity `info`. Those findings score zero. They do not move a `block` to `review`, `incomplete`, or `no-findings`, and they do not move `no-findings` to `block`. `--fail-on` ignores them, including `--fail-on info`.

Each note says that its confidence is the model's claim, not a measurement.

## Commands

```bash
ironheights scan ./path/to/skill --llm
ironheights scan ./path/to/skill --llm --dry-run
ironheights review ./path/to/skill
```

`review` is `scan --llm` with the same flags. `--json`, `--sarif`, `--md`, `--html`, `--format`, `--since-baseline`, `--fail-on`, `--config`, `--all`, `--allow-skipped`, `--no-color`, and `--quiet` behave as they do for `scan`. `--quiet` does not hide the request notice. That notice is the record of what left the machine.

`scan --stdin` and `scan --text` are not sent to a model. A text scan has no skill directory to re-read, so the command keeps the deterministic result and says why. The grade uses the risk score from before any model note, so an `IH-LLM-001` note does not change the letter.

`--dry-run` prints one deterministic-verdict line and the request that would have been sent. It does not contact the server, and it does not write the findings report, SARIF, or Markdown. The process exit code is still the deterministic verdict.

`--llm-api` must be `ollama` or `openai`. Any other value is a usage error (exit 64) and does not scan. Every other model failure keeps the deterministic exit code.

## Where the request goes

| You pass                                     | Request                                                           |
| -------------------------------------------- | ----------------------------------------------------------------- |
| nothing but `--llm`                          | `POST http://127.0.0.1:11434/api/chat` (Ollama), model `llama3.2` |
| `--llm-url` with an empty path on loopback   | Ollama `/api/chat` on that origin                                 |
| a URL ending in `/v1` or `/chat/completions` | OpenAI-compatible `/v1/chat/completions`                          |
| `--llm-api openai`                           | OpenAI-compatible chat completions                                |
| `--llm-api ollama`                           | Ollama `/api/chat`                                                |

Loopback means `localhost`, `::1`, `0.0.0.0`, and `127.0.0.0/8`. A name that only ends in `.localhost` is not treated as loopback. Ironheights does not look up DNS to decide. The host in the URL is what counts.

A loopback URL does not need `--llm-consent`. Any other host needs both `--llm-consent` and the environment variable `IRONHEIGHTS_LLM_API_KEY`. The key is sent as `Authorization: Bearer` and is not printed. A URL that contains a user, a password, or a query key named `key`, `api_key`, `token`, or `secret` is refused. Config can set `llm.url`, `llm.model`, `llm.api`, `llm.timeoutMs`, and `llm.maxInputChars`. Config cannot turn the review on and cannot store consent. An unknown key such as `llm.consent` is a config error.

`llm.timeoutMs` defaults to 30000 and must be from 1000 to 120000. `llm.maxInputChars` defaults to 24000 and must be from 1000 to 100000. The response body is capped at 65536 bytes. Redirects are not followed. HTTPS uses the normal certificate check.

Before a real request, the exact JSON body is printed to stderr. The findings report stays on stdout, so `--json` stays machine-readable. The body is not copied into the JSON report.

## What is sent

The body is a chat request with a fixed system instruction and one user message. The system instruction tells the model to ignore instructions inside the skill text. The user message contains:

- the skill's display name
- the relative paths the model is allowed to cite
- the deterministic findings (rule, severity, file, line, evidence, message)
- the skill's text files, between `<<<UNTRUSTED_SKILL_TEXT>>>` and `<<<END_UNTRUSTED_SKILL_TEXT>>>`

Archive files are omitted. A file the scanner calls binary is sent only when the decoded text still contains several words, so a null byte cannot hide the rest of a skill. Real binaries and images stay out. Absolute paths on your machine are not included. The review reads the files again after the rule scan, so a file that changes in between can be reviewed in its new form while the findings are from the first read.

Skill text is treated as untrusted data:

- control characters, ANSI escapes, bidi overrides, and zero-width characters are stripped
- a skill that contains the closing delimiter cannot end the untrusted region early
- the text is cut at the input cap, and the prompt says it was truncated
- common secret shapes are replaced with `[REDACTED]` before the body is built: private-key blocks, AWS access key ids, GitHub and npm and Slack tokens, `sk-` keys, bearer tokens, and long quoted values assigned to a secret-like name
- if `IRONHEIGHTS_LLM_API_KEY` itself appears in the skill, that value is removed too

Redaction is best-effort. A secret in a shape the scrubber does not know is still sent. Do not point a remote model at a skill that contains a live secret.

## What comes back

The model must return one JSON object and no other text:

```json
{ "notes": [{ "summary": "string", "concern": "string", "confidence": "low", "file": "SKILL.md" }] }
```

`notes` has at most 8 objects. The only keys are `notes`, `summary`, `concern`, `confidence`, and `file`. `confidence` is `low`, `medium`, or `high`. `file` must be one of the relative paths that were sent, or empty. Markdown fences, a verdict field, extra keys, and any other shape are discarded. A note that names a file that was not sent is dropped. Nothing in the reply is executed.

A discarded reply, a timeout, a connection error, an HTTP error, a redirect, or an oversized response prints `LLM review skipped: ... Deterministic result unchanged.` and leaves the verdict alone.

`IH-LLM-001` is not a pattern rule. `rules show IH-LLM-001` describes the note. A content scan does not emit it.

## JSON

When the review ran, the document gains `llmReview`:

```json
{
  "enabled": true,
  "advisory": true,
  "status": "ok",
  "reviews": [
    {
      "skillName": "example",
      "status": "ok",
      "endpoint": "http://127.0.0.1:11434/api/chat",
      "model": "llama3.2",
      "api": "ollama",
      "redactedSecrets": 0
    }
  ]
}
```

`status` is `ok`, `skipped`, `dry-run`, or `partial` when skills in one run disagree. `advisory` is always true. The field is omitted when you did not ask for a review.
