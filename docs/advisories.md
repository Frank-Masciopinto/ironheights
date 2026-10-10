# Advisory feed

`scan` and `fetch` stay offline. They read a signed cache under `$IRONHEIGHTS_HOME` (default `~/.ironheights`) when one exists. They do not download the feed. `ironheights advisories update` and `ironheights --online` are the only commands that fetch it.

The feed URL is fixed:

- `https://ironheights.dev/advisories.json`
- `https://ironheights.dev/advisories.json.sig`

Both requests are HTTPS, host `ironheights.dev` only, with redirects refused. The CLI prints those URLs before it requests them. There is no telemetry and no client id.

## What a match means

`IH-ADV-001` is critical. A match on skill name, content hash, or IOC host blocks `safe-install`. The `status` string is copied from the source and shown in the finding. The CLI does not map that string onto a severity. If a row should not block, leave it out of the feed. `ruleOverrides` can disable `IH-ADV-001` or lower its severity for a local config.

Name matching is case-insensitive against the skill folder and the `name` in `SKILL.md`. An empty `versions` list, or a list that contains `*`, matches every version. Otherwise the skill's frontmatter `version` must be listed. A hash match does not depend on the version or the name. An IOC host matches only as a whole host (`evil.example` does not match `notevil.example` or `evil.example.com`).

When `fetch` or `safe-install` knows the publisher handle, a name match also requires `owner` if the advisory sets it. A local `scan` does not know the publisher, so a slug match applies even when `owner` is set. Hash and host matches do not use `owner`.

A missing cache is not an error. `scan` reports nothing from the feed. A cache that fails the signature check, or a production public key that is still `UNCONFIGURED`, stops the command with exit code 70. The bad cache is not used.

## Document

`schemaVersion` is `1`. The signature is over the exact file bytes, not a re-parsed object. See [advisories.schema.json](advisories.schema.json).

```json
{
  "schemaVersion": 1,
  "generatedAt": "2026-10-10T00:00:00.000Z",
  "advisories": [
    {
      "id": "IH-2026-0001",
      "skill": "evil-skill",
      "owner": "some-publisher",
      "versions": ["1.2.3"],
      "contentHashes": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
      "campaign": "example-campaign",
      "iocHosts": ["evil.example"],
      "sources": ["https://ironheights.dev/tracker/example-campaign"],
      "firstSeen": "2026-10-01",
      "status": "malicious"
    }
  ]
}
```

`status` is the status stated by the source, for example `malicious` or `suspicious`. `sources` are https URLs. `contentHashes` are sha256 hex, with an optional `sha256:` prefix in the source file.

The detached signature file is one line:

```text
ed25519 <base64 of the 64-byte signature>
```

## Signing procedure

The production private key is not in this repository. Do not generate it on a shared machine and do not commit it.

1. On a machine you control, create a key file outside the repo:

   ```bash
   node scripts/generate-advisory-key.mjs --out "$HOME/ironheights-advisory.key"
   ```

   The command prints the public key and writes the seed with mode `0600`.

2. Put that public key in `src/advisories/pinned-key.ts` as `PINNED_ADVISORY_PUBLIC_KEY_HEX` (64 lowercase hex characters, no `sha256:` prefix). Until that constant replaces `UNCONFIGURED`, the CLI refuses every feed.

3. Ship a CLI release that contains the public key. The feed published before that release cannot be trusted by older binaries, and a binary that still says `UNCONFIGURED` will keep refusing.

4. Build a source file from the tracker. The signing script adds `schemaVersion`, sorts entries, and strips `sha256:` from hashes. `status` must be the status the tracker states, not a status invented for the feed.

   ```json
   {
     "generatedAt": "2026-10-10T00:00:00.000Z",
     "advisories": []
   }
   ```

5. Sign it:

   ```bash
   node scripts/sign-advisories.mjs \
     --source tracker-source.json \
     --key "$HOME/ironheights-advisory.key" \
     --out advisories.json
   ```

   That writes `advisories.json` and `advisories.json.sig`. The script prints the public key again so you can confirm it matches the pinned constant.

`test/fixtures/advisories/test-private.hex` is a test key. It is not the production key. Do not sign a feed you publish with it.

## What the website needs to publish

Publish both files together, with no redirect:

| URL                                           | Body                   |
| --------------------------------------------- | ---------------------- |
| `https://ironheights.dev/advisories.json`     | the signed JSON        |
| `https://ironheights.dev/advisories.json.sig` | the detached signature |

`Content-Type` can be `application/json` and `text/plain`. The CLI checks the bytes and the signature, not the content type. A redirect, including to the same host, is refused.

Build the source file from the public tracker. Map each row as follows:

| Tracker field                | Feed field                                       |
| ---------------------------- | ------------------------------------------------ |
| skill slug                   | `skill`                                          |
| publisher handle, when known | `owner`                                          |
| affected versions            | `versions` (`[]` or `["*"]` means every version) |
| file or bundle sha256        | `contentHashes`                                  |
| campaign name                | `campaign`                                       |
| indicator hosts              | `iocHosts`                                       |
| write-up URLs                | `sources` (https only, at least one)             |
| first-seen date              | `firstSeen` (`YYYY-MM-DD`)                       |
| status stated by the source  | `status`                                         |

Give each row a stable `id`. Re-sign and replace both URLs when the tracker changes. Upload the pair together so a client cannot cache a new JSON file with the previous signature. Clients that already have a good cache keep it when a later download fails verification.

Rotating the key is a CLI release first, then a newly signed feed. The website and `pinned-key.ts` have to move together.
