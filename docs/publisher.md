# Publisher / Registry tools

New in 0.26.0, open and opt-in. Ironheights protects any AI bot that installs it; these tools let skill authors and marketplaces such as ClawHub publish proof of what was checked. Nothing is sold and detection is unchanged.

## ClawHub attestations

`ironheights attest owner/slug@version [--out file] [--badge file]` fetches the skill read-only (GET requests only, into a temp folder that is deleted afterwards; nothing is installed), scans it and writes a signed attestation. Besides the content digest, verdict, version and rule-set hash, the statement records `source` (`registry: clawhub`, ref, owner, slug, version) and `publisher` (the owner handle). Only `no-findings` is marked verified.

`ironheights attest owner/slug@version --verify file.json [--public-key key.pem]` fetches the same ref again and fails if the bytes changed, the attestation is for another ref, it expired or the signature is wrong.

## Batch attest

`ironheights attest --batch skills.txt [--out-dir attestations]` attests every listed skill (ClawHub refs or local folders, one per line with `#` comments, or a JSON array of strings). Each gets an attestation and badge in the output folder, and `batch-summary.json` lists every item with verdict, digest and publisher, plus counts (total, verified, not verified, errors). A skill that could not be fetched or scanned is listed with its error and is never counted as verified. The summary is signed with the local key. Exit 0 only when every item is verified.

## Publisher reputation

`ironheights publisher reputation [publisher] [--min-skills 3] [--out file] [--json]` builds a signed report from the attestations retained on this machine. It refuses to run if the retention store fails verification.

Methodology (`ironheights-reputation/1`, also embedded in every report):

1. Inputs are attestation records in the local signed retention store that carry a ClawHub publisher. Local-folder attestations are ignored. Nothing is fetched, estimated or filled in.
2. Per publisher, each skill (slug) counts once, using its most recent attestation.
3. Counts are verified (`no-findings`), review, block and incomplete, taken from those latest attestations. `everBlocked` counts slugs that had any block attestation in their history.
4. Tier:
   - `insufficient-data` with fewer than `--min-skills` skills (default 3)
   - `flagged` when any latest verdict is block
   - `mixed` when any latest verdict is review or incomplete, or any slug was ever blocked
   - `clean` when every latest verdict is verified
5. There is no numeric score and no weighting. A reputation reflects only what this machine attested, with the Ironheights version and rule set in use, and says nothing about skills it never saw.
