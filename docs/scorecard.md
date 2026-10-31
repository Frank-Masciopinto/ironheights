# OpenSSF Scorecard notes

## Branch-Protection check needs a token

The default `GITHUB_TOKEN` cannot read classic branch protection, so the
Branch-Protection check errors. To fix it:

1. Create a fine-grained personal access token at
   <https://github.com/settings/personal-access-tokens/new>:
   - Resource owner: `Frank-Masciopinto`, repository access: only `ironheights`.
   - Repository permissions: **Administration: Read-only** (plus the default
     Metadata: Read-only). Nothing else.
   - Expiry: up to 1 year; set a reminder to rotate it.
2. Add it as an Actions secret named `SCORECARD_TOKEN`
   (Settings → Secrets and variables → Actions → New repository secret), or:
   `gh secret set SCORECARD_TOKEN --repo Frank-Masciopinto/ironheights`.
3. Re-run the `OpenSSF Scorecard` workflow.

`scorecard.yml` uses `secrets.SCORECARD_TOKEN || github.token`, so it keeps
working without the secret.

## Checks that depend on time or people

- **Code-Review**: counts merged changes approved by a second person.
- **Maintained**: needs the repository to be older than 90 days.
- **Contributors**: needs recent contributors from several organizations.
- **CII-Best-Practices**: sign in at <https://www.bestpractices.dev> with GitHub;
  answers are in `docs/openssf-best-practices.md`.
- **Branch-Protection**: needs `SCORECARD_TOKEN`; a 10 also needs required
  reviews, status checks, and admin enforcement (maintainer decision).

## Signed releases

`release.yml` attaches a Sigstore-signed SLSA provenance bundle
(`ironheights-<version>.intoto.jsonl`) to each GitHub release.
`release-provenance.yml` (manual) backfills the same for existing releases by
attesting the assets already on them; it never rebuilds or publishes to npm.

## Binary artifacts and fuzzing

Binary test fixtures for IH-BIN-001/002 are written at test time by
`test/support/binary-fixtures.ts`. Property-based fuzz tests (fast-check) live
in `test/fuzz/`; raise `FUZZ_RUNS` for a longer local run.
