# Release verification

The release workflow (`.github/workflows/release.yml`) stages the npm package with `npm stage publish --provenance --access public`; the maintainer approves it on npmjs.com with 2FA. The same job packs the tarball, writes a CycloneDX SBOM `ironheights-X.Y.Z.cdx.json`, and writes `SHA256SUMS`. A second job requests a GitHub artifact attestation (Sigstore-signed SLSA provenance) for all three and attaches them, plus the bundle `ironheights-X.Y.Z.intoto.jsonl`, to the GitHub release for tag `vX.Y.Z`. Every asset name carries the release version.

`SHA256SUMS` uses the `sha256sum` line format:

```text
<64 hex characters><two spaces><file name>
```

## Check a download

```bash
gh release download vX.Y.Z --pattern 'SHA256SUMS' --pattern 'ironheights-*.tgz' --pattern 'ironheights-*.cdx.json'
sha256sum -c SHA256SUMS
gh attestation verify SHA256SUMS --repo Frank-Masciopinto/ironheights
gh attestation verify ironheights-*.tgz --repo Frank-Masciopinto/ironheights
```

## Check who built the release

The expected author is the GitHub Actions workflow `Frank-Masciopinto/ironheights/.github/workflows/release.yml` running on a `refs/tags/v*` ref, and the npm package `ironheights` is owned by the npm account `ironheights`.

```bash
# npm registry copy: verifies registry signatures and Sigstore provenance
npm install ironheights@X.Y.Z && npm audit signatures
# show the provenance: source repo, commit and workflow that built it
npm view ironheights@X.Y.Z --json | jq .dist.attestations
# GitHub release assets: pin the signer workflow
gh attestation verify ironheights-X.Y.Z.tgz --repo Frank-Masciopinto/ironheights \
  --signer-workflow Frank-Masciopinto/ironheights/.github/workflows/release.yml
```

The npm package page also shows a "Built and signed on GitHub Actions" provenance badge linking to the exact commit and workflow run. Reject a package or asset whose provenance names any other repository or workflow.

The checksum files are produced at release time. They are not committed. There is no release private key in this repository. The attestation uses GitHub's OIDC token, the same identity the npm provenance publish already uses.
