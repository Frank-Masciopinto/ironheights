# Release verification

The release workflow still publishes to npm with `npm publish --provenance --access public`. After that publish succeeds, the same job packs the tarball again, writes `SHA256SUMS`, and a second job attaches both files to the GitHub release for the tag. The checksum job also requests a GitHub artifact attestation for `SHA256SUMS` and the tarball.

`SHA256SUMS` uses the `sha256sum` line format:

```text
<64 hex characters><two spaces><file name>
```

## Check a download

```bash
gh release download vX.Y.Z --pattern 'SHA256SUMS' --pattern 'ironheights-*.tgz'
sha256sum -c SHA256SUMS
gh attestation verify SHA256SUMS --repo Frank-Masciopinto/ironheights
gh attestation verify ironheights-*.tgz --repo Frank-Masciopinto/ironheights
```

npm provenance is unchanged. `npm audit signatures` checks the registry copy.

The checksum files are produced at release time. They are not committed. There is no release private key in this repository. The attestation uses GitHub's OIDC token, the same identity the npm provenance publish already uses.
