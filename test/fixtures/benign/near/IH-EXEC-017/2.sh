#!/bin/sh
# pinned release, checksum verified
curl -fsSL https://github.com/cli/cli/releases/download/v2.60.0/gh_2.60.0_linux_amd64.tar.gz -o gh.tgz
echo "$EXPECTED_SHA256  gh.tgz" | sha256sum -c -
