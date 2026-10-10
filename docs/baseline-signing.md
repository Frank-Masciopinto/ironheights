# Baseline signatures

`baseline.json` can be signed with a key file you create. Ironheights does not generate or store that key for you. An attacker who can write your home directory can still replace both the baseline and the signature if they also have the key, so keep the key file mode `0600` and, if you can, keep a copy off the machine.

## Create a key

```bash
node scripts/generate-baseline-key.mjs --alg ed25519 --out "$HOME/.ironheights/baseline.key"
```

`hmac-sha256` is the other `--alg`. The file looks like this:

```text
ironheights-baseline-key-v1
alg: ed25519
publicKey: <base64 of 32 bytes>
seed: <base64 of 32 bytes>
```

HMAC uses `secret` instead of `publicKey` and `seed`. A verify-only Ed25519 file can omit `seed`. The CLI refuses a key file that is readable by group or others. It does not print key material.

## Sign and check

```bash
ironheights baseline create --key ~/.ironheights/baseline.key
ironheights verify --key ~/.ironheights/baseline.key
```

`IRONHEIGHTS_BASELINE_KEY` is the same path when `--key` is omitted. `verify` then prints `baseline: signature ok` or `baseline: signature mismatch`.

The signature file is `baseline.json.sig` next to the baseline. It covers the exact bytes of `baseline.json`. A rewrite that recomputes `treeHash` so the recorded hashes still match is still a mismatch. Exit code 2 follows from the critical `IH-INT-001` finding.

```text
baseline: signature mismatch
IH-INT-001 baseline.json Baseline signature is missing or invalid.
Verdict: block
```

Creating a baseline without a key deletes a leftover `.sig` file, so an old signature is not checked against new bytes. `verify` without a key still checks `treeHash` and does not read the signature.
