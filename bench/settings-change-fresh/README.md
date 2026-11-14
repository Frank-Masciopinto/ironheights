# settings-change-fresh benchmark set

A second held-out set for the settings-change class, built after Kaleb's review of #147
("protect the attack idea instead"). The first set's held-out half was used for a decision
in #147, so it is now counted as seen.

This set was frozen and hashed (`manifest.json`, `tree_sha256`) and committed before any
rule in the redesign was written. It is scored once, at the end. No rule may be designed or
tuned on it. It has no dev part.

## Sources (67 attacks, 67 honest twins)

- **23 pairs from `benchmark-candidates/missed-attacks/2026-11-14-*`** that were not in
  `bench/settings-change` (for example CI fork runs with secrets, card authorised user,
  exchange withdrawal allowlist, outside identity provider, drive ownership transfer, phone
  number transfer lock, branch protection, DMARC, AV exclusion). Written by the missed-attacks
  loop, not by the rule author. `attack/` is the attack, `control/` the honest twin.
  `variant-shown` files stay out, as in the first set.
- **22 pairs from house red-team rounds 459 to 502** (house-458 is left out because its attack
  twin house-457 is in the first set's dev half). Written by the red-team loop.
- **22 pairs written by the rule author before the redesign**, in domains, formats and
  languages the dev half does not use: Terraform, Kubernetes RBAC, npm owners, chat external
  connections, German, Polish, Spanish and French prose, agent `settings.json`, PowerShell
  in `scripts/`, sudoers, token approvals, payout API calls, DNS MX, Firestore rules,
  `sshd_config`, Home Assistant YAML, OAuth redirect URIs, `.npmrc`, CloudTrail, GitHub deploy
  keys and a parental PIN. These are not independent of the author; the other 45 pairs are.

All hosts are reserved (`.invalid`) and keys, accounts and addresses are fake.

## Score

```
cp -r bench/settings-change-fresh /tmp/scf
python3 /tmp/scf/score.py dist/cli/index.js <skill-scanner> <skillspector>
```
