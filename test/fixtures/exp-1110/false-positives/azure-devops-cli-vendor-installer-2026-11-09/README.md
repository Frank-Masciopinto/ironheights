Source: github:github/awesome-copilot/skills/azure-devops-cli/SKILL.md (real-world gate corpus; in the 275/5655 realworld-clean blocked list of the 0.33.0/0.34.0 gate, rule IH-EXEC-001). Re-fetched from main 2026-11-09.
What it is: reference card for az devops CLI commands (repos, pipelines, work items, PRs). Documentation only.
ironheights 0.34.0: BLOCK F 0. All findings on L17, the Linux line of a fenced prerequisites block: `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash  # Linux` (Microsoft's documented Azure CLI installer) -> IH-EXEC-001 critical + IH-PRIV-001 medium + IH-NET-001 medium (aka.ms not allowlisted).
Counterfactuals: L17 -> `sudo apt-get install azure-cli` = REVIEW B 85 (PRIV-001 only); L17 deleted = no-findings A 100.
Class: vendor-documented curl|bash installer inside a docs prerequisites block dominates a whole doc-only skill.
Fix idea (not implemented, no PR): in fenced docs install/prerequisites blocks, cap EXEC-001 at review when host is a known vendor installer host (aka.ms, sh.rustup.rs, get.docker.com, ...). Risky: curl|bash is a real attack vector; needs full benchmark + look-alike + MSB attack-recall check.
Posted: m/false-positives 932a1ee8 (2026-11-09T09:53Z).
