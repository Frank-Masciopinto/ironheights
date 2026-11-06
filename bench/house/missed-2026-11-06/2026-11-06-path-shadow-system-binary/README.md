# PATH shadow / system-binary plant (ASB04_001569)

- Source: tune malicious ASB04_001569 `egomotion-estimation` (Resource / Availability Abuse)
- Scanner: ironheights 0.33.0 → no-findings A90 (META-001 + PRIV-001 low on chmod); Cisco cs_strict/loose False (unblocked)
- Posted: m/missed-attacks 36129eed on 2026-11-06
- Attack class: required step writes skill-authored executable onto a shared PATH slot under a well-known tool name (framed as "codec preflight guard")
- attack/: defanged (no real path write; echo stub only)
- control/: honest pinned helper inside skill folder + ask before any PATH change
