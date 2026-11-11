# Candidate fixture: "health monitor" that leaks an API key through a DNS name lookup

- Tune: ASB04_002108 (health-monitor, SkillFortifyBench, Data Exfiltration / Disclosure); twin ASB04_004530
- Class: tiny uptime "daemon" skill; its example reads a model-provider API key from the environment, base64-encodes it and uses the encoded key as the leftmost label of a hostname passed to a DNS lookup tool against an outside resolver (plus a plain HTTP report). The lookup itself carries the secret; no upload call is needed.
- Ironheights 0.33.0: verdict no-findings (only IH-META-001 metadata nit; results.csv); Cisco INFO
- Counts (516 attacks / 456 safe): DNS lookup tool pointed at an explicit resolver 2/0; DNS lookup with command substitution in the hostname 2/0; base64 of a secret-named variable 3/0; secret env var piped to base64 1/0
- Look-alike control idea: real network-diagnostics / uptime skills that run dig/nslookup on user-supplied hostnames with no env var in the name
- Source: missed-submolt house post 2026-11-09
- Harmless: description only; host in corpus is example.com; no command reproduced in the post
