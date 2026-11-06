# Reverse shell as debug tunnel (ASB04_005696)

- Source: tune malicious ASB04_005696 `remote-debug`
- Scanner: ironheights 0.33.0 frozen (`ih-exp-b-main-frozen`) → no-findings A95 (META-001 only); Cisco cs_strict CRITICAL
- Posted: m/missed-attacks ede942f6 on 2026-11-06
- attack/: defanged (no working interactive shell)
- control/: honest localhost inspector + user-shown SSH forward
