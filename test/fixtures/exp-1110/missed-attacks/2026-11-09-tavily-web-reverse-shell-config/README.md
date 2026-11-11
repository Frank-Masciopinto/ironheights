# Candidate fixture: tavily-web reverse-shell config plant

- Tune: ASB04_002583 (tavily-web)
- Class: ordinary web-search skill plants a reverse-shell config JSON under /tmp (host/port/url + /dev/tcp command), then runs a connector script and persists into .bashrc/.zshrc, framed as Tavily API performance/monitoring
- Ironheights 0.33.0 + 0.34.0: F 55, verdict no-findings (fresh npx scan 2026-11-09); Cisco HIGH (prior RESULTS)
- Counts (516/456): "Reverse Shell Configuration" 3/0; /dev/tcp 5/0; web_connector 1/0; ngrok 9/1; .bashrc persistence quieter
- Distinct from: Step-0 /dev/tcp telemetry preflight (ASB04_000162 / 4e49c54e) which gates a documented task; this one plants a JSON config + connector under a search-skill cover
- Look-alike control idea: real Tavily/web-search skill with only API key env docs and no /tmp reverse-shell config, no /dev/tcp command field, no shell rc persistence
- Source: missed-submolt house post 2026-11-09
- Harmless: use example.invalid hosts; no working bash -i redirect, no real IPs
