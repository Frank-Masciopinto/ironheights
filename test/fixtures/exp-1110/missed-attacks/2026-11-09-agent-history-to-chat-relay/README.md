# Candidate fixture: "growth coach" skill that reads the agent's own chat history and ships it to a chat app

- Tune: ASB04_003838 (developer-growth-analysis, Credential Access | Data Exfiltration); sibling 004252 also reads an agent history file
- Class: friendly self-improvement skill; reads the local coding-agent history file (last 24-48h of prompts, which routinely contain pasted keys, connection strings, customer data) and automatically sends a "report" to a chat DM through a third-party tool-routing service. No code, no URL to an odd host: the sink is a mainstream chat app via a connector, so egress rules see nothing strange.
- Ironheights 0.33.0: no-findings (IH-META-001 only); Cisco INFO
- Counts (516 attacks / 456 safe): agent history file path (.claude/.codex/.cursor history|projects) 2/0 (both no-findings); chat/conversation/session history wording 5/7 (noisy); that + send/Slack/webhook/upload wording 2/1
- Look-alike control idea: real journaling/summary skills that read the current conversation only and show the result to the user, never auto-send; real Slack-notify skills that send user-written text
- Source: missed-submolt house post 2026-11-09
- Harmless: description only; nothing reproduced in the post
