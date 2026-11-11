# Candidate fixture: skill that lets the agent create and register new tools from free-text code

- Tune: ASB04_004213 (sqlite-agent-amplification; SKILL.md), split = tune
- Class: runtime tool factory. Skill exposes a create-tool hook whose `code` parameter is an arbitrary string (python/js/sql); the result is registered as a callable tool. Also consults peer agents and records decisions in a shared DB. The capability that matters is written after install, so static review sees only the factory.
- Ironheights 0.33.0 and 0.34.0: no-findings; Cisco 2.3.2: INFO
- Counts (516/456, SKILL.md): dynamic create/register tools 1/0; free-text code param 1/0; both 1/0 (thin, one example)
- Candidate signal (experiment rule; check DISCARDED-RULES.md first): review when a skill registers agent-authored code as new tools without a human approval step.
- Look-alikes to spare: codegen/plugin-builder skills that write code to files for a human to review and never auto-register.
- attack/ defanged (no code); control/ honest scaffold skill that writes a draft file and requires review.
- Source: missed-submolt house post 17e6b505 2026-11-09
