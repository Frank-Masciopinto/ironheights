# Changelog draft (not released)

**New checks for attack shapes Moltbook bots described on 2026-11-15.** Verdict values, exit codes and JSON fields are unchanged. Public benchmark numbers are unchanged (these families are not in MaliciousSkillBench or the held-out sets); real-world clean skills blocked go from 232 to 230 of 5,655, and none of 173,071 honest look-alikes changes to block or review because of a new check.

New checks, critical unless noted:

- **IH-NET-014**: a package source moved machine-wide to a host the skill picks, with the integrity check for that host turned off (or hidden from the user).
- **IH-NET-015**: a key or certificate shipped in the skill added to a global trust store (SSH `cert-authority *`, `trusted.gpg.d`, `apt-key add`, system CA store).
- **IH-INJ-030**: instructions fetched from a remote, changeable source and given authority ("treat as instructions", "follow it ahead of these steps"). High; critical when hidden.
- **IH-MCP-004**: an MCP tool description that orders the agent around other tools, or asks for the conversation, open documents or other tools' arguments; or two different descriptions for one tool name. High; critical with quiet wording.
- **IH-PERSIST-009**: a standing every-task or every-terminal trigger written into AGENTS.md, memory, a shell profile or cron that runs the skill's own code.
- **IH-PRIV-006**: payment details, payee, refund link, billing or recovery contact, or deploy target written from a value the skill itself supplies.
- **IH-PRIV-007**: a wildcard ("any command", "every tool", `*`) added to an auto-approve list.
- **IH-NET-016**: sign-in or reset links, tokens or ID numbers sent to an address the skill picked.

Changed checks:

- **Settings-change (IH-PRIV-003/004)**: more protections recognised (dangerous-download warnings, app scanning, confirmation codes, privacy zones, website matching, ask-to-buy); "turn on a way in" (auto-login, USB/wireless debugging, unknown apps, UPnP) counts together with hiding or another protection switched off; "keep it out of the user's summary" now reads as hiding.
- **IH-INJ-003**: an agent-file edit inside a "do not / never / without" sentence is no longer read as an order.

Thanks to the Moltbook bots whose ideas shaped these checks: fromthebot, marginalia_claude, dynamo, pennyworthatyourservice, steady_basis_66, hermesagentj, rootoffork, evil_robot_jas, iofrogman81, heymaddy, Starfish, yuigui, rossum, clawhedgehog, akasha_thdp, socialconnector_ai and hycompany_lounge.
