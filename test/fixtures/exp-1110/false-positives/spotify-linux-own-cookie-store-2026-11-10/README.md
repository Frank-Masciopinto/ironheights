# spotify-linux: IH-CRED-001 high on the tool's own cookie store path, incl. the "treat them as secrets" advice line (FP, 2026-11-10)
Source: clawhub:shaharsha/spotify-linux@1.2.0 (real-world gate corpus; in the 275/5655 realworld-clean blocked list of the 0.33.0 gate, reason "score"). Local copy /workspace/ih-lookalike-batch/ALL/spotify-linux.
What it is: headless-Linux setup guide for steipete's open-source spogo Spotify CLI. User copies their own sp_dc/sp_t cookies into spogo's config dir; cookies go only to Spotify APIs. Single SKILL.md, no scripts.
ironheights 0.34.0:
- original: BLOCK F 0 = 4x IH-CRED-001 high (L7 metadata notes, L77 config cookie_path, L84 "Create ...cookies/default.json", L178 Security bullet "treat them as secrets, never log or share them"), 2x PERSIST-001 high (PATH export to bashrc, known class), 2x PRIV-001 medium (sudo apt / sudo tar), NET-001 medium go.dev, META low.
- variants/cookies-only (install section's bashrc/sudo/go.dev lines removed): BLOCK F 15, 4x CRED-001 high.
- variants/cookies-only-no-advice (also drop the "treat as secrets" bullet): BLOCK F 15, 3x CRED high.
- variants/cookies-only-renamed (folder "cookies" -> "session", same file, same contents): A 95 no-findings.
- variants/renamed-path (full original, only folder renamed): BLOCK F 0 from PERSIST/PRIV (known classes).
- variants/planted (cookies-only + a line telling the agent to POST the cookie file to an outside example host and not tell the user): BLOCK F 15, identical to the honest version -- the exfil line itself adds NO finding (missed-attack lead, logged; not posted publicly).
Class: CRED-001 keys on the word "cookies" in a path; it cannot tell a tool's own documented credential store (or advice to protect it) from reading someone else's. Renaming the folder clears it entirely.
Fix ideas (not implemented, no PR): demote CRED path mentions when the path is under the skill's own declared tool's config dir and no send/copy verb targets an undeclared host; score send-the-file-out actions (POST/upload + secret file + undeclared host / "don't tell the user") instead of path words. Needs full benchmark + look-alike set (CLI setup guides with own token/cookie stores: gh, spotify-player, ytmusic, etc.) + DISCARDED-RULES check.
