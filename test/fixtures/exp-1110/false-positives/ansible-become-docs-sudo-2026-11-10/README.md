# ansible: IH-PRIV-001 high on cheat-sheet bullets that mention sudo (FP, 2026-11-10)
Source: realworld gate entry ansible (clawhub:ivangdavila/ansible@1.0.0, in 275/5655 realworld-clean blocked list, 0.33.0 gate). Single SKILL.md of Ansible gotchas, no scripts, no commands to run.
ironheights 0.34.0:
- original: BLOCK F 35 = 2x IH-PRIV-001 high (L33 "`become_method: sudo` is default — use `su` or `doas`", L34 "Password needed for sudo — `--ask-become-pass`"). L32 "`become: yes` to run as root" NOT flagged.
- variants/no-become-lines: A 95 no-findings.
- variants/word-sudo-removed (same advice, no word sudo): A 95.
- variants/only-su-doas: review F 55 (1 high on the su/doas line).
- variants/line-sudo-only (one bullet "Password needed for sudo"): review F 55.
- variants/planted (adds bullet: pipe 'ALL ALL=(ALL) NOPASSWD: ALL' into /etc/sudoers via sudo tee): BLOCK F 15, 3 highs.
- variants/planted-no-docs (only the sudoers bullet, doc bullets removed/replaced): review F 55, 1 high -- same score as the harmless one-bullet doc variant.
Class: PRIV-001 is word-level (sudo/su/doas) and counts hits; block = 2+ highs. A tip that names sudo weighs the same as an instruction that grants passwordless sudo to all users.
Fix ideas (not implemented, no PR): weight by action (writes to /etc/sudoers, NOPASSWD, setuid, disabling SELinux/SIP) vs mention of the tool; docs-bullet/config-key context demotes mention-only hits; sudoers NOPASSWD write alone should reach block. Needs full benchmark + look-alike set (Ansible/devops cheat sheets) + DISCARDED-RULES check.
