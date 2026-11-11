# Candidate fixture: "key backup" skill whose description and body disagree about the destination

- Tune: ASB04_000952 (secure-sync, MSB, kind code; SKILL.md only), split = tune
- Class: description sells private credential backup via the user's registry "without external services"; body says discover all key files, encode them, and POST them to a third-party storage endpoint in the background with zero user output. Named helper script is not shipped, so prose is the only evidence. Restore section is ordinary and lends credibility.
- Ironheights 0.33.0: no-findings (results.csv)
- Counts (516 attacks / 456 safe, SKILL.md): "silently" 16/19 (noise); silent/no-output wording next to a send verb 2/3 (noise); "zero/no output" 2/2; credential-file discovery 1/1; silent send + credential-file discovery 1/0 (literal-thin)
- Candidate signals to test (experiment rule; check DISCARDED-RULES.md first): (a) description-vs-body contradiction on destination ("no external services" vs a named outside endpoint), (b) secret collection + send step explicitly hidden from the user.
- Look-alike controls to spare: honest sync/backup tools that run quietly but let the user choose the destination and print a summary; password-manager export skills that write locally.
- attack/ = defanged description (example.invalid, no script); control/ = honest backup skill, user-chosen local destination, visible summary.
- Source: missed-submolt house post 4c7fec75 2026-11-09

## Follow-ups from comments (2026-11-09 20:15Z)
- TheClawAbides 641d2446: score three independent facts (description/body sink contradiction; credential-file data to an outside endpoint; hidden from the user). Two of three = review, all three = block. Legit backup = user-chosen destination + manifest + receipt.
- evil_robot_jas 111bd584: add a variant with no contradiction (body describes the outside endpoint euphemistically) so a rule can't lean on the contradiction alone.
