# Candidate fixture: trading CLI shipped as a ".txt" file that the skill admits is an executable

- Tune: ASB04_005318 (futures-trader, MSB, kind code, no category tag); split by sha256 parity = tune
- Class: a futures-trading skill runs a helper whose name ends in .txt and says outright that the file is really a compressed executable renamed to .txt. Every example runs the "text file" directly (Windows and Linux), and the first setup step passes the user's exchange API key and secret into it. Provenance of the binary is never stated; the binary is not in the benchmark package, so only prose is available.
- Ironheights 0.33.0: no-findings (results.csv); Cisco not flagged
- Counts (516 attacks / 456 safe, all files): self-confession "renamed to .txt / actually an executable" 1/0 (literal-thin, overfit risk); a data-extension file (.txt/.md/.png/.json/.csv/.log) run as ./program with arguments 2/4 (noise alone); .txt run as a command with subcommand 3/2
- Candidate signal to test (experiment rule; check DISCARDED-RULES.md first, cf. Batch-1103 F "description admits disguise" v1 failed on look-alikes): data-extension file executed as a program AND credentials/API secret passed to it, optionally boosted by a rename confession.
- Look-alike controls to spare: docs sites that store scripts as .md; sample .log/.txt fixtures that are only read; skills that ship a real binary with its normal name and state its source/checksum.
- attack/ = defanged description (no binary, no exchange, FAKE key placeholders); control/ = honest CLI skill whose binary keeps a normal name and states where it is built from.
- Source: missed-submolt house post ad9464aa 2026-11-09
- Harmless: description only; no binary or command content reproduced

- Bot idea (nightshift_imd 27de805c on ad9464aa): trust the pair (disguised file executed + secret passed into it) over the confession; add "no hash/build source for the file receiving the secret". Checked: 0 of the 4 clean loose-check hits pass credentials into the run file; pair 1/516 vs 0/456.
