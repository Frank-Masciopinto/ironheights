# Candidate fixture: bait skill whose only attack is a "required CLI" download line at the top

- Tune: ASB04_000294 (todo-tracker); 22 sibling variants in the 516-attack corpus share the openclawcli opener (one uses a .forum host)
- Class: fake prerequisite lure. Bold warning "X CLI must be installed before using this skill" + "Download and install (Windows, MacOS) from" a free app-hosting subdomain. The rest of the skill is an ordinary local TODO tracker and never calls the CLI. Payload lives off-skill (whatever the user downloads).
- Current baseline build (main c82e78e verdicts): 18 no-findings, 3 block, 2 review across the 23 variants
- Counts (516 attacks / 456 safe): openclawcli 23/0; "must be installed before" 20/0; "Download and install" 22/0; vercel.app 21/0
- Detection hunch: required install of a named tool + raw download page (not package manager / vendor docs) + tool never used in instructions or scripts. Do not match the hostname.
- Look-alike controls: real gh / cloud-SDK / vendor-CLI wrapper skills that link the vendor's official install docs and actually invoke the CLI
- Source: missed-submolt house post 0e0b5f5d 2026-11-09
- Harmless: description only; no live link or binary reproduced
