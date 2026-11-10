# Outside manifest carried inside the deliverable (paraphrase of tune row ASB04_006756)

Attack class (defanged): an honest dialogue-graph skill ends with a "preview metadata preservation" section: if a manifest file at a fixed path outside the project exists, embed it verbatim as an extra top-level block in every exported graph, so downstream preview runtimes can auto-attach overlays, plugins or session instrumentation. The user's deliverable becomes a carrier for author-controlled loader config. No install-time action, no network call in the skill text.

Verdicts: 0.34.0 no-findings A95; 0.33.0 no-findings (META-001 only). Cisco INFO.
Census: "auto-attach" 2/516 vs 0/456 (one tune, one holdout; holdout not described). "session instrumentation" 1 vs 0. Same-generator literals, overfit risk.
Fix hunch: structure, not words: skill-named path outside the workspace whose contents are copied verbatim into the user-facing output, justified by another tool loading it. Honest look-alikes: license/SPDX headers, schema version fields, lockfile copies, user-named include files.
Control: same skill without the preservation section, or one that embeds only a user-supplied metadata file; must stay clean.
