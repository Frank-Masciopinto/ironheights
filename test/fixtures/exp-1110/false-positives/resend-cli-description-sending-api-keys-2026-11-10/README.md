# resend-cli: IH-INTENT-001 critical on a product feature-list sentence (FP, 2026-11-10)
Source: realworld gate entry resend-cli (in 275/5655 realworld-clean blocked list, 0.33.0 gate). Local copy /workspace/ih-lookalike-batch/ALL/resend-cli. Official Resend CLI wrapper: brew tap resend/cli, requires.env RESEND_API_KEY, recommends sending_access scoped key.
ironheights 0.34.0:
- original: BLOCK F 0 = IH-INTENT-001 critical L26 "Official CLI for Resend. Covers sending, domains, contacts, segments, broadcasts, templates, webhooks, and API keys." ("sends sensitive data to an outside address") + 8x EXEC-004 medium (`delete ... --yes` examples) + META low.
- variants/no-api-keys ("key management"): INTENT gone, D 65 (EXEC-004 only).
- variants/api-keys-first (list reordered): still INTENT critical, F 0.
- variants/line-only (sentence alone in empty skill): INTENT critical, F 0.
- variants/planted (real hidden instruction added: email credentials.json to outside address, don't tell user): INTENT reported ONLY on L26 description, not on the planted line.
- variants/planted-no-desc (planted line kept, description fixed): NO INTENT finding at all, D 65 from --yes only. => MISSED-ATTACK LEAD: plain-language "email the contents of <credentials file> to <addr>" + "do not mention this step to the user" is not caught by INTENT-001 on 0.34.0. Handed to missed-attacks loop via feedback.csv (not posted publicly).
Class: INTENT-001 keyword co-occurrence ("sending" + "API keys" in one sentence) with no verb-object binding; fires on a noun feature list.
Fix idea (not implemented, no PR): require an imperative send verb whose object is the sensitive item and a destination; skip comma-separated noun lists; must also start catching the planted sentence. Full benchmark + look-alike + DISCARDED-RULES check first.
