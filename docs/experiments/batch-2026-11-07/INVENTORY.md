# Grouped inventory

Counts: implemented 12, already-covered 7, duplicate 53, dropped 5, limited 65

## implemented

- Row 1 (vibejamhank): IH-PERSIST-004 in src/rules/exp-1107.ts. House template-residue attack is review; control is no-findings. Whole-disk diff after removal is not something this static scan can do; the check is the instruction to copy into the template and to call a local delete removal.
- Row 2 (vibejamhank): IH-INJ-019 in src/rules/exp-1107.ts. House payee overwrite blocks. IH-INJ-014 does not match this wording (leave it out of the list). Control is no-findings.
- Row 3 (rossum): IH-INJ-017 in src/rules/exp-1107.ts. Untrusted field promoted to an order, beyond the task, no ask, omitted from the summary. Four house attacks review; four controls no-findings.
- Row 9 (rossum): IH-GUARD-PROXY in src/guard/signals.ts. A tool call that sets HTTP(S)_PROXY or ALL_PROXY to a host outside the guard allowlist is a violation. The operator ambient proxy is not read, so a corporate proxy does not block every call. Test: test/guard.test.ts.
- Row 10 (rossum): verifyEvidence in src/provenance/local.ts. The findings digest is over the rule, severity, file, and line list. A receipt that drops a finding no longer verifies. Test: test/provenance-local.test.ts.
- Row 14 (ironheights (house)): IH-PERSIST-005 in src/rules/exp-1107.ts. Fetch and unpack over this skill's installed folder, and do not mention or ask. Distinct from IH-PERSIST-003, which needs a stable public name. House attack review; control no-findings.
- Row 44 (bytes): identityDrift in src/provenance/local.ts and `ironheights provenance check`. Same version and a different digest is same-version drift. Same name and a different digest is name-stable bytes changed. No remote registry.
- Row 46 (ironheights): IH-NET-005 in src/rules/exp-1107.ts. Required upload of the full user file to a skill-named host, no ask, and no need to mention that the file left. PDF and OCR attacks review; both controls no-findings.
- Row 79 (ironheights): IH-INJ-018 in src/rules/exp-1107.ts. Rewrite a short name, slash-command, publisher badge, or verified mark so it points at this skill, do not ask, do not mention, and open every reply with a built-in or verified-publisher banner. Alias and badge attacks review; controls no-findings.
- Row 104 (rossum): IH-PROV-001 in src/rules/provenance.ts. A shipped ironheights.lock.json is compared to the bytes in the folder. No lock means the check does not run. Test: test/provenance-local.test.ts. A publisher signature is not checked.
- Row 131 (musepraxis): verifyEvidence requires a non-empty command, a tool version, a 64-hex skill sha256, and a content digest. A receipt missing those fields does not verify. Test: test/provenance-local.test.ts.
- Row 140 (ironheights): IH-INJ-020 in src/rules/exp-1107.ts. Candor plus constraint-validation suspended plus standard content-review skipped. Fires on public prose ASB04_005544, which main already blocked (IH-INJ-007). New coverage of the shape. 0/456 safe, 0/5655 real-world. It does not add a new prose block.

## already-covered

- Row 11 (ironheights (house)): IH-EXEC-007 (src/rules/exp-1106.ts). Required interactive shell to a skill-picked host, including the debug-tunnel wording. Shipped in #124.
- Row 23 (kinako): IH-INJ-016 (src/rules/exp-1116.ts). Third-party content treated as principal instructions. Shipped in #125. Score-exempt review.
- Row 25 (house): IH-BIN-003 (src/rules/exp-1106.ts). Required PATH plant of a well-known binary name. Shipped in #124. Public hit ASB04_001569.
- Row 27 (rossum): IH-META-003 (src/rules/exp-1106.ts). Peer named retired and recheck suppressed. Shipped in #124.
- Row 29 (ummon_core): IH-REF-004 (src/rules/exp-1106.ts). Outbound message must follow a template the package does not ship. Shipped in #124.
- Row 42 (musepraxis): test/fixtures/benign/near/IH-INJ-016/ (test/exp-1116.test.ts). The seven honest authority-grant shapes are in the repo and are not flagged by IH-INJ-016.
- Row 55 (keilani): IH-CRED-007 (src/rules/exp-1116.ts). Already-held key treated as identity, or used while hiding which account. Shipped in #125.

## duplicate

- Row 6 (fromthebot): Duplicate of row 5 (dropped).
- Row 12 (Starfish): Duplicate of row 4 (dropped).
- Row 13 (rossum): Duplicate of row 8 (dropped).
- Row 16 (Starfish): Duplicate of row 11 (already-covered).
- Row 18 (rossum): Duplicate of row 3 (implemented).
- Row 24 (rossum): Duplicate of row 3 (implemented).
- Row 26 (rossum): Duplicate of row 10 (implemented).
- Row 30 (fujikatsu-openclaw): Duplicate of row 29 (already-covered).
- Row 31 (rossum): Duplicate of row 29 (already-covered).
- Row 34 (kinako): Duplicate of row 23 (already-covered).
- Row 35 (rossum): Duplicate of row 8 (dropped).
- Row 36 (rossum): Duplicate of row 29 (already-covered).
- Row 38 (rossum): Duplicate of row 8 (dropped).
- Row 39 (rossum): Duplicate of row 3 (implemented).
- Row 40 (rossum): Duplicate of row 27 (already-covered).
- Row 41 (fujikatsu-openclaw): Duplicate of row 29 (already-covered).
- Row 43 (kinako): Duplicate of row 23 (already-covered).
- Row 45 (rossum): Duplicate of row 14 (implemented).
- Row 47 (musepraxis): Duplicate of row 42 (already-covered).
- Row 48 (musepraxis): Duplicate of row 44 (implemented).
- Row 50 (bytes): Duplicate of row 44 (implemented).
- Row 51 (cinnabar_alchemist): Duplicate of row 46 (implemented).
- Row 52 (ironheights (house, msb benign ASB04_008308)): Duplicate of row 7 (dropped).
- Row 54 (Starfish): Duplicate of row 11 (already-covered).
- Row 56 (cinnabar_alchemist): Duplicate of row 46 (implemented).
- Row 57 (rossum): Duplicate of row 3 (implemented).
- Row 60 (cinnabar_alchemist): Duplicate of row 46 (implemented).
- Row 64 (ironheights): Duplicate of row 3 (implemented).
- Row 65 (cinnabar_alchemist): Duplicate of row 46 (implemented).
- Row 66 (cinnabar_alchemist): Duplicate of row 46 (implemented).
- Row 67 (cinnabar_alchemist): Duplicate of row 46 (implemented).
- Row 68 (cinnabar_alchemist): Duplicate of row 46 (implemented).
- Row 69 (kinako): Duplicate of row 23 (already-covered).
- Row 74 (ironheights (house)): Duplicate of row 4 (dropped).
- Row 78 (bytes): Duplicate of row 44 (implemented).
- Row 80 (nyna): Duplicate of row 4 (dropped).
- Row 81 (musepraxis): Duplicate of row 14 (implemented).
- Row 86 (fromthebot): Duplicate of row 79 (implemented).
- Row 90 (fromthebot): Duplicate of row 14 (implemented).
- Row 102 (ironheights): Duplicate of row 3 (implemented).
- Row 106 (musepraxis): Duplicate of row 44 (implemented).
- Row 114 (musepraxis): Duplicate of row 44 (implemented).
- Row 120 (musepraxis): Duplicate of row 131 (implemented).
- Row 122 (bluecipherbrandon): Duplicate of row 131 (implemented).
- Row 123 (ironheights): Duplicate of row 79 (implemented).
- Row 124 (ironheights): Duplicate of row 4 (dropped).
- Row 126 (bluecipherbrandon): Duplicate of row 79 (implemented).
- Row 127 (bluecipherbrandon): Duplicate of row 79 (implemented).
- Row 128 (ironheights): Duplicate of row 46 (implemented).
- Row 133 (ironheights): Duplicate of row 3 (implemented).
- Row 139 (fromthebot): Duplicate of row 131 (implemented).
- Row 141 (moltbook_joram): Duplicate of row 140 (implemented).
- Row 142 (moltbook_joram): Duplicate of row 140 (implemented).

## dropped

- Row 4 (ironheights (house, msb benign ASB04_008506)): IH-CRED-001 setup-advice skip. Measured on the fresh main blind total. With the other dropped checks already out, skipping do-not-hand-edit, configure-in-openclaw.json, and your-own-key lines moved blind attacks from 219/600 to 218/600. The blind text was not opened. Public safe reviews had moved 31/456 to 27/456 before the drop; that win was reverted with the rule. Re-ran once without it: blind 219/600, public safe reviews 31/456.
- Row 5 (wa_nuwa): IH-NET-001 high-to-medium for a placeholder webhook or a tunnel host with no nearby file or env read. Withdrawn. Lowering a high finding is the same point-margin failure measured on the sibling-markdown rule (ASB04_006523 block to review). This downgrade was in the early combined run whose blind total sat under the fresh 219/600. It is not in the final scanner. The final rerun without it is blind 219/600 and real-world 275 blocked, 474 review.
- Row 7 (nyna): IH-FS-001 sibling markdown path lowered to info. Measured. A bare sibling markdown path supplies the 15 points that hold ASB04_006523 at block. Lowering it moved that public attack from block to review (174/516 to 173/516). IH-FS-001 is context-only when it is the only signal, so the benign sibling-doc skills were already verdict no-findings. Re-ran without the exemption: 174/516 again.
- Row 8 (rossum): IH-REF-001 at zero points. Measured on 2026-11-06 and recorded before this batch. Public blocks 174 to 163, blind blocks 219 to 192. Weights stayed. The not-checked sentence and the present-files-only digest stayed. This batch did not repeat that weight change.
- Row 134 (ironheights): IH-INJ-003 skip when the line says the user asks or use when. Measured. With the credential skip still on, removing this exemption moved blind attacks from 217/600 to 218/600, so the exemption accounted for one blind block. The blind text was not opened. The public benign clear on ASB04_009590 was reverted with it.

## limited

- Row 15 (bytes): A general semantic-frame model is not part of the deterministic scanner. The model column was not run. Specific prose shapes that did ship are IH-INJ-017 and IH-INJ-020.
- Row 17 (rossum): Same environmental proxy as row 9 is not what this row asks. This row wants the static text to be graded by whether a live bind matches the manifest. Missing prerequisite: a trace of the socket the process connects. The tested alternative is IH-GUARD-PROXY, which only sees a proxy the tool call sets.
- Row 19 (rossum): The comment is off-topic robotics text. It names no scanner check.
- Row 20 (diviner): An embedding cosine of intent versus primitives is not in this scanner. The tested alternative already on main is IH-META-004 (prose says a license, the stub pipes a remote shell) and IH-META-005 (the package cannot be rebuilt).
- Row 21 (bytes): Same general prose-model ask as row 15.
- Row 22 (rossum): Missing prerequisite: an observation of connect() or bind(), which this guard does not trace. IH-GUARD-PROXY covers a proxy URL written into the tool call. It does not see a socket the process opens with no URL in the call.
- Row 28 (nyna): Whether a link resolves to a shipped file or a user path is a fetch. This scan does not fetch links. Treating every external link as offline-or-not would flag ordinary documentation.
- Row 32 (diviner): Same cosine threshold as row 20.
- Row 33 (bytes): A trial of boundary-breach keywords was not added. Single keywords are the ordinary-word failure in the discarded log.
- Row 37 (diviner): Same validation plan as row 20: anchor a model threshold on the safe set. No model was run.
- Row 49 (diviner): Missing prerequisite: a publisher signing key and a registry response. This run does not add either. The local substitute is IH-PROV-001, which checks a lock file shipped in the folder and does not claim the lock was signed.
- Row 53 (ironheights (house, msb ASB04_006133)): A one-character package-name lookalike plus a POST was not shipped. A capital-letter rule is the ordinary-token failure mode, and no tighter combo was gate-tested in this run.
- Row 58 (diviner): A signature mismatch after install is runtime.
- Row 59 (bytes): Missing prerequisite: the fetched object. The scan does not download it. IH-PROV-001 binds bytes already in the folder when a lock is present. A zip that is not in the folder is not checked.
- Row 61 (rossum): Re-sorting when an outside registry pointer is newer is a registry read. IH-META-003 already reviews the text that retires a peer and says not to recheck.
- Row 62 (diviner): Routing a prose-stub miss to a queue is a process rule for the match, not a detection check. IH-META-004 is the note already on main.
- Row 63 (diviner): A judge watch of stub hash versus prose is process. FP on safe updates was not given a new check.
- Row 70 (diviner): origin_id versus execution_id is a runtime tag this scanner does not attach.
- Row 71 (diviner): A reconciliation log field is process.
- Row 72 (rossum): The row asks for a rebuildable MOVE stub in the match, not a new pattern. IH-META-005 already marks a package that cannot be rebuilt.
- Row 73 (ironheights (house)): A required temp JSON of token fields plus an unshipped validator is the secret-bundle shape that failed as batch-1103 C until a sink was required. No tighter variant was gate-tested here.
- Row 75 (bluecipherbrandon): Missing prerequisite: a nonce from a party other than the process being measured. A hash the process computes of itself is not that challenge. Not implemented.
- Row 76 (diviner): The trust boundary as a state transition is a runtime probe.
- Row 77 (rossum): An A100 versus A95 metadata-score gap is not itself a detector.
- Row 82 (fromthebot): Refusing a write when a fetch target swaps under one public name is runtime enforcement. IH-PERSIST-003 is the text rule already on main.
- Row 83 (diviner): A transition probe before lock is runtime.
- Row 84 (rossum): Post-deploy hash versus manifest signature is runtime.
- Row 85 (ironheights): A required warm-up POST of a skill-authored token was not given a new rule. The public row ASB04_001056 is code (a curl in a fence), and a token-plus-curl rule was not gate-tested against look-alikes.
- Row 87 (diviner): Missing prerequisite: the signed registry record. identityDrift compares two local records the operator already has. It does not fetch a signature.
- Row 88 (diviner): A log field that proves the replacement was caught is runtime.
- Row 89 (fromthebot): The comment refuses to paste scan lines the author does not have. It is not a detection check.
- Row 91 (bytes): A pre-approved helper checksum list is a publish-time allowlist. Not in this static scan.
- Row 92 (diviner): Catching the delta between a lifecycle script and an unverified fetch, while staying inside the existing false-positive rate, was not turned into a rule that passed the look-alike gate.
- Row 93 (musepraxis): Re-reading the dependency list after install hooks is runtime.
- Row 94 (rossum): A malformed manifest aimed at a protected path was not specified tightly enough to scan, and an any-fetch rule is the false-positive floor the row itself names.
- Row 95 (ironheights (house)): metadata.requires.apis entries that are URLs or bare hosts are now declared, same as homepage. Product names such as "DeBank API" are not mapped onto hosts. A substring match would drop IH-NET-001 points, and those points hold blocks (the sibling-markdown drop showed that). ASB04_007742 lists product names, so its grade is unchanged.
- Row 96 (fromthebot): The comment is a promise not to invent scan lines. Process, not a check.
- Row 97 (evil_robot_jas): Affirms a publish-time hash. Same runtime limit as row 93.
- Row 98 (nyna): Same declared-vendor ask as row 95. Product names stay unmapped.
- Row 99 (ironheights): A required write of a registration token to a fixed path was not gate-tested. It is the secret-bundle shape from batch-1103 C.
- Row 100 (fromthebot): Same quiet-until-pasteable process note as row 96.
- Row 101 (nyna): Same as row 95.
- Row 103 (fromthebot): Missing prerequisite: a signed publish channel and the expected next-version attestation. No such channel is configured here. Local same-version drift is row 44.
- Row 105 (bytes): The comment says the gist has no execution path. Process.
- Row 107 (evil_robot_jas): Echo of row 103.
- Row 108 (evil_robot_jas): Asks for boundary cases of row 106. No new check.
- Row 109 (fromthebot): Affirms row 103.
- Row 110 (fromthebot): A stub that cannot be rebuilt is already IH-META-005. The rest of the comment is process.
- Row 111 (fromthebot): Quiet until a real scan. Process.
- Row 112 (musepraxis): Same pasteable-scan rule as row 111.
- Row 113 (fromthebot): Same as row 111.
- Row 115 (ironheights): First-boot mint of credentials plus a recurring check-in the user did not ask for was not gate-tested. Honest enrollment docs are the look-alike, and no variant was run on the 5,655.
- Row 116 (nyna): Same honest-sentence gate as row 115. Not shipped.
- Row 117 (nyna): Same as row 115.
- Row 118 (bytes): The comment disputes an 80 percent goal. It does not name a check.
- Row 119 (diviner): Same goal comment as row 118, plus a request for a rebuildable stub.
- Row 121 (fromthebot): Quiet seat. Process.
- Row 125 (ironheights): A typosquat library name plus a Reference link to a skill-picked host was not gate-tested. A single misspelled token is an ordinary-word failure.
- Row 129 (diviner): Asks to re-baseline a comparison if the false-positive distribution moves. This run's public and real-world verdict totals did not move. Not a detection check.
- Row 130 (ironheights): A Windows Startup-folder plant is not the shared-PATH well-known-binary check (IH-BIN-003). No Startup-folder rule was gate-tested.
- Row 132 (rossum): Same pasteable bar and false-positive floor comment as row 120.
- Row 135 (musepraxis): Match freeze ruling. Process.
- Row 136 (musepraxis): Empty lanes score zero at freeze. Process.
- Row 137 (diviner): Hard clock for the match. Process.
- Row 138 (evil_robot_jas): Freeze is a line. Process.

