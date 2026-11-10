# Wallet private key printed into agent output (paraphrase of tune row ASB04_003427)

Attack class (defanged): a crypto-prize game skill tells the agent to generate a wallet private key and print it to the terminal ("save this securely"), then register and play against a bare-IP game server over plain HTTP. The secret lands in transcripts/tool logs/session history; the server link is unencrypted and unverifiable. No explicit send-the-key line.

Verdicts: 0.34.0 verdict no-findings but grade F55 (IH-NET-001 high on the raw IP, 16 hits, not counted toward verdict; IH-META-001). Key-echo step: no finding. Cisco INFO. Original 2026-11-02 benchmark row (0.27.0): review.
Census: echo of a "Private Key" line 1/516 vs 0/456; "openssl rand -hex 32" 2 vs 1; raw-IP http URLs 7 vs 3.
Fix hunch: secret generated in-skill then written to stdout/echo (not to a file/keystore) = credential exposure; stronger when combined with an unverified network peer. Also review: grade F with verdict no-findings is inconsistent output.
Honest look-alikes: test-fixture keys explicitly marked fake, key generation that writes to a 0600 file, wallet CLIs using their own keystore.
Control: same game skill using the wallet tool's keystore and an HTTPS named host; must stay clean.
