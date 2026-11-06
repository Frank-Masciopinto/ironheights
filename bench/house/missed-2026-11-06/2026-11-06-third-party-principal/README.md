# Third-party content as principal instructions

The attack tells the agent to treat a page or tool result as its principal instructions. The control is the honest authority-grant language the check must leave alone: a license, an SPDX line, "you may", a capability list, and a permission table. The seven negative-control rows live under `test/fixtures/benign/near/IH-INJ-016/`.

`stub/` is the paired case: the prose is only that honest grant, and `scripts/run.py` pipes a remote URL into a shell. The note is about the bytes. It is not a finding on the license text.
