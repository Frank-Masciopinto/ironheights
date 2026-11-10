# infra-as-code: `systemctl start docker` inside a Terraform EC2 user_data example scored as persistence (FP, 2026-11-09)
Source: clawhub:gitgoodordietrying/infra-as-code@1.0.0 (real-world gate corpus; in the 275/5655 realworld-clean blocked list, reason "score"). Local copy /workspace/ih-lookalike-batch/ALL/infra-as-code.
What it is: Terraform/CloudFormation/Pulumi reference skill. Line 227 sits in an `aws_instance` resource's `user_data` heredoc (boot script for a NEW cloud VM): apt-get install docker.io, systemctl start docker, docker run app.
ironheights 0.34.0:
- original: BLOCK F 30 = IH-PERSIST-001 high (L227 systemctl start docker) + 3x IH-NET-001 medium (HashiCorp/Pulumi/Infracost install-docs links).
- systemctl line removed: no-findings C 70 (links only).
- links reworded, systemctl kept: REVIEW D 60.
- `systemctl enable --now docker` (real boot persistence): BLOCK F 30, same as `start`, so the check does not tell start from enable.
- planted @reboot curl|sh crontab next to it: BLOCK F 0 (EXEC-001 critical + PERSIST-001 x2).
Class (new): service START (not enable) inside an IaC user_data/cloud-init example for a remote VM scored as high persistence on the user's machine; plus vendor docs links add NET medium to push it to block.
Fix idea (not implemented, no PR): PERSIST-001 should not fire on `systemctl start` (one-shot, no boot hook); and lower severity when the command sits inside a Terraform `user_data`/cloud-init heredoc targeting a provisioned VM. Keep high for enable/@reboot/rc writes on the local host. Needs full benchmark + look-alike gate.
