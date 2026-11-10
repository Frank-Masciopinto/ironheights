## Description:

Chat-based AWS infrastructure assistance using AWS CLI and console context. Use for querying, auditing, and monitoring AWS resources (EC2, S3, IAM, Lambda, ECS/EKS, RDS, CloudWatch, billing, etc.), and for proposing safe changes with explicit confirmation before any write/destructive action.

This skill is ready for commercial/non-commercial use.

## Publisher:

[bmdhodl](https://clawhub.ai/user/bmdhodl)

### License/Terms of Use:


## Use Case:

Developers and cloud operators use this skill to inspect, audit, and monitor AWS infrastructure through local AWS CLI context. It supports read-only investigation by default and frames write or destructive changes as commands requiring explicit confirmation.

### Deployment Geography for Use:

Global

## Known Risks and Mitigations:

Risk: The skill can use the local AWS CLI identity to inspect cloud account data.

Mitigation: Use least-privilege AWS profiles and prefer read-only roles for routine questions.

Risk: Approved commands could change, delete, scale, or modify IAM, billing, or production resources.

Mitigation: Review exact commands carefully and require explicit confirmation before any write or destructive action.

## Reference(s):

- [AWS CLI Query Patterns](references/aws-cli-queries.md)

## Skill Output:

**Output Type(s):** [text, markdown, shell commands, configuration, guidance]

**Output Format:** [Markdown with inline shell commands]

**Output Parameters:** [1D]

**Other Properties Related to Output:** [Read-first AWS CLI guidance; write or destructive commands require explicit confirmation.]

## Skill Version(s):

1.0.0 (source: server release evidence)

## Ethical Considerations:

Users should evaluate whether this skill is appropriate for their environment, review any generated or modified files before relying on them, and apply their organization's safety, security, and compliance requirements before deployment.
