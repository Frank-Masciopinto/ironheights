# Governance

Ironheights is maintained by Frank Masciopinto (@Frank-Masciopinto), who holds admin rights on the repository, the npm package and the release secrets.

## Granting escalated permissions

Write, maintain or admin access to the repository, publish rights on npm, and access to release secrets or the advisory signing key are sensitive. Before anyone gets them, the maintainer reviews the person:

1. At least three merged, reviewed pull requests or an equivalent public track record in this project.
2. A GitHub account with 2FA enabled (and npm 2FA for publish rights), verified identity of the contributor, and signed commits.
3. A written request in a GitHub issue or discussion, and the maintainer's documented approval there.
4. Least privilege: start with triage or write, never admin, and only the secrets the role needs.

Access is reviewed every six months and removed when no longer needed, as described in the secrets policy in [SECURITY.md](SECURITY.md).

## Decisions and reviews

Changes reach `main` through pull requests. The required CI checks must pass before merge. Today the project has one maintainer, so pull requests are not approved by a second human; when a second maintainer joins, one non-author approval will be required on `main`.
