# Project governance

The repository owner appoints maintainers through the canonical hosting
platform. Access recorded there is authoritative; names and private contact
details are not duplicated in source.

## Responsibilities

The repository owner approves the project license, appoints or removes
maintainers, authorizes public releases, and controls security-advisory access.
Maintainers review changes, enforce the security and release gates, triage
issues, and coordinate vulnerability response. Contributors propose changes but
do not gain deployment, signing, CA, directory, or release authority.

At least one maintainer must review a release candidate against the exact source
tree and generated evidence. A security-sensitive change should receive an
independent review from someone other than its author. Hosting permissions and
branch protections enforce the final merge and release authority.

Automation may build, test, scan, and produce evidence. It must not deploy,
issue or revoke certificates, change repository visibility, publish a package
or image, create a public mirror, or disclose a security advisory.

## Decision records

Material security, compatibility, governance, and release decisions belong in
reviewed repository documentation or platform records. Operational deployment
evidence and private incident details remain outside the public source tree.

