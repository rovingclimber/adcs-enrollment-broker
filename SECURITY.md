# Security policy

AD CS Enrollment Broker handles certificate-enrollment authority and should be treated as a
security-sensitive component. Please report suspected vulnerabilities
privately.

## Supported versions

Security fixes are made for the latest published release. The default branch is
development material and is not a supported deployment. Older releases receive
fixes only when a security advisory explicitly says so.

Until the first published release, there is no supported public version.

## Reporting a vulnerability

Use the canonical public repository's private vulnerability-reporting feature:
open **Security**, choose **Advisories**, and select **Report a vulnerability**.
If that feature is unavailable, do not open a public issue. Use the private
security contact named in the repository profile and disclose only enough
information to establish a confidential channel.

Include the affected version or commit, prerequisites, impact, a minimal
reproduction using synthetic data, and any suggested mitigation. Do not send
private keys, credentials, authentication tokens, production certificate
requests, directory exports, or unrelated personal data.

The maintainers aim to acknowledge a report within three business days and
provide an initial triage decision within ten business days. Remediation and
disclosure timing depend on severity, exploitability, affected users, and the
availability of a tested fix. The reporter and maintainers should agree on a
coordinated disclosure date before publishing details.

## Research boundary

Test only systems and data you own or are explicitly authorized to assess. Use
an isolated environment with synthetic identities. Avoid denial of service,
persistence, social engineering, destructive actions, and access to other
people's data. Stop and report privately if a test crosses an authorization or
privacy boundary.

The maintainers will track accepted reports privately, arrange retesting where
practical, and publish an advisory after affected releases can be updated.

## Published lab-PoC boundary

The initial public source is a lab proof of concept, not a production-readiness
claim. Within its documented container/host trust boundary, security-sensitive
stores still use pathname validation followed by open operations. A same-UID or
privileged host process that can replace those paths concurrently is trusted.
The signer accepts one allowed-UID connection at a time; an authorized local
peer can consume that service until the bounded per-connection deadline. These
are accepted lab availability and host-trust limits, not confidentiality or
multi-tenant isolation guarantees.

Example-based adversarial contracts are extensive, but continuous fuzzing,
coverage publication and security data-flow analysis remain roadmap work. These
accepted limitations do not block publication of the labelled lab PoC.
Production use requires a threat-model review and, where untrusted same-UID or
host actors are in scope, descriptor-bound no-follow file access and appropriate
signer admission/capacity isolation. Production also requires organization-
approved certificate policy, hardware or equivalently separated key custody,
availability engineering and an external security assessment.

