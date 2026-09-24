# Support policy

AD CS Enrollment Broker is a self-hosted certificate-enrollment broker. The public project
provides source code, documentation, and reproducible build evidence; it does
not provide a hosted service, managed PKI, deployment access, or an operational
service-level agreement.

## Supported use

The latest published release is the only supported version. Support covers the
documented protocol subset, build process, configuration contract, and defects
that can be reproduced with synthetic data in an isolated environment.

Questions and non-sensitive defect reports may use the canonical public
repository's issue tracker. Include the version, platform, configuration names
with values removed, expected behavior, actual behavior, and a minimal
reproduction. Search existing issues first.

Use the private process in [SECURITY.md](SECURITY.md) for anything that could
expose a vulnerability, credential, private key, certificate request, directory
identity, internal topology, or personal data.

## Outside the support boundary

The maintainers do not operate a user's CA, directory, network, signer, client,
or recovery process. Environment design, production availability, regulatory
approval, certificate-policy approval, and hardware-signer custody remain the
deploying organization's responsibility. The included SoftHSM path is for
development and test; it is not a production custody recommendation.

Unreleased commits, modified builds, downstream forks, unsupported protocol
profiles, and end-of-life releases are accepted only on a best-effort basis.

The first public release is supported as an isolated lab PoC. Its accepted
pathname race, bounded serial-signer availability, and continuous-fuzz/coverage
gaps are listed in `SECURITY.md`; they do not block that labelled source release.
They do block any inference that the project is production-ready. A production
operator must resolve the applicable host/file isolation and signer availability
requirements from its own threat model and complete the other production gates
documented there.

