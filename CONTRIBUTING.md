# Contributing

Thank you for helping improve AD CS Enrollment Broker. Keep changes narrow, reviewable, and
grounded in the documented security properties.

## Before opening a change

- Use the issue tracker for non-sensitive proposals and defects.
- Follow [SECURITY.md](SECURITY.md) for suspected vulnerabilities.
- Do not include private infrastructure, real identities, credentials, keys,
  certificate requests, authentication traces, or production evidence.
- Use synthetic `example.test` identities and documentation address ranges in
  tests and examples.
- Do not copy implementation code from protocol-reference projects. Protocol
  behavior must be supported by the normative specification and compatible
  client evidence.

## Change requirements

Explain the problem, the resulting behavior, and the security boundary affected.
Add focused tests for changed behavior, update the public documentation, and
keep package locks and provenance inputs consistent. Run the locked restore,
default contracts, and any relevant provider contracts described in
[the build guide](docs/development/build-and-test.md).

Changes must preserve fail-closed configuration, server-authoritative identity,
proof-of-possession checks, one-submit behavior, strict certificate validation,
and explicit signer-provider selection. CI must never deploy or contact a live
CA, directory, signer, or client.

Contributors must have the right to submit their work. Accepted contributions
are distributed under the repository's Apache-2.0 `LICENSE`.

## Review and release

Maintainers may request a smaller change, additional evidence, or an independent
security review. Passing CI is necessary but does not by itself authorize a
merge, release, deployment, certificate operation, or disclosure. Public
releases follow [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

