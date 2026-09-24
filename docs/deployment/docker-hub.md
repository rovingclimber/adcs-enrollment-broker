# Docker Hub image

Public releases are available as:

```text
rovingclimber/adcs-enrollment-broker
```

The initial published platform is `linux/amd64`. Each GitHub release builds the
image from the exact public source, runs the contract suite inside the Docker
build, starts the image without credentials to prove readiness fails closed,
and scans that same local image for High and Critical OS and application
vulnerabilities before any registry login or push. The pushed digest then
receives a GitHub artifact attestation.

## Run with Compose

Copy `.env.example` to `.env`, replace every reserved placeholder, and prepare
the external deployment directories described in the
[configuration reference](../reference/configuration.md). Then:

```bash
docker compose pull
docker compose up -d --no-build
```

Compose defaults to `rovingclimber/adcs-enrollment-broker:latest`. For a
controlled deployment, pin the reviewed digest in `.env`:

```dotenv
PKIPROXY_IMAGE=rovingclimber/adcs-enrollment-broker@sha256:REPLACE_WITH_REVIEWED_DIGEST
PKIPROXY_PULL_POLICY=always
```

The Compose file wires the broker process only. A usable enrollment service
still requires private TLS and Kerberos material, directory authorization, an
authoritative facts source, AD CS/CES trust, durable state, and the separately
isolated signer described in the [deployment topology](topology.md). The image
contains no deployment secrets or lab configuration.

## Tags and verification

A stable published semantic-version release such as `v1.2.3` produces
full-version, major/minor, commit, and `latest` tags. Prereleases and
non-semantic tags fail before registry login. The release tag must resolve to a
commit reachable from protected `main`. Treat tags as discovery aids and deploy
by digest.

Verify the GitHub provenance attestation with the GitHub CLI:

```bash
gh attestation verify \
  oci://docker.io/rovingclimber/adcs-enrollment-broker:VERSION \
  -R rovingclimber/adcs-enrollment-broker
```

This public image is the lab proof-of-concept distribution described by the
project security policy. Its availability does not turn the broker, software
PKCS#11 signer, or example Compose topology into a production-ready authority.
