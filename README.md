# AD CS Enrollment Broker

AD CS Enrollment Broker is a policy and registration-authority layer between
native Windows certificate-enrollment clients and Microsoft Active Directory
Certificate Services (AD CS). It implements the supported portions of MS-XCEP
and MS-WSTEP, derives certificate identity from authoritative server-side facts,
and submits restricted requests through AD CS enrollment services.

The broker supports three enrollment paths:

- domain computers authenticated with Kerberos;
- guarded bootstrap requests paired to an immutable asset by an authenticated
  technician;
- renewal authenticated with an existing broker-issued client certificate.

All paths validate proof of possession and replace client-supplied identity with
broker policy. The returned certificate is checked against the approved public
key, subject, SAN set, EKU, key usage, chain, and revocation policy before it is
released.

This snapshot contains product source, synthetic tests and publication-safe
documentation. It intentionally excludes deployment records, private topology,
operational evidence, credentials, certificate identifiers, and Git history.

## Documentation

- [Documentation home](docs/index.md) and [quick start](docs/quick-start.md)
- [System context and trust boundaries](docs/architecture/system-context.md)
- [Component architecture](docs/architecture/components.md)
- [Trust boundaries and durable state](docs/architecture/trust-boundaries.md)
- [Protocol flows](docs/protocols/enrollment-flows.md)
- [Deployment topology and rollback](docs/deployment/topology.md)
- [Operations](docs/operations.md) and [troubleshooting](docs/troubleshooting.md)
- [Security model](docs/security/trust-model.md)
- [Threat model](docs/security/threat-model.md)
- [Security reporting](SECURITY.md)
- [Support policy](SUPPORT.md)
- [Contribution guide](CONTRIBUTING.md)
- [License](LICENSE) and [attribution notice](NOTICE)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Release governance](docs/security/release-governance.md)
- [Configuration reference](docs/reference/configuration.md)
- [Build and test](docs/development/build-and-test.md)
- [Glossary](docs/reference/glossary.md)
- [Protected-artifact image build](docs/development/build-and-test.md#build-the-protected-ci-artifact)

## Quick build

```bash
dotnet restore PkiProxy.slnx --locked-mode
dotnet run --no-restore --project tests/PkiProxy.PublicContractTests -c Release
dotnet publish src/PkiProxy.Api/PkiProxy.Api.csproj -c Release --no-restore \
  /p:PathMap="$(pwd)=/_/src"
```

The default application configuration exposes a loopback development listener
with enrollment disabled. A real deployment requires explicit authenticated
listener, directory, CA, signer, state-store, trust, and revocation settings.
Start from `.env.example`; its real application keys contain reserved placeholders
that startup rejects until an operator supplies reviewed deployment values.

AD CS Enrollment Broker is licensed under the [Apache License 2.0](LICENSE). Public release
also requires completion of the [public release checklist](RELEASE_CHECKLIST.md).
