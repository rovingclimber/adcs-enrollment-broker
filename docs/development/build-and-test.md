# Build and test

Prerequisites are the .NET 10 SDK and the native libraries needed by the
authentication and certificate paths. Package versions are locked.

```bash
dotnet restore PkiProxy.slnx --locked-mode \
  -p:NuGetAudit=true -p:NuGetAuditMode=all -p:TreatWarningsAsErrors=true
dotnet run --no-restore --project tests/PkiProxy.PublicContractTests -c Release
dotnet publish src/PkiProxy.Api/PkiProxy.Api.csproj -c Release --no-restore \
  /p:UseAppHost=false /p:PathMap="$(pwd)=/_/src"
```

The public contract harness uses synthetic identities and verifies representative
fail-closed parsing, authoritative claim mapping, and explicit signer-provider
selection. The private integration suite additionally exercises native Windows,
Kerberos, LDAP, CA, PKCS#11, fault injection, and operational acceptance against
an isolated test estate.

The public snapshot manifest records each exported path, mode, size, and SHA-256
value. Private source paths and commits remain in a separate private provenance
record. Reproduce a release candidate from the same reviewed source twice and
require identical file bytes and public manifest hash before publication.

## Documentation build

Documentation remains Markdown and Mermaid in Git. CI builds it with MkDocs
Material 9.6.20 from a digest-pinned image and parses every diagram with Mermaid
CLI 11.9.0 from a separately digest-pinned image. The build runs in strict mode;
the offline checker also validates local links and heading fragments.

Generated `site/` and diagram renders are CI artifacts, not reviewed source.
GitHub Pages is deliberately inactive. A future public-repository change may
add a least-privilege, SHA-pinned Pages workflow after an owner enables Pages
and validates the exact mirror.

## Build the protected CI artifact

Download the `build-test-evidence` artifacts from a protected-main pipeline
into a directory outside the checkout. The release builder verifies the source
commit, Git tree, public-export manifest, complete source inventory, protected
ref flag, and every published application byte before Docker receives them:

```bash
tools/build-release-image.sh \
  pki-enrollment-broker:rc-1 /path/to/downloaded/artifacts rc-1 ./release-evidence
tools/verify-release-image.sh \
  pki-enrollment-broker:rc-1 ./release-evidence/release-provenance.json
```

The runtime image is non-root and records the source commit, CI pipeline/job,
and provenance digest as labels. Admission checks the running DLL against the
protected artifact and requires the credential-free image to report healthy
but not ready. The release provenance is an unsigned hash chain until a
governed public release-signing identity is established.
