# Quick start

This path proves that the public snapshot builds and that its fail-closed
contracts pass. It does **not** create a usable enrollment authority.

## Build and test

Install the .NET 10 SDK, then run:

```bash
dotnet restore PkiProxy.slnx --locked-mode \
  -p:NuGetAudit=true -p:NuGetAuditMode=all -p:TreatWarningsAsErrors=true
dotnet run --no-restore --project tests/PkiProxy.PublicContractTests -c Release
dotnet publish src/PkiProxy.Api/PkiProxy.Api.csproj -c Release --no-restore \
  /p:UseAppHost=false /p:PathMap="$(pwd)=/_/src"
```

The default settings expose only a loopback development listener and keep
enrollment disabled. A real deployment requires separately governed directory,
CA, signer, trust, facts, state, TLS and Kerberos inputs.

## Run the public image

The [Docker Hub image](deployment/docker-hub.md) packages the same public source.
After completing `.env` and its external mounts:

```bash
docker compose pull
docker compose up -d --no-build
```

Use a reviewed immutable digest for a controlled deployment.

## Build the documentation

CI uses an immutable MkDocs Material container. With a local MkDocs Material
9.6.20 installation, run:

```bash
mkdocs build --strict -f mkdocs.yml
python3 tools/check-doc-links.py .
```

The generated `site/` directory is disposable output and is never the source of
truth. Markdown, Mermaid diagrams and `mkdocs.yml` are the reviewed inputs.

## Before enabling enrollment

1. Read the [concepts](concepts.md) and [threat model](security/threat-model.md).
2. Design the [deployment topology](deployment/topology.md) and separate signer.
3. Supply every value in the [configuration reference](reference/configuration.md).
4. Establish restrictive ownership for secrets and durable stores.
5. Validate rollback while listeners remain private.
6. Run native Windows interoperability and failure tests in an isolated estate.

The included software-PKCS#11 path supports a lab proof of concept. Production
signing keys require an independently governed hardware or equivalent boundary.
