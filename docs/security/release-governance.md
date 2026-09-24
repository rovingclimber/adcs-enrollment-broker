# Release governance and provenance

A public candidate is a fresh, history-free export from a reviewed protected
source commit. The public manifest inventories every payload file while a
separate private record binds the export to its protected source. Private
source history, deployment evidence, and operational identifiers never enter
the candidate.

The owner selected Apache License 2.0 for the project. The canonical license
text is unmodified; `NOTICE` identifies the public copyright attribution as
`Copyright 2026 RovingClimber`. RovingClimber is a pseudonym, not a claim that
the project is published by a registered company, brand, or separate entity.

The candidate must pass disclosure, locked dependency restore, contract,
provider, static-analysis, dependency, repository, SBOM, provenance, image, and
clean-room gates. A passing pipeline supplies evidence; it does not authorize a
release. The repository owner makes the publication decision, and the exact
reviewed candidate is mirrored without edits. The license decision does not
authorize a visibility change or release.

Static analysis uses only the repository-controlled policy in
`security/semgrep/pkiproxy-security.yml`; network registry aliases are forbidden.
The retained SARIF must prove warning-free execution of the complete policy.
Runtime assurance builds a local archive from the exact CI application artifact,
then scans that archive for both OS and application dependencies. Canonical
evidence binds source, provenance, image/archive identities, scanner identity
and report bytes, and refuses High or Critical vulnerabilities. Neither step
pushes or deploys an image.

Release provenance is currently an unsigned hash chain. It binds source tree,
public manifest, complete source inventory, build output, application SBOM,
runtime package inventory, container labels, and admitted image. A future
signature requires a separately governed signing identity, custody model,
rotation plan, and verification policy.

Use the root `RELEASE_CHECKLIST.md` for every candidate. A changed file,
dependency, manifest, pipeline input, or generated artifact creates a new
candidate and invalidates earlier approval.

