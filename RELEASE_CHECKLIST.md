# Public release checklist

The private operational repository and its history are never publication
inputs. A release begins with one deterministic, history-free export and ends
with an exact mirror of the reviewed candidate.

## Governance

- [ ] The candidate contains the owner-approved, unmodified Apache-2.0
  `LICENSE` and `NOTICE` with `Copyright 2026 RovingClimber`.
- [ ] Private vulnerability reporting is enabled and the security contact can
  receive reports before visibility changes.
- [ ] `SECURITY.md`, `SUPPORT.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`,
  `NOTICE`, and `THIRD_PARTY_NOTICES.md` match the planned release.
- [ ] Maintainers and protected-branch rules are recorded in the hosting
  platform.

## Candidate identity and assurance

- [ ] The candidate contains one reviewed history-free root and no inherited
  tags, releases, objects, artifacts, or private remote metadata.
- [ ] The public manifest matches every tracked file, mode, size, and digest.
- [ ] Manifest verification ran on POSIX and rejected executable and owner-only
  mode drift; a Windows export alone is never authoritative for file modes.
- [ ] Independent exports from the protected source are byte-identical.
- [ ] Full-history and full-tree disclosure scans pass.
- [ ] Locked restore, default contracts, the real SoftHSM contract, publish,
  static analysis, dependency analysis, and repository scanning pass.
- [ ] Semgrep used the tracked local policy, its policy digest is retained, and
  warning-free SARIF contains the complete expected rule inventory.
- [ ] The exact provenance-bound release-image archive was scanned with native
  OS and application package inventories; the identity-bound report has no High
  or Critical vulnerability.
- [ ] The SPDX SBOM, license results, source inventory, build provenance, and
  runtime package inventory describe the exact candidate.
- [ ] Every license result is reviewed; required notices are present; no
  specification PDF or private operational evidence is included.
- [ ] A clean-room build uses only candidate files and protected build artifacts.
- [ ] Adversarial signer configuration proves unknown, misspelled, nested and
  collection-shaped keys fail before secret, provider, signing or socket activity.
- [ ] Signer keys, PINs and authentication tokens are regular non-link files
  owned by each consuming UID at exact mode `0600`; distinct signer/listener
  UID copies have equal content and no shared group-readable fallback.
- [ ] Release notes label the candidate as a lab PoC and retain the accepted
  pathname-race, bounded serial-signer availability, and fuzz/coverage roadmap
  dispositions from `SECURITY.md`; no production-readiness claim is made.

## Publication

- [ ] The final external security review has accepted this exact candidate or
  every finding is recorded with an explicit disposition.
- [ ] The public destination is empty and has no unrelated history.
- [ ] The mirrored tree and commit are byte-for-byte the reviewed candidate;
  no release-time edits are allowed.
- [ ] The owner explicitly authorizes the visibility change and release.
- [ ] After publication, rerun disclosure and build gates from the public host,
  verify private vulnerability reporting, and record the public commit and
  artifact digests.

Any failed or uncertain item stops publication. Fixes create a new candidate
that repeats the checklist from the beginning.

