# Operational facts update flow

```mermaid
sequenceDiagram
  participant O as Authorized operator
  participant W as Local facts workbench
  participant P as Reviewed publisher
  participant F as Active facts store
  participant A as Audit and recovery store
  participant B as Broker
  O->>W: Edit allowlisted mutable facts
  W->>W: Validate immutable identity and schema
  W-->>O: Draft preview and content digest
  O->>P: Submit reviewed draft and expected revision
  P->>P: Authenticate actor, verify digest and revision
  P->>A: Write recovery copy and chained audit entry
  P->>F: Atomic publish
  B->>F: Read current revision for next policy decision
  F-->>B: Authoritative immutable identity and current facts
```

The workbench creates a draft; it cannot publish. The publisher runs under a
separate identity, accepts only allowlisted fields, protects immutable asset
identity, performs optimistic revision checks and records a hash-linked audit
entry. Facts affect the next enrollment or renewal decision; editing facts does
not rewrite an already-issued certificate.

If publication fails after a recovery record is written, operators reconcile
the recorded revision and hashes before retrying. Never repair the active JSON
file by hand.
