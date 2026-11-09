# Operational facts update flow

```mermaid
sequenceDiagram
  participant S as External source of truth
  participant C as Optional HTTP connector
  participant O as Authorized operator
  participant W as Local facts workbench
  participant P as Reviewed publisher
  participant F as Active facts store
  participant A as Audit and recovery store
  participant B as Broker
  alt Snapshot refresh
    C->>S: Bounded lookup for every known identity
    S-->>C: Exactly one bounded JSON record each
    C->>C: Map and validate complete candidate
    C->>P: Candidate plus expected source hash
  else Human edit
  O->>W: Edit allowlisted mutable facts
  W->>W: Validate immutable identity and schema
  W-->>O: Draft preview and content digest
  O->>P: Submit reviewed draft and expected revision
  end
  P->>P: Authenticate actor, verify digest and revision
  P->>A: Write recovery copy and chained audit entry
  P->>F: Atomic publish
  B->>F: Read current revision for next policy decision
  F-->>B: Authoritative immutable identity and current facts
```

The workbench creates a draft; it cannot publish. Snapshot connector mode creates
a complete candidate only after every upstream record succeeds. The publisher runs under a
separate identity, accepts only allowlisted fields, protects immutable asset
identity, performs optimistic revision checks and records a hash-linked audit
entry. Facts affect the next enrollment or renewal decision; editing facts does
not rewrite an already-issued certificate.

Consequently, a facts publication does not dynamically change an active RADIUS
session or the claims presented by an installed certificate. The relying party
continues to evaluate that signed snapshot until a replacement certificate is
issued, the older certificate is revoked or expires, or separate local policy
rejects it. Deployments must align fact stability, certificate lifetime,
renewal cadence, and revocation behavior with their required response time.

Live connector mode follows a different path: initial enrollment makes one
bounded upstream lookup and fails closed when it cannot obtain current facts.
Renewal may use the last accepted local record only while its age is within the
configured maximum. No connector call occurs during an EAP-TLS authentication.

If publication fails after a recovery record is written, operators reconcile
the recorded revision and hashes before retrying. Never repair the active JSON
file by hand.

See [Facts connectors](../facts-connectors.md) for the request, mapping, cache and
provider boundaries.
