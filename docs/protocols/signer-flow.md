# Signer request and replay flow

```mermaid
sequenceDiagram
  participant B as Broker policy engine
  participant J as Submission journal
  participant S as Isolated signer
  participant R as Replay store
  participant K as PKCS#11 key
  participant C as CA enrollment service
  B->>B: Canonicalize approved CMC bytes and metadata
  B->>S: Authenticated PKS2 signing intent
  S->>S: Validate version, generation, profile, template, correlation and digest
  S->>R: Atomically claim correlation and request digest
  alt first valid request
    R-->>S: Claimed
    S->>K: Sign approved digest
    K-->>S: Signature
    S-->>B: Bound signature response
    B->>J: Claim CA submission before transport
    B->>C: Submit restricted request once
  else identical correlation and digest
    R-->>S: Existing identical request
    S->>K: Sign approved digest again
    S-->>B: Bound signature response
    B->>J: Check CA submission claim
  else correlation conflict or policy mismatch
    R-->>S: Conflict
    S-->>B: Fail closed without key use
  end
```

The signer does not decide device identity. It independently limits how its key
can be used. Unknown configuration, legacy framing, unauthenticated peers,
generation mismatch and conflicting correlation reuse fail before signing.
The replay store retains conflict checks across a normal signer restart.

An identical retry may repeat a private-key operation. The submission journal
prevents the retry from becoming a second CA submission. Ambiguous CA outcomes
require reconciliation before any new attempt.
