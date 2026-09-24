# Enrollment protocol flows

These sequences show the security-relevant transitions. Transport details use
the supported MS-XCEP and MS-WSTEP profiles described by the public source.

## Domain enrollment

```mermaid
sequenceDiagram
    participant W as Windows client
    participant B as Broker
    participant D as Directory and facts
    participant S as Isolated signer
    participant C as CA enrollment service
    W->>B: Kerberos-authenticated GetPolicies
    B->>D: Resolve machine and current facts
    D-->>B: Immutable identity and allowlisted facts
    B-->>W: Filtered XCEP policy
    W->>B: MS-WSTEP Issue with CMC and PKCS#10 proof
    B->>B: Bound parsing and CSR policy validation
    B->>D: Fresh identity and facts lookup
    B->>S: Canonical policy-approved signing intent
    S-->>B: CMC signature
    B->>B: Claim submission journal
    B->>C: Restricted template enrollment
    C-->>B: Full response and leaf certificate
    B->>B: Validate key, identity, usage, chain, revocation
    B-->>W: Validated MS-WSTEP response
```

## Guarded bootstrap

```mermaid
sequenceDiagram
    participant W as Workgroup client
    participant B as Broker
    participant T as Technician
    participant D as Asset catalogue
    participant C as CA enrollment service
    W->>B: Bounded anonymous Issue from admitted peer
    B->>B: Validate CSR, reserve quota, retain CSR and SPKI binding
    B-->>W: Pending transaction and short pairing code
    T->>B: Mutual-Kerberos approval for transaction and asset
    B->>D: Validate immutable asset
    D-->>B: Authoritative identity and facts
    B-->>T: Approval recorded
    W->>B: QueryTokenStatus for exact transaction
    B->>B: Recheck binding, approval, expiry and one-submit state
    B->>C: One guarded enrollment submission
    C-->>B: Issued result
    B->>B: Validate and persist terminal release
    B-->>W: Certificate bound to original client key
```

The pairing code locates a transaction; it never grants authority and is never
derived from the private key. Approval requires authenticated technician policy
and an existing immutable asset.

## Certificate renewal

```mermaid
sequenceDiagram
    participant W as Enrolled client
    participant B as Broker
    participant D as Directory and facts
    participant C as CA enrollment service
    W->>B: mTLS MS-XCEP and MS-WSTEP renewal
    B->>B: Validate certificate and broker binding
    B->>D: Re-read current authoritative identity and facts
    D-->>B: Current approved values
    B->>C: Journaled restricted renewal
    C-->>B: Replacement certificate
    B->>B: Validate exact key and certificate policy
    B-->>W: Replacement certificate
```

Windows chooses a suitable client certificate during EAP-TLS and native
enrollment according to its policy and certificate properties. Deployments must
avoid leaving multiple simultaneously suitable certificates when deterministic
selection matters.

Continue with the [signer flow](signer-flow.md), [facts update flow](facts-flow.md)
and [certificate lifecycle](certificate-lifecycle.md).
