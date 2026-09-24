# Trust boundaries and durable state

```mermaid
flowchart LR
  subgraph U[Untrusted and semi-trusted callers]
    WC[Windows client]
    OP[Technician browser or client]
  end
  subgraph B[Broker host boundary]
    IN[Bounded protocol listeners]
    PE[Policy engine]
    ST[(Journal, bootstrap, bindings)]
  end
  subgraph S[Separated signer boundary]
    SV[Intent and replay validator]
    KS[(PKCS#11 key store)]
    RS[(Replay store)]
  end
  subgraph A[Authoritative enterprise services]
    DI[Directory]
    FA[Facts and asset catalogue]
    CA[CA enrollment service]
    RV[Chain and revocation sources]
  end
  WC --> IN
  OP --> IN
  IN --> PE
  PE <--> ST
  PE --> DI
  PE --> FA
  PE -->|authenticated local signing intent| SV
  SV --> KS
  SV <--> RS
  PE -->|journaled submission| CA
  PE --> RV
```

| Boundary | Trust placed in it | Required separation |
| --- | --- | --- |
| Client | Generates and retains the private key; presents native proof | Cannot select subject, SAN, template or CA |
| Broker | Authenticates, resolves facts, decides policy and validates output | Dedicated identity; bounded listeners; owner-only state |
| Signer | Enforces intent schema, generation, digest and replay policy | Separate process/UID and socket; production hardware custody |
| Directory/facts | Supplies current identity and policy facts | Authenticated TLS; exact search bases and groups; audited updates |
| CA | Issues only through a restricted template and service identity | Minimal enrollment authority; pinned trust and revocation |

Durable state is part of the security boundary. Journals, transactions, quotas,
bindings, audit chains and replay stores must survive restart, reject unknown
versions and preserve conservative ambiguous outcomes. Back up and restore them
as a coherent generation; never copy only the application image.
