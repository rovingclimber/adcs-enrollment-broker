# Component architecture

```mermaid
flowchart TB
    subgraph Listener[Broker listener process]
      I[Ingress bounds]
      A[Kerberos / mTLS authentication]
      Z[Route authorization]
      F[Authoritative facts resolver]
      P[Enrollment policy]
      J[Submission journal]
      V[Issued certificate validator]
      I --> A --> Z --> F --> P --> J
    end
    subgraph Signer[Network-isolated signer process]
      SP[PKS2 policy validator]
      R[Correlation replay store]
      K[Explicit key provider]
      SP --> R --> K
    end
    subgraph State[Durable private state]
      Q[Bootstrap quota ledger]
      X[Bootstrap transactions]
      BF[Broker certificate bindings]
      AF[Facts audit chain]
    end
    P -->|canonical signing intent| SP
    J -->|single guarded submit| CA[CA enrollment service]
    CA --> V
    State --> Listener
```

Inbound SOAP is bounded by raw bytes, read time, XML depth, node count,
attribute count, text size, and decoded token size before DOM, ASN.1, state,
signer, or CA work. Public health is constant or cached; a serialized background
self-test performs dependency checks independently of request traffic.

Durable stores use bounded state graphs and conservative ambiguity handling.
The submission journal claims work before CA transport so retries cannot create
a second submission. Bootstrap reserves count and worst-case bytes before it
publishes a retained request.
