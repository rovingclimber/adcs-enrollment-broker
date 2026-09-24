# Deployment topology and rollback

```mermaid
flowchart TB
  W[Windows clients] -->|private HTTPS: XCEP and WSTEP| LB[Broker listeners]
  T[Technician clients] -->|private HTTPS and Kerberos| LB
  LB --> BP[Broker policy process]
  BP -->|LDAPS and Kerberos| D[Directory]
  BP -->|read-only| F[(Facts overlay)]
  BP -->|authenticated Unix socket| S[Isolated signer]
  S --> H[(Hardware HSM or lab software PKCS#11)]
  BP -->|restricted HTTPS enrollment| C[CA service]
  BP --> Q[(Durable state generation)]
  M[Private monitoring] --> BP
```

Keep all listeners private. Separate the signer process, identity, socket,
replay store and key provider from the network-facing broker. Mount configuration,
trust, facts, TLS, secrets and state from an external deployment root; do not
bake them into the image.

## Generation-based release

```mermaid
sequenceDiagram
  participant O as Operator
  participant N as New generation
  participant D as Dependencies
  participant A as Active generation
  participant P as Previous generation
  O->>N: Stage exact protected-CI artifact and external overlay
  N->>N: Verify provenance, ownership and configuration
  N->>D: Private readiness checks
  D-->>N: Ready
  O->>A: Atomically switch listeners to new generation
  A-->>O: Native smoke and health evidence
  alt acceptance fails
    O->>A: Stop failed generation
    O->>P: Reactivate preserved previous generation
    P-->>O: Health and protocol smoke pass
  else acceptance passes
    O->>P: Retain stopped for rollback window
  end
```

Rollback changes the active application generation and its compatible state as
one controlled action. Never delete the previous image, configuration, signer
generation, replay data or journals until the rollback window closes. A schema
change needs an explicit forward and reverse compatibility decision.

The included Compose file is a generic wiring example. It is not a production
orchestration design, firewall policy, backup system or secret provider.
