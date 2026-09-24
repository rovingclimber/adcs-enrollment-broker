# Concepts

AD CS Enrollment Broker is a narrow registration-authority boundary between
native Windows clients and Microsoft AD CS. It allows clients to use MS-XCEP
policy discovery and MS-WSTEP enrollment while keeping certificate identity
under server-side policy.

| Concept | Meaning |
| --- | --- |
| Authoritative facts | Asset identity, hostname, class and use case read from governed server-side sources. |
| Certificate claim | An allowlisted subject or SAN value derived from authenticated identity and governed facts, rather than accepted from the client. |
| Relying party | RADIUS or another service that validates the certificate and makes the final authorization decision. |
| Use-based policy | A compact authorization rule that evaluates an approved endpoint-use claim instead of maintaining a mapping for every certificate identity. |
| Signed facts snapshot | The approved claims captured at issuance. Later fact changes require renewal, replacement, revocation, or another relying-party control before access changes. |
| Client proof | A CSR, CMC proof, Kerberos identity or existing certificate that proves key or identity possession without choosing certificate claims. |
| Broker binding | Durable association between a broker-issued certificate and its approved asset. |
| Signing intent | Canonical versioned request sent to the isolated signer after policy validation. |
| Submission journal | Durable claim made before CA transport to prevent blind duplicate submission. |
| Bootstrap transaction | Expiring CSR/SPKI-bound request that needs authenticated technician approval for an immutable asset. |
| Readiness | Private dependency status. Public liveness never exercises a key, directory or CA. |

The client generates and retains its private key. The broker authenticates the
requester, looks up current facts, replaces client-supplied identity, asks the
isolated signer to authorize the approved CMC request, submits once to the CA,
and validates the issued certificate before returning it.

The broker is not in the live EAP-TLS decision path. The relying party validates
the issued certificate and applies its own policy to the approved claims. Those
claims are not live inventory data: certificate lifetime, renewal cadence, and
revocation determine how quickly a changed fact can affect access.

The product intentionally implements a constrained RSA and Microsoft enrollment
profile. Unsupported algorithms, actions, extensions, templates, providers and
state versions fail closed.

See [why this exists](why.md), [system context](architecture/system-context.md),
[enrollment flows](protocols/enrollment-flows.md), and the
[glossary](reference/glossary.md).
