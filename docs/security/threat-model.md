# Threat model

## Protected assets

The primary assets are CA enrollment authority, signer keys, authoritative
identity and facts, client key binding, durable replay/journal state and the
integrity of issued certificate claims.

| Threat | Main controls | Residual production duty |
| --- | --- | --- |
| Client chooses privileged claims | Server-side identity mapping, allowlisted facts and exact template | Govern directory and facts administrators |
| Malformed SOAP/ASN.1 exhausts service | Raw byte, time, XML, token and DER bounds before side effects | Rate-limit and monitor private ingress |
| Stolen pairing code authorizes bootstrap | Code only locates CSR/SPKI-bound transaction; Kerberos technician approval required | Govern technician groups and admitted peers |
| Duplicate or ambiguous issuance | Durable signer replay store and pre-transport submission journal | Reconcile CA state; back up coherent state |
| Broker compromise uses signing key | Separate authenticated signer, strict intent policy and explicit provider | Hardware-backed key and independent signer administration |
| CA returns wrong certificate | Exact key, subject, SAN, EKU, usage, chain and revocation validation | Maintain trust and revocation availability |
| Configuration typo weakens policy | Unknown and overlapping keys fail before listeners or key access | Review external overlays and ownership |
| Supply-chain substitution | Locked packages, digest-pinned CI, SBOM, scans and protected artifact provenance | Establish governed release signing and public transparency |

## PoC and production boundary

The lab proof establishes protocol interoperability and policy behavior. Its
software PKCS#11 signer is acceptable only for a proof of concept. Production
requires independent key custody, hardened host and network boundaries, a real
secret provider, monitored backups, disaster recovery, governed release signing,
capacity testing and organization-specific audit and incident procedures.

See the [trust model](trust-model.md) and [trust-boundary diagram](../architecture/trust-boundaries.md).
