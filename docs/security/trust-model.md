# Security model

The broker enforces these core properties:

- client input cannot select subject, SAN claims, template, or issuer;
- Kerberos identity comes from the authenticated connection, never a header;
- renewal requires possession of a current broker-issued certificate and a
  durable binding to its asset;
- bootstrap approval binds one validated CSR and SPKI pair to one immutable asset;
- malformed or oversized input fails before state, signer, directory, or CA work;
- CA submission is claimed durably before transport and ambiguous outcomes are
  reconciled without blind retry;
- certificate release requires exact key, identity, usage, chain, and revocation
  validation;
- signer provider selection is explicit and missing or conflicting settings fail
  before readiness;
- public health traffic cannot invoke the private key.

The broker deliberately supports a constrained RSA and Microsoft enrollment
profile. Unsupported algorithms, extensions, actions, templates, providers, and
state versions fail closed.

Private keys, authentication tokens, raw SOAP requests, CSRs, keytabs, PINs,
and private operational evidence must not be logged or committed. Durable state
directories require a dedicated operating-system identity and restrictive
permissions. Production deployments should place signer custody behind hardware
or an equivalently separated service and should treat host administrators as a
documented trust boundary.

The public snapshot is produced from a private source repository by a
default-deny exporter. It contains no Git history and no private deployment
evidence. Publication still requires an owner-approved license and completion
of the public release checklist. Security reporting, support, contribution,
governance, and third-party inventory policies are part of the exported tree.
