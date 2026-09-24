# Configuration reference

The committed application settings contain no enrollment authority. Operators
must supply every security-sensitive value explicitly through a protected
deployment overlay.

| Area | Required decisions |
| --- | --- |
| Listener | Exact authority, port, transport, admitted peers, TLS certificate and request limits |
| Kerberos | Realm, service principal, credential supervisor, channel binding and directory policy |
| Directory | TLS endpoint, base DN, exact computer and technician group identifiers, timeouts |
| Facts | Owner-only facts, immutable asset catalogue, revision policy, audit and recovery paths |
| CA | HTTPS enrollment endpoint, pinned trust and revocation, exact template and response limits |
| Signer | `pkcs11` or explicit development `pem-file`, generation pin, socket identity and replay store |
| PKCS#11 | Absolute module and PIN-file paths, exact token label and serial, key ID and bounded sessions |
| State | Separate owner-only journal, bootstrap, quota, binding and recovery stores with retention budgets |

Never infer a signer provider, key path, secret path, template, listener, or
directory group. Unknown, incomplete, duplicate, or semantically overlapping
values must stop startup. Keep environment-specific values outside the public
tree and outside container images.

Copy `.env.example` to an untracked `.env` as a key catalogue. Its names use
the .NET double-underscore mapping and are consumed by the application. The
committed values are deliberately non-runnable: startup rejects `CHANGE_ME`,
`example.test`, and TEST-NET placeholders. Replace them with the deployment's
reviewed values, keep listeners disabled until their complete dependency set is
mounted, and pass `.env` to the container runtime.

Private keys, Kerberos keytabs, signer authentication tokens, and PINs must be
regular, non-link files owned by the consuming process UID with exact mode
`0600`, mounted read-only from a secret provider. When signer and listener UIDs
differ, materialize separate byte-identical authentication-token files for the
two UIDs; a shared group-readable file is rejected. Environment variables hold
only their in-container paths. Policy, trust, facts, bootstrap, and facts
management files are a separate non-secret deployment overlay and still require
restricted write custody outside Git.

The example Compose file mounts subdirectories below
`PKIPROXY_DEPLOYMENT_ROOT`: `config`, `trust`, `facts`, `tls`, `secrets`,
`signer`, `signer-ipc`, and `state`. Keep that root outside the source checkout.
The secret provider must materialize the `secrets` files with owner-only modes;
the isolated signer owns its socket and key material. The broker receives only
the signer's public certificate, authenticated socket, and token-file path.

`Broker__Signer__` key names bind case-insensitively as standard .NET
configuration keys. The signer schema contains scalar leaves only. Unknown or
misspelled keys, nested children and numeric collection children stop startup
before secret-file, provider, signing or listener activity.

Use documentation identities such as `broker.example.test`, `ca.example.test`,
`client-001.example.test`, and TEST-NET address ranges. Do not copy operational
values into example configuration.
