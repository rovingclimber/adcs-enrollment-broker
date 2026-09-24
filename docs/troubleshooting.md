# Troubleshooting

| Symptom | Safe checks | Do not |
| --- | --- | --- |
| Policy discovery fails | Confirm listener authority, Kerberos service principal, clock, DNS and directory policy | Enable anonymous domain enrollment |
| Bootstrap remains pending | Check transaction expiry, admitted peer, immutable asset and authenticated approval audit | Treat the six-digit code as authority |
| Signer is not ready | Check explicit provider, generation, socket/token ownership, PKCS#11 token and replay-store version | Fall back silently to a PEM key |
| Request outcome is unknown | Inspect sanitized journal state and reconcile by correlation with the CA | Resubmit blindly or delete the marker |
| Issued certificate is rejected | Compare key, subject, SAN, EKU, usage, chain and revocation against approved values | Disable certificate or revocation checks |
| Renewal picks the wrong certificate | Review native policy and remove superseded suitable certificates | Assume Windows pins a particular certificate |
| Facts publish conflicts | Compare expected/current revisions and audit hashes; create a new reviewed draft | Edit the active store by hand |
| New generation fails acceptance | Stop it and reactivate the preserved compatible generation | Destroy previous state during cutover |

Logs and support bundles must exclude raw SOAP, CSRs, private keys, PINs,
keytabs, authentication tokens and private topology. Use correlation identifiers,
hashes and sanitized state names. Repository `SECURITY.md` defines private
vulnerability reporting and `SUPPORT.md` defines support scope.
