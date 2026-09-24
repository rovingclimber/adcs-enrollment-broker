# Operations

## Routine checks

- Monitor process liveness separately from private dependency readiness.
- Alert on signer rejection, replay conflict, journal reconciliation, quota
  pressure, facts revision failure and certificate validation failure.
- Verify directory, CA, DNS, time, chain and revocation freshness.
- Reconcile every ambiguous CA submission before allowing another attempt.
- Test restoration of the complete durable-state and signer generation.

Public health must be constant or cached and must never use the signing key or
turn traffic into a directory/CA probe. Expose detailed readiness only to the
private operator plane.

## Planned change order

1. Export and verify the exact protected CI artifact and provenance.
2. Stage a new immutable application generation.
3. Materialize secrets and configuration with correct ownership.
4. Validate configuration and private readiness before listener cutover.
5. Run synthetic then native protocol smoke tests.
6. Retain the previous stopped generation and evidence for rollback.

## Incident priorities

Stop affected enrollment listeners when identity facts, signer policy, CA trust,
journal integrity or durable bindings cannot be established. Preserve state and
sanitized metadata for reconciliation. Do not relax certificate validation,
delete consumed markers or replay a request to make service appear healthy.
