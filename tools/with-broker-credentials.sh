#!/bin/sh
# Optional production entrypoint for a broker that uses a keytab-backed
# Kerberos identity. Ticket refresh failure terminates the broker fail closed.
set -eu
: "${Broker__Kerberos__ServicePrincipal:?Broker Kerberos service principal is required}"
case "$Broker__Kerberos__ServicePrincipal" in
  *CHANGE_ME*|*example.test*|*EXAMPLE.TEST*) echo "Reserved Kerberos placeholder refused." >&2; exit 64 ;;
esac
test -f /run/secrets/broker.keytab
test -z "${KRB5_TRACE:-}"
umask 077
test ! -e /tmp/broker-service.ccache
test ! -L /tmp/broker-service.ccache
exec k5start -q -F -P -a -K 10 -l 1h -m 600 -x \
  -k FILE:/tmp/broker-service.ccache \
  -f /run/secrets/broker.keytab "$Broker__Kerberos__ServicePrincipal" \
  -- dotnet /app/PkiProxy.Api.dll
