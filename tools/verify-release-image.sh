#!/bin/sh
set -eu

usage() { echo "Usage: tools/verify-release-image.sh IMAGE_REFERENCE RELEASE_MANIFEST" >&2; exit 64; }
[ "$#" -eq 2 ] || usage
image_ref=$1
manifest=$2
printf '%s\n' "$image_ref" | grep -Eq '^[A-Za-z0-9._:/@-]+$' || usage
command -v docker >/dev/null 2>&1 || { echo "docker is required." >&2; exit 69; }
command -v curl >/dev/null 2>&1 || { echo "curl is required." >&2; exit 69; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required." >&2; exit 69; }
[ -f "$manifest" ] || { echo "Release provenance is required." >&2; exit 66; }

tmp=$(mktemp -d)
name="pki-proxy-release-check-$$"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM
docker image inspect "$image_ref" > "$tmp/image-inspect.json"
docker run --rm --network none --entrypoint sha256sum "$image_ref" /app/PkiProxy.Api.dll > "$tmp/api.sha256"
python3 tools/release-evidence.py verify-image --manifest "$manifest" \
  --inspect "$tmp/image-inspect.json" --api-digest "$tmp/api.sha256"

docker run --detach --name "$name" --read-only --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true --network bridge \
  --publish 127.0.0.1::8080 "$image_ref" >/dev/null
host_port=$(docker port "$name" 8080/tcp | sed -n 's/^127\.0\.0\.1:\([0-9][0-9]*\)$/\1/p')
[ -n "$host_port" ] || { echo "Exact loopback test port unavailable." >&2; exit 70; }
attempt=0
while :; do
  attempt=$((attempt + 1))
  [ "$attempt" -le 30 ] || { echo "Disabled release image did not become healthy." >&2; exit 70; }
  health=$(curl --silent --show-error --output "$tmp/health" --write-out '%{http_code}' --max-time 2 "http://127.0.0.1:$host_port/healthz" || true)
  [ "$health" = "200" ] && break
  sleep 1
done
ready=$(curl --silent --show-error --output "$tmp/ready" --write-out '%{http_code}' --max-time 2 "http://127.0.0.1:$host_port/readyz" || true)
[ "$ready" = "503" ] || { echo "Credential-free image did not fail readiness closed." >&2; exit 70; }
trap - EXIT HUP INT TERM
cleanup
echo "Release admission and smoke passed: health=200 readiness=503"
