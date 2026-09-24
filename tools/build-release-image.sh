#!/bin/sh
set -eu

usage() { echo "Usage: tools/build-release-image.sh IMAGE_TAG ARTIFACTS_DIR GENERATION OUTPUT_DIR" >&2; exit 64; }
[ "$#" -eq 4 ] || usage
image_tag=$1
artifacts=$2
generation=$3
output=$4
printf '%s\n' "$image_tag" | grep -Eq '^[A-Za-z0-9._:/@-]+$' || usage
printf '%s\n' "$generation" | grep -Eq '^[A-Za-z0-9._-]+$' || usage
command -v git >/dev/null 2>&1 || { echo "git is required." >&2; exit 69; }
command -v docker >/dev/null 2>&1 || { echo "docker is required." >&2; exit 69; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required." >&2; exit 69; }
[ -f Dockerfile.release ] && [ -f "$artifacts/release/provenance.json" ] || { echo "Protected CI artifacts are required." >&2; exit 66; }
git diff --quiet --ignore-submodules --
git diff --cached --quiet --ignore-submodules --
test ! -e artifacts || { echo "Repository artifacts path must not pre-exist." >&2; exit 65; }
test ! -e "$output" || { echo "Output directory must not pre-exist." >&2; exit 65; }

python3 tools/release-evidence.py verify-ci --root . --manifest "$artifacts/release/provenance.json" --build "$artifacts/api"
source_commit=$(python3 tools/release-evidence.py field --manifest "$artifacts/release/provenance.json" --name commit)
source_created=$(git show -s --format=%cI HEAD)
pipeline_id=$(python3 tools/release-evidence.py field --manifest "$artifacts/release/provenance.json" --name pipelineId)
job_id=$(python3 tools/release-evidence.py field --manifest "$artifacts/release/provenance.json" --name jobId)
provenance_sha=$(sha256sum "$artifacts/release/provenance.json" | awk '{print $1}')

mkdir "$output"
cp -R "$artifacts" artifacts
cp artifacts/release/provenance.json "$output/ci-provenance.json"
cp artifacts/release/application.spdx.json "$output/application.spdx.json"
docker build --pull=false --network=default \
  --build-arg "SOURCE_COMMIT=$source_commit" \
  --build-arg "SOURCE_CREATED=$source_created" \
  --build-arg "CI_PIPELINE_ID=$pipeline_id" \
  --build-arg "CI_JOB_ID=$job_id" \
  --build-arg "PROVENANCE_SHA256=$provenance_sha" \
  --file Dockerfile.release --tag "$image_tag" .

docker image inspect "$image_tag" > "$output/image-inspect.json"
docker run --rm --network none --entrypoint sha256sum "$image_tag" /app/PkiProxy.Api.dll > "$output/api.sha256"
docker run --rm --network none --entrypoint cat "$image_tag" /var/lib/dpkg/status > "$output/dpkg-status"
python3 tools/release-evidence.py finalize-image \
  --manifest artifacts/release/provenance.json --inspect "$output/image-inspect.json" \
  --api-digest "$output/api.sha256" --runtime-packages "$output/dpkg-status" \
  --application-sbom "$output/application.spdx.json" \
  --generation "$generation" --output "$output/release-provenance.json"
python3 tools/release-evidence.py verify-image --manifest "$output/release-provenance.json" \
  --inspect "$output/image-inspect.json" --api-digest "$output/api.sha256"
rm -rf artifacts
echo "Release image built and admitted: source=$source_commit generation=$generation"
