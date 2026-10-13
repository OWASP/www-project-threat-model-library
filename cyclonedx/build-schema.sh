#!/usr/bin/env bash
# Rebuilds the bundled CycloneDX threat model schema from the pinned
# CycloneDX specification fork, using that fork's own schema bundler.
#
# The external SPDX, behaviour taxonomy and cryptography definition schemas
# are bundled too, so the output is fully self-contained.
#
# Usage: cyclonedx/build-schema.sh
# Requires: git, node, npm
set -euo pipefail

SPEC_REPO="https://github.com/P3tra-WP/specification.git"
SPEC_BRANCH="2.0-dev-threatmodeling-library-parity"
SPEC_COMMIT="7973584488bba51107d62c96d630047d1b68ff05"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git clone --quiet --branch "$SPEC_BRANCH" "$SPEC_REPO" "$work/spec"
git -C "$work/spec" checkout --quiet "$SPEC_COMMIT"

mkdir -p "$work/build/model"
cp "$work/spec/schema/2.0/model/"*.schema.json "$work/build/model/"
for external in spdx behavior-taxonomy cryptography-defs; do
    cp "$work/spec/schema/$external.schema.json" "$work/build/model/"
done
cp "$here/cyclonedx-threat-model-2.0.schema.json" "$work/build/"

bundler="$work/spec/tools/src/main/js/bundler"
(cd "$bundler" && npm ci --silent)
node -e '
const { bundleSchemas } = require(process.argv[1]);
bundleSchemas(process.argv[2], process.argv[3], { validate: true, refExceptions: [] })
    .catch(() => process.exit(1));
' "$bundler/bundle-schemas.js" "$work/build/model" "$work/build/cyclonedx-threat-model-2.0.schema.json" >/dev/null

cp "$work/build/cyclonedx-threat-model-2.0-bundled.schema.json" "$here/"
echo "Bundled schema written to $here (fork commit ${SPEC_COMMIT:0:7})"
