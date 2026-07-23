#!/usr/bin/env bash
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
stage="$(mktemp -d)"
trap 'rm -rf "$fixture" "$stage"' EXIT

printf 'fixture lockfile\n' >"$fixture/Cargo.lock"
printf 'fixture Apache license\n' >"$fixture/LICENSE-APACHE"
printf 'fixture MIT license\n' >"$fixture/LICENSE-MIT"
printf 'fixture third-party licenses\n' >"$fixture/THIRD-PARTY-LICENSES.html"

for component in yon yon-relay; do
  printf '{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"%s"}}}\n' \
    "$component" >"$fixture/$component.cdx.json"
done

for suffix in linux-aarch64 linux-x86_64 macos-aarch64 macos-x86_64; do
  for binary in yon yon-relay; do
    printf 'fixture %s\n' "$binary" >"$stage/$binary"
    tar --create --gzip --file "$fixture/$binary-$suffix.tar.gz" \
      --directory "$stage" "$binary"
  done
done

for suffix in windows-aarch64 windows-x86_64; do
  for binary in yon yon-relay; do
    printf 'fixture %s\n' "$binary" >"$stage/$binary.exe"
    (
      cd "$stage"
      zip --quiet "$fixture/$binary-$suffix.zip" "$binary.exe"
    )
  done
done

(
  cd "$fixture"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\0' \
    | sort --zero-terminated \
    | xargs --null sha256sum >SHA256SUMS
)

bash "$repository_root/.github/scripts/verify-release-assets.sh" "$fixture"

mkdir "$fixture/criterion"
if bash "$repository_root/.github/scripts/verify-release-assets.sh" "$fixture" \
  >/dev/null 2>&1; then
  echo 'release inventory accepted an unexpected directory' >&2
  exit 1
fi
