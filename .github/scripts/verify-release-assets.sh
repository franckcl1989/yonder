#!/usr/bin/env bash
set -euo pipefail

readonly dist="${1:?release asset directory is required}"
test -d "$dist"

expected="$(mktemp)"
actual="$(mktemp)"
checksum_names="$(mktemp)"
trap 'rm -f "$expected" "$actual" "$checksum_names"' EXIT

cat <<'EOF' | LC_ALL=C sort >"$expected"
Cargo.lock
LICENSE-APACHE
LICENSE-MIT
SHA256SUMS
THIRD-PARTY-LICENSES.html
yon-linux-aarch64.tar.gz
yon-linux-x86_64.tar.gz
yon-macos-aarch64.tar.gz
yon-macos-x86_64.tar.gz
yon-relay-linux-aarch64.tar.gz
yon-relay-linux-x86_64.tar.gz
yon-relay-macos-aarch64.tar.gz
yon-relay-macos-x86_64.tar.gz
yon-relay-windows-aarch64.zip
yon-relay-windows-x86_64.zip
yon-windows-aarch64.zip
yon-windows-x86_64.zip
yon.cdx.json
yon-relay.cdx.json
EOF

find "$dist" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort >"$actual"
diff --unified "$expected" "$actual"

while IFS= read -r name; do
  test -f "$dist/$name"
  test ! -L "$dist/$name"
  test -s "$dist/$name"
done <"$expected"

test "$(wc -l <"$dist/SHA256SUMS")" -eq 18
(
  cd "$dist"
  sha256sum --check --strict SHA256SUMS
  sed -E 's/^[0-9a-f]{64}  //' SHA256SUMS | LC_ALL=C sort >"$checksum_names"
)
grep -v '^SHA256SUMS$' "$expected" | diff --unified - "$checksum_names"

for component in yon yon-relay; do
  jq --exit-status --arg component "$component" '
    .bomFormat == "CycloneDX"
      and .specVersion == "1.5"
      and .metadata.component.name == $component
  ' "$dist/$component.cdx.json" >/dev/null
done

for suffix in linux-aarch64 linux-x86_64 macos-aarch64 macos-x86_64; do
  for binary in yon yon-relay; do
    archive="$dist/$binary-$suffix.tar.gz"
    test "$(tar --list --gzip --file "$archive" | wc -l)" -eq 1
    test "$(tar --list --gzip --file "$archive")" = "$binary"
  done
done

for suffix in windows-aarch64 windows-x86_64; do
  for binary in yon yon-relay; do
    archive="$dist/$binary-$suffix.zip"
    test "$(unzip -Z1 "$archive" | wc -l)" -eq 1
    test "$(unzip -Z1 "$archive")" = "$binary.exe"
  done
done
