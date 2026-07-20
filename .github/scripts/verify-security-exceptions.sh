#!/usr/bin/env bash
set -euo pipefail

manifest="${1:?a Cargo manifest path is required}"
metadata="$(
  cargo metadata \
    --manifest-path "$manifest" \
    --locked \
    --all-features \
    --format-version 1
)"

jq -e '
  def stable_semver:
    . as $version
    | if test("^[0-9]+\\.[0-9]+\\.[0-9]+(?:\\+[0-9A-Za-z.-]+)?$") then
        capture("^(?<major>[0-9]+)\\.(?<minor>[0-9]+)\\.(?<patch>[0-9]+)(?:\\+[0-9A-Za-z.-]+)?$")
        | [.major, .minor, .patch]
        | map(tonumber)
      else
        error("non-stable semantic version: \($version)")
      end;
  def versions_of($name):
    [.packages[] | select(.name == $name) | (.version | stable_semver)];
  def package_id($name; $version):
    [.packages[] | select(.name == $name and .version == $version) | .id] as $ids
    | if ($ids | length) == 1 then $ids[0]
      else error("expected exactly one \($name) \($version)")
      end;
  def depends_on($from_name; $from_version; $to_name; $to_version):
    package_id($from_name; $from_version) as $from
    | package_id($to_name; $to_version) as $to
    | any(.resolve.nodes[] | select(.id == $from) | .deps[]?; .pkg == $to);
  def parents_of($name; $version):
    package_id($name; $version) as $child
    | [.resolve.nodes[] | select(any(.deps[]?; .pkg == $child)) | .id]
    | sort;
  (versions_of("curve25519-dalek")) as $curve
  | (versions_of("quinn-proto")) as $quinn
  | ($curve | length) > 0
  and all($curve[]; . >= [4, 1, 3] and . < [5, 0, 0])
  and ($quinn | length) > 0
  and all($quinn[]; . >= [0, 11, 13] and . < [0, 12, 0])
  and depends_on("libp2p"; "0.56.0"; "libp2p-dns"; "0.44.0")
  and depends_on("libp2p-dns"; "0.44.0"; "hickory-resolver"; "0.25.2")
  and depends_on("hickory-resolver"; "0.25.2"; "hickory-proto"; "0.25.2")
  and depends_on("libp2p-quic"; "0.13.1"; "if-watch"; "3.2.2")
  and depends_on("libp2p-tcp"; "0.44.1"; "if-watch"; "3.2.2")
  and depends_on("if-watch"; "3.2.2"; "netlink-packet-core"; "0.8.1")
  and depends_on("netlink-packet-core"; "0.8.1"; "paste"; "1.0.15")
  and (
    parents_of("paste"; "1.0.15")
    == [package_id("netlink-packet-core"; "0.8.1")]
  )
' <<<"$metadata"

feature_tree="$(
  cargo tree \
    --manifest-path "$manifest" \
    --locked \
    --all-features \
    --target all \
    -e normal \
    --prefix none \
    --format '{p}|{f}'
)"

test "$(grep -Fxc 'hickory-resolver v0.25.2|system-config,tokio' <<<"$feature_tree")" -eq 1
test "$(grep -Fxc 'hickory-proto v0.25.2|futures-io,std,tokio' <<<"$feature_tree")" -eq 1
