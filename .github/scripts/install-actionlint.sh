#!/usr/bin/env bash
set -euo pipefail

readonly version="1.7.12"
readonly archive="actionlint_${version}_linux_amd64.tar.gz"
readonly expected_sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
readonly install_dir="${RUNNER_TEMP:?RUNNER_TEMP must be set}/actionlint-${version}"
readonly archive_path="${RUNNER_TEMP}/${archive}"

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --output "$archive_path" \
  "https://github.com/rhysd/actionlint/releases/download/v${version}/${archive}"
printf '%s  %s\n' "$expected_sha256" "$archive_path" | sha256sum --check --strict

mkdir --parents "$install_dir"
tar --extract --gzip --file "$archive_path" --directory "$install_dir" actionlint
rm --force "$archive_path"
printf '%s\n' "$install_dir" >> "${GITHUB_PATH:?GITHUB_PATH must be set}"
"$install_dir/actionlint" -version
