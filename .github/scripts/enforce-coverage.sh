#!/usr/bin/env bash
set -euo pipefail

report="${1:-coverage.json}"

jq -r '
  def percent:
    if .count == 0 then
      "n/a"
    else
      (((.covered * 10000 / .count) | floor) / 100 | tostring) + "%"
    end;
  .data[]
  | "coverage totals: "
    + "lines=\(.totals.lines | percent) "
    + "functions=\(.totals.functions | percent) "
    + "regions=\(.totals.regions | percent) "
    + "branches=\(.totals.branches | percent)"
' "$report"

if jq --exit-status '
  .data as $data
  | ($data | length) > 0
  and all($data[];
    .totals.lines.count > 0
    and (.totals.lines.covered * 100 >= .totals.lines.count * 95)
    and .totals.functions.count > 0
    and (.totals.functions.covered * 100 >= .totals.functions.count * 95)
    and .totals.regions.count > 0
    and (.totals.regions.covered * 100 >= .totals.regions.count * 90)
    and .totals.branches.count > 0
    and (.totals.branches.covered * 100 >= .totals.branches.count * 75)
    and all(.files[];
      .summary.lines.count == 0
      or (.summary.lines.covered * 100 >= .summary.lines.count * 75)
    )
  )
' "$report" >/dev/null; then
  exit 0
fi

echo "::error::coverage did not satisfy the risk-based release thresholds"
jq -r '
  .data[].files[]
  | select(
      .summary.lines.count > 0
      and (.summary.lines.covered * 100 < .summary.lines.count * 75)
    )
  | "file below 75% line coverage: \(.filename) "
    + "(\(.summary.lines.covered)/\(.summary.lines.count))"
' "$report"
exit 1
