$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("yonder-performance-gate-" + [guid]::NewGuid())
$criterion = Join-Path $root 'criterion'
$report = Join-Path $root 'report.json'
$gate = Join-Path $PSScriptRoot 'enforce-performance.ps1'

function Write-Estimate {
    param([string[]]$PathSegments, [double]$UpperBound)

    $path = $criterion
    foreach ($segment in $PathSegments) {
        $path = Join-Path $path $segment
    }
    New-Item -ItemType Directory -Force $path | Out-Null
    [ordered]@{
        mean = [ordered]@{
            confidence_interval = [ordered]@{
                confidence_level = 0.95
                lower_bound = $UpperBound * 0.9
                upper_bound = $UpperBound
            }
            point_estimate = $UpperBound * 0.95
            standard_error = 1.0
        }
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $path 'estimates.json') -Encoding utf8
}

try {
    Write-Estimate @('terminal_fixed_buffer_copy_16k', 'new') 50000
    Write-Estimate @('terminal_audit_concurrent_copy_16k', 'new') 500000
    Write-Estimate @('file', 'async_stream_hash_atomic_commit_64k', 'new') 5000000
    Write-Estimate @('audit', 'append_batch_64k', 'new') 10000000
    Write-Estimate @('audit_finalize_sync', 'new') 100000000

    & $gate -CriterionRoot $criterion -OutputPath $report
    $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    if (-not $result.'file/async_stream_hash_atomic_commit_64k'.passed) {
        throw 'passing fixture was not recorded as passing'
    }

    Write-Estimate @('audit_finalize_sync', 'new') 2000000000
    $failed = $false
    try {
        & $gate -CriterionRoot $criterion -OutputPath $report
    } catch {
        $failed = $true
    }
    if (-not $failed) {
        throw 'an over-limit finalization estimate did not fail the gate'
    }

    Write-Estimate @('audit_finalize_sync', 'new') 100000000
    Write-Estimate @('terminal_audit_concurrent_copy_16k', 'new') 15000000
    Write-Estimate @('audit', 'append_batch_64k', 'new') 7000000
    $failed = $false
    try {
        & $gate -CriterionRoot $criterion -OutputPath $report
    } catch {
        $failed = $true
    }
    if (-not $failed) {
        throw 'a terminal-to-audit relative regression did not fail the gate'
    }
} finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
