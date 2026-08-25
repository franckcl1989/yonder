param(
    [Parameter(Mandatory = $true)]
    [string]$CriterionRoot,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$limits = @(
    [ordered]@{
        Name = 'terminal/fixed_buffer_copy_16k'
        RelativePath = @('terminal_fixed_buffer_copy_16k', 'new', 'estimates.json')
        MaximumNanoseconds = 2000000.0
        Bytes = 16 * 1024
    },
    [ordered]@{
        Name = 'terminal/audit_concurrent_copy_16k'
        RelativePath = @('terminal_audit_concurrent_copy_16k', 'new', 'estimates.json')
        MaximumNanoseconds = 20000000.0
        Bytes = 16 * 1024
    },
    [ordered]@{
        Name = 'file/async_stream_hash_atomic_commit_64k'
        RelativePath = @('file', 'async_stream_hash_atomic_commit_64k', 'new', 'estimates.json')
        MaximumNanoseconds = 50000000.0
        Bytes = 64 * 1024
    },
    [ordered]@{
        Name = 'audit/append_batch_64k'
        RelativePath = @('audit', 'append_batch_64k', 'new', 'estimates.json')
        MaximumNanoseconds = 20000000.0
        Bytes = 64 * 1024
    },
    [ordered]@{
        Name = 'audit/finalize_sync'
        RelativePath = @('audit_finalize_sync', 'new', 'estimates.json')
        MaximumNanoseconds = 500000000.0
        Bytes = 0
    }
)

function Join-PathSegments {
    param([string]$Root, [object[]]$Segments)

    $path = $Root
    foreach ($segment in $Segments) {
        $path = Join-Path $path ([string]$segment)
    }
    return $path
}

$results = [ordered]@{}
foreach ($limit in $limits) {
    $estimatePath = Join-PathSegments -Root $CriterionRoot -Segments $limit.RelativePath
    if (-not (Test-Path -LiteralPath $estimatePath -PathType Leaf)) {
        throw "missing Criterion estimate for $($limit.Name): $estimatePath"
    }
    $estimate = Get-Content -LiteralPath $estimatePath -Raw | ConvertFrom-Json
    $upper = [double]$estimate.mean.confidence_interval.upper_bound
    if (-not [double]::IsFinite($upper) -or $upper -le 0) {
        throw "invalid Criterion mean upper bound for $($limit.Name): $upper"
    }
    $throughput = if ($limit.Bytes -eq 0) {
        $null
    } else {
        ([double]$limit.Bytes * 1000000000.0) / ($upper * 1MB)
    }
    $passed = $upper -le $limit.MaximumNanoseconds
    $results[$limit.Name] = [ordered]@{
        mean_upper_ns = $upper
        maximum_ns = $limit.MaximumNanoseconds
        throughput_mib_per_second = $throughput
        passed = $passed
    }
}

$terminalConcurrent = $results['terminal/audit_concurrent_copy_16k'].mean_upper_ns
$auditBatch = $results['audit/append_batch_64k'].mean_upper_ns
$maximumRelativeRatio = 2.0
$relativePassed = $terminalConcurrent -le ($auditBatch * $maximumRelativeRatio)
$results['relative/terminal_vs_audit_batch'] = [ordered]@{
    terminal_mean_upper_ns = $terminalConcurrent
    audit_batch_mean_upper_ns = $auditBatch
    maximum_ratio = $maximumRelativeRatio
    actual_ratio = $terminalConcurrent / $auditBatch
    passed = $relativePassed
}

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory) {
    New-Item -ItemType Directory -Force $outputDirectory | Out-Null
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding utf8

$failed = @($results.GetEnumerator() | Where-Object { -not $_.Value.passed })
foreach ($entry in $results.GetEnumerator()) {
    $value = $entry.Value
    if ($value.Contains('throughput_mib_per_second') -and $null -ne $value.throughput_mib_per_second) {
        Write-Host ("{0}: upper={1:N0} ns, throughput>={2:N2} MiB/s, pass={3}" -f `
                $entry.Key, $value.mean_upper_ns, $value.throughput_mib_per_second, $value.passed)
    } elseif ($value.Contains('mean_upper_ns')) {
        Write-Host ("{0}: upper={1:N0} ns, pass={2}" -f `
                $entry.Key, $value.mean_upper_ns, $value.passed)
    } else {
        Write-Host ("{0}: ratio={1:N3}, pass={2}" -f `
                $entry.Key, $value.actual_ratio, $value.passed)
    }
}
if ($failed.Count -ne 0) {
    throw "performance gate failed: $($failed.Key -join ', ')"
}
