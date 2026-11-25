# Reproduce the study on Windows (PowerShell 5.1+). Same levels as run_all.sh; see docs/REPLICATION.md.
#   .\run_all.ps1 analysis   Recompute every table and figure from the archived SBOMs (no Docker); checks exactness.
#   .\run_all.ps1 full       Rebuild, re-extract ground truth, re-run all tools and scans (Docker, many hours).
param([ValidateSet("analysis", "full")][string]$Level = "analysis")
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot
$env:PYTHONUTF8 = "1"

if (-not (Test-Path .venv)) { python -m venv .venv }
$Py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $Py -m pip install -q -r requirements.lock.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

function Invoke-Step([string[]]$PyArgs) {
    Write-Host "`n== $(Get-Date -Format HH:mm:ss) $($PyArgs -join ' ')"
    & $Py @PyArgs
    if ($LASTEXITCODE -ne 0) { throw "failed: $($PyArgs -join ' ')" }
}

function Save-Expected {
    Write-Host "`n== snapshot shipped results -> work\expected_results"
    if (Test-Path work\expected_results) { Remove-Item -Recurse -Force work\expected_results }
    New-Item -ItemType Directory -Force work | Out-Null
    Copy-Item -Recurse results work\expected_results
}

function Invoke-Analysis {
    Invoke-Step @("scripts/normalize.py")
    Invoke-Step @("scripts/score.py")
    Invoke-Step @("scripts/analyze.py")
    Invoke-Step @("scripts/sensitivity.py")
    Invoke-Step @("scripts/vuln_scan.py", "--skip-scan")
    Invoke-Step @("scripts/figures.py")
}

$NetTargets = @("J-S2", "J-S3-ubuntu", "J-S3-alpine", "J-S3-distroless", "J-S3-layered", "J-P",
                "G-S2", "G-S3-ubuntu", "G-S3-alpine", "G-S3-distroless", "X-jenkins", "X-keycloak")
$NetExpect = @("J-S2=45", "J-S3-ubuntu=45", "J-S3-alpine=45", "J-S3-distroless=45", "J-S3-layered=45", "J-P=45",
               "G-S2=55", "G-S3-ubuntu=55", "G-S3-alpine=55", "G-S3-distroless=55", "X-jenkins=19", "X-keycloak=71")

if ($Level -eq "analysis") {
    if (-not (Test-Path work\sboms\default)) { throw "work\sboms missing: unpack the data archive (p16-data-*.tar.gz) into the repository root first" }
    Save-Expected
    Invoke-Analysis
    Invoke-Step @("scripts/check_reproduction.py", "--only", "sbom_inventory.json", "metrics.csv", "misses.csv",
                  "false_positives.csv", "tables/*.csv")
} else {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) { throw "Docker engine not reachable" }
    if (-not (Test-Path work\cache\trivy\java-db)) { throw "work\cache missing: unpack the DB snapshot archive (p16-db-snapshots-*.tar.gz) first" }
    Save-Expected
    Invoke-Step @("scripts/build_targets.py")
    Invoke-Step @("scripts/verify_build.py")
    Invoke-Step @("scripts/extract_gt.py")
    Invoke-Step @("scripts/verify_gt.py")
    Invoke-Step @("scripts/run_tools.py", "--reps", "1", "2", "--force")
    Invoke-Step @("scripts/run_tools.py", "--reps", "1", "--config", "best", "--force")
    Invoke-Step (@("scripts/rerun_online.py", "--targets") + $NetTargets + @("--reps", "1", "2", "--expect") + $NetExpect + @("--gap-minutes", "40", "--max-attempts", "5"))
    Invoke-Step (@("scripts/rerun_online.py", "--targets") + $NetTargets + @("--reps", "1", "--config", "best", "--expect") + $NetExpect + @("--gap-minutes", "40", "--max-attempts", "5"))
    Invoke-Step @("scripts/vuln_scan.py")
    Invoke-Analysis
    & $Py scripts/check_reproduction.py
    if ($LASTEXITCODE -ne 0) { Write-Host "(differences listed above: see docs\REPLICATION.md, 'Full re-run')" }
}
Write-Host "`n== done"
