# regression_gate.ps1 — حارس عدم التراجع
# Usage: .\scripts\regression_gate.ps1
# يقارن النتائج بـ baseline.json ويُرجع exit code 1 عند أي تراجع.

param(
    [string]$BaselineFile = "$PSScriptRoot\baseline.json",
    [switch]$SaveBaseline
)

$ROOT    = Split-Path $PSScriptRoot -Parent
$BACKEND = Join-Path $ROOT "backend"
$FRONTEND= Join-Path $ROOT "frontend"
$VENV_PY = Join-Path $BACKEND "venv\Scripts\python.exe"

$PASS = $true
$report = @()

function Log-Check($label, $ok, $detail) {
    $sym = if ($ok) { "PASS" } else { "FAIL" }
    $color = if ($ok) { "Green" } else { "Red" }
    Write-Host "[$sym] $label — $detail" -ForegroundColor $color
    if (-not $ok) { $script:PASS = $false }
    $script:report += [PSCustomObject]@{ Check=$label; Status=$sym; Detail=$detail }
}

Write-Host "`n=== Regression Gate ===" -ForegroundColor Cyan

# ── 1. Read baseline ─────────────────────────────────────────────────────────
$baseline = $null
if (Test-Path $BaselineFile) {
    $baseline = Get-Content $BaselineFile | ConvertFrom-Json
} else {
    Write-Host "[WARN] No baseline.json found — will save current run as baseline." -ForegroundColor Yellow
    $SaveBaseline = $true
}

# ── 2. Run pytest ────────────────────────────────────────────────────────────
Write-Host "`n[1/4] Running pytest..." -ForegroundColor Cyan
$pytestOut = & $VENV_PY -m pytest "$BACKEND\tests" -q -p no:cacheprovider 2>&1
$pytestText = $pytestOut -join "`n"

$passedMatch = [regex]::Match($pytestText, '(\d+) passed')
$failedMatch = [regex]::Match($pytestText, '(\d+) failed')
$passed = if ($passedMatch.Success) { [int]$passedMatch.Groups[1].Value } else { 0 }
$failed = if ($failedMatch.Success) { [int]$failedMatch.Groups[1].Value } else { 0 }
$total  = $passed + $failed

Write-Host "  pytest: $passed passed, $failed failed (total $total)"

if ($baseline) {
    $prevPassed = $baseline.pytest.passed
    $prevFailed = $baseline.pytest.failed
    # Rule: no previously-passing test may become failing
    $regressionFail = $failed -gt $prevFailed
    Log-Check "pytest no-regression" (-not $regressionFail) "was:$prevFailed failed → now:$failed failed"
} else {
    Log-Check "pytest baseline" ($passed -gt 0) "$passed passed"
}

# ── 3. Vite build ────────────────────────────────────────────────────────────
Write-Host "`n[2/4] Running vite build..." -ForegroundColor Cyan
Push-Location $FRONTEND
$buildOut = npx vite build 2>&1
$buildText = $buildOut -join "`n"
$buildOk = $LASTEXITCODE -eq 0
Pop-Location

# Extract bundle size from vite output (kB)
$sizeMatch = [regex]::Match($buildText, 'dist/assets/index[^\s]+\s+([\d.]+)\s+kB')
$bundleKb = if ($sizeMatch.Success) { [double]$sizeMatch.Groups[1].Value } else { 0 }

if ($baseline -and $baseline.vite_build.bundle_size_kb -gt 0) {
    $prevKb  = $baseline.vite_build.bundle_size_kb
    $maxKb   = $prevKb * 1.10
    $sizeOk  = $bundleKb -le $maxKb
    Log-Check "vite build" $buildOk "exit=$($LASTEXITCODE)"
    Log-Check "bundle size ≤+10%" $sizeOk "${bundleKb}kB vs baseline ${prevKb}kB (max ${maxKb}kB)"
} else {
    Log-Check "vite build" $buildOk "exit=$($LASTEXITCODE)"
}

# ── 4. Smoke tests ───────────────────────────────────────────────────────────
Write-Host "`n[3/4] Smoke tests..." -ForegroundColor Cyan
try {
    $health = Invoke-WebRequest -Uri "http://localhost:5000/health" -UseBasicParsing -TimeoutSec 5
    Log-Check "/health" ($health.StatusCode -eq 200) "HTTP $($health.StatusCode)"
} catch {
    Log-Check "/health" $false "ERROR: $_"
}

try {
    $phd = Invoke-WebRequest -Uri "http://localhost:5000/api/phd/opportunities?limit=1" -UseBasicParsing -TimeoutSec 5
    Log-Check "/api/phd/opportunities" ($phd.StatusCode -eq 200) "HTTP $($phd.StatusCode)"
} catch {
    Log-Check "/api/phd/opportunities" $false "ERROR: $_"
}

try {
    $fe = Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing -TimeoutSec 5
    Log-Check "Frontend :3000" ($fe.StatusCode -eq 200) "HTTP $($fe.StatusCode)"
} catch {
    Log-Check "Frontend :3000" $false "ERROR: $_"
}

# ── 5. Save baseline if requested ───────────────────────────────────────────
if ($SaveBaseline) {
    $newBaseline = @{
        date    = (Get-Date -Format "yyyy-MM-dd")
        pytest  = @{ total=$total; passed=$passed; failed=$failed }
        vite_build = @{ status=if($buildOk){"pass"}else{"fail"}; bundle_size_kb=$bundleKb }
    } | ConvertTo-Json -Depth 5
    $newBaseline | Set-Content -Path $BaselineFile -Encoding utf8
    Write-Host "`n[4/4] Baseline saved to $BaselineFile" -ForegroundColor Green
}

# ── Result ───────────────────────────────────────────────────────────────────
Write-Host "`n=== Regression Gate Result ===" -ForegroundColor Cyan
$report | Format-Table -AutoSize

if ($PASS) {
    Write-Host "ALL CHECKS PASSED — no regression detected." -ForegroundColor Green
    exit 0
} else {
    Write-Host "REGRESSION DETECTED — fix before merging." -ForegroundColor Red
    exit 1
}
