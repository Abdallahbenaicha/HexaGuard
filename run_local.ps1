# run_local.ps1 — HexaGuard/SecuraX One-Command Local Startup
# Usage: .\run_local.ps1
# Stop: Ctrl+C in each terminal, or close the windows opened by this script

$ROOT = $PSScriptRoot
$BACKEND = Join-Path $ROOT "backend"
$FRONTEND = Join-Path $ROOT "frontend"

Write-Host "=== HexaGuard / SecuraX — Local Startup ===" -ForegroundColor Cyan

# ── 1. Backend venv ──────────────────────────────────────────────────────────
$VENV = Join-Path $BACKEND "venv"
if (-not (Test-Path $VENV)) {
    Write-Host "[1/5] Creating Python venv..." -ForegroundColor Yellow
    python -m venv $VENV
}
$ACTIVATE = Join-Path $VENV "Scripts\Activate.ps1"
& $ACTIVATE
Write-Host "[1/5] venv active." -ForegroundColor Green

# ── 2. Install Python deps ───────────────────────────────────────────────────
Write-Host "[2/5] Installing Python dependencies..." -ForegroundColor Yellow
pip install -r (Join-Path $BACKEND "requirements.txt") -q
pip install openpyxl -q
Write-Host "[2/5] Done." -ForegroundColor Green

# ── 3. Generate .env if missing ──────────────────────────────────────────────
$ENV_FILE = Join-Path $BACKEND ".env"
if (-not (Test-Path $ENV_FILE)) {
    Write-Host "[3/5] Generating secure .env..." -ForegroundColor Yellow
    $SECRET = python -c "import secrets; print(secrets.token_hex(32))"
    @"
SECRET_KEY=$SECRET
FLASK_ENV=development
FLASK_DEBUG=0
RATELIMIT_ENABLED=false
DEPLOYMENT_MODE=local
ENABLE_LIVE_BOUNTY_SCANNING=false
ALLOW_LOCAL_LAB_TARGETS=false
ENABLE_BACKGROUND_SCHEDULER=true
"@ | Set-Content -Path $ENV_FILE -Encoding utf8
    Write-Host "[3/5] .env created with random SECRET_KEY." -ForegroundColor Green
} else {
    Write-Host "[3/5] .env already exists — skipping." -ForegroundColor Green
}

# ── 4. Frontend deps ─────────────────────────────────────────────────────────
Write-Host "[4/5] Installing frontend dependencies..." -ForegroundColor Yellow
Push-Location $FRONTEND
if (-not (Test-Path "node_modules")) {
    npm ci --silent
}
Pop-Location
Write-Host "[4/5] Done." -ForegroundColor Green

# ── 5. Launch Backend + Frontend in separate windows ─────────────────────────
Write-Host "[5/5] Starting Backend (port 5000) and Frontend (port 3000)..." -ForegroundColor Yellow

# Backend window
$backendCmd = "cd '$BACKEND'; & '$ACTIVATE'; python app.py; Read-Host 'Press Enter to close'"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd

# Wait for backend to start
Start-Sleep -Seconds 3

# Frontend window
$frontendCmd = "cd '$FRONTEND'; npm run dev; Read-Host 'Press Enter to close'"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd

# Wait then open browser
Start-Sleep -Seconds 4
Start-Process "http://localhost:3000"

Write-Host ""
Write-Host "=== Services starting ===" -ForegroundColor Cyan
Write-Host "  Backend API : http://localhost:5000" -ForegroundColor White
Write-Host "  Frontend    : http://localhost:3000" -ForegroundColor White
Write-Host "  Health check: http://localhost:5000/health" -ForegroundColor White
Write-Host ""
Write-Host "To stop: close the two PowerShell windows that opened." -ForegroundColor Gray
Write-Host "See RUN_LOCAL.md for troubleshooting." -ForegroundColor Gray
