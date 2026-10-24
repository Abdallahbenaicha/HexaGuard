#!/usr/bin/env bash
# run_local.sh — HexaGuard/SecuraX One-Command Local Startup (Linux/macOS)
# Usage: bash run_local.sh
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

echo "=== HexaGuard / SecuraX — Local Startup ==="

# 1. venv
if [ ! -d "$BACKEND/venv" ]; then
    echo "[1/5] Creating Python venv..."
    python3 -m venv "$BACKEND/venv"
fi
source "$BACKEND/venv/bin/activate"
echo "[1/5] venv active."

# 2. Python deps
echo "[2/5] Installing Python dependencies..."
pip install -r "$BACKEND/requirements.txt" -q
pip install openpyxl -q
echo "[2/5] Done."

# 3. .env
ENV_FILE="$BACKEND/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "[3/5] Generating secure .env..."
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > "$ENV_FILE" << EOF
SECRET_KEY=$SECRET
FLASK_ENV=development
FLASK_DEBUG=0
RATELIMIT_ENABLED=false
DEPLOYMENT_MODE=local
ENABLE_LIVE_BOUNTY_SCANNING=false
ALLOW_LOCAL_LAB_TARGETS=false
ENABLE_BACKGROUND_SCHEDULER=true
EOF
    echo "[3/5] .env created."
else
    echo "[3/5] .env already exists — skipping."
fi

# 4. Frontend deps
echo "[4/5] Installing frontend dependencies..."
cd "$FRONTEND"
[ ! -d node_modules ] && npm ci --silent
cd "$ROOT"
echo "[4/5] Done."

# 5. Launch
echo "[5/5] Starting Backend (5000) and Frontend (3000)..."
cd "$BACKEND" && python app.py &
BACKEND_PID=$!
cd "$FRONTEND" && npm run dev &
FRONTEND_PID=$!

sleep 4
echo ""
echo "=== Services running ==="
echo "  Backend API : http://localhost:5000"
echo "  Frontend    : http://localhost:3000"
echo "  Health check: http://localhost:5000/health"
echo ""
echo "Press Ctrl+C to stop both services."
echo "See RUN_LOCAL.md for troubleshooting."

# Open browser if possible
(sleep 2 && (xdg-open http://localhost:3000 2>/dev/null || open http://localhost:3000 2>/dev/null)) &

wait $BACKEND_PID $FRONTEND_PID
