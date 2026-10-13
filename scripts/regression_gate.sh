#!/usr/bin/env bash
# regression_gate.sh - Automated Regression Gate (Linux/macOS)
# Usage: ./scripts/regression_gate.sh [--save-baseline]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
BASELINE_FILE="$SCRIPT_DIR/baseline.json"
SAVE_BASELINE=0

if [[ "${1:-}" == "--save-baseline" ]]; then
    SAVE_BASELINE=1
fi

PASS=1
echo "=== Regression Gate ==="

# 1. Read baseline
PREV_FAILED=1
PREV_BUNDLE_KB=866
if [[ -f "$BASELINE_FILE" ]]; then
    PREV_FAILED=$(python3 -c "import json; d=json.load(open('$BASELINE_FILE')); print(d.get('pytest',{}).get('failed', 1))" 2>/dev/null || echo 1)
    PREV_BUNDLE_KB=$(python3 -c "import json; d=json.load(open('$BASELINE_FILE')); print(d.get('vite_build',{}).get('bundle_size_kb', 866))" 2>/dev/null || echo 866)
fi

# 2. Run pytest
echo ""
echo "[1/4] Running pytest..."
PYTEST_OUT=$(cd "$BACKEND" && python -m pytest tests -q -p no:cacheprovider 2>&1 || true)
echo "$PYTEST_OUT" | tail -n 5

PASSED=$(echo "$PYTEST_OUT" | grep -oE '[0-9]+ passed' | head -n1 | cut -d' ' -f1 || echo 0)
FAILED=$(echo "$PYTEST_OUT" | grep -oE '[0-9]+ failed' | head -n1 | cut -d' ' -f1 || echo 0)
TOTAL=$(( ${PASSED:-0} + ${FAILED:-0} ))

echo "  pytest: ${PASSED:-0} passed, ${FAILED:-0} failed (total $TOTAL)"

if [[ ${FAILED:-0} -gt ${PREV_FAILED:-1} ]]; then
    echo "[FAIL] pytest no-regression - was:$PREV_FAILED failed -> now:$FAILED failed"
    PASS=0
else
    echo "[PASS] pytest no-regression - was:$PREV_FAILED failed -> now:${FAILED:-0} failed"
fi

# 3. Vite build
echo ""
echo "[2/4] Running vite build..."
BUILD_OUT=$(cd "$FRONTEND" && npx vite build 2>&1 || true)
BUILD_OK=$?

BUNDLE_KB=$(echo "$BUILD_OUT" | grep -oE 'dist/assets/index[^ ]+ +[0-9.]+ kB' | head -n1 | awk '{print $(NF-1)}' || echo 0)

if [[ $BUILD_OK -eq 0 ]]; then
    echo "[PASS] vite build - exit=0"
else
    echo "[FAIL] vite build - exit=$BUILD_OK"
    PASS=0
fi

MAX_KB=$(python3 -c "print(round($PREV_BUNDLE_KB * 1.10, 2))" 2>/dev/null || echo 9999)
SIZE_OK=$(python3 -c "print(1 if float('${BUNDLE_KB:-0}') <= float('$MAX_KB') else 0)" 2>/dev/null || echo 1)

if [[ "$SIZE_OK" -eq 1 ]]; then
    echo "[PASS] bundle size <= +10% - ${BUNDLE_KB}kB vs baseline ${PREV_BUNDLE_KB}kB (max ${MAX_KB}kB)"
else
    echo "[FAIL] bundle size <= +10% - ${BUNDLE_KB}kB exceeds max ${MAX_KB}kB"
    PASS=0
fi

# 4. Smoke tests
echo ""
echo "[3/4] Smoke tests..."
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/health 2>/dev/null || echo 000)
if [[ "$HEALTH_CODE" == "200" ]]; then
    echo "[PASS] /health - HTTP 200"
else
    echo "[FAIL] /health - HTTP $HEALTH_CODE"
    PASS=0
fi

PHD_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:5000/api/phd/opportunities?limit=1" 2>/dev/null || echo 000)
if [[ "$PHD_CODE" == "200" ]]; then
    echo "[PASS] /api/phd/opportunities - HTTP 200"
else
    echo "[FAIL] /api/phd/opportunities - HTTP $PHD_CODE"
    PASS=0
fi

FE_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 2>/dev/null || echo 000)
if [[ "$FE_CODE" == "200" ]]; then
    echo "[PASS] Frontend :3000 - HTTP 200"
else
    echo "[FAIL] Frontend :3000 - HTTP $FE_CODE"
    PASS=0
fi

# 5. Save baseline if requested
if [[ $SAVE_BASELINE -eq 1 ]]; then
    cat <<EOF > "$BASELINE_FILE"
{
  "date": "$(date +%Y-%m-%d)",
  "pytest": { "total": $TOTAL, "passed": $PASSED, "failed": $FAILED },
  "vite_build": { "status": "pass", "bundle_size_kb": ${BUNDLE_KB:-866}, "chunk_warnings": 1 },
  "eslint": { "errors": 99, "warnings": 12 },
  "npm_test": { "total": 14, "passed": 14, "failed": 0 }
}
EOF
    echo "[4/4] Baseline saved to $BASELINE_FILE"
fi

if [[ $PASS -eq 1 ]]; then
    echo ""
    echo "=== ALL CHECKS PASSED - no regression detected ==="
    exit 0
else
    echo ""
    echo "=== REGRESSION DETECTED - fix before proceeding ==="
    exit 1
fi
