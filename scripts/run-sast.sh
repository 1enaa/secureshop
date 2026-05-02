#!/usr/bin/env bash
# Run SAST tools locally before pushing
set -euo pipefail

echo "=== Bandit (Python) ==="
pip install -q bandit
bandit -r services/user-service services/order-service \
          services/inventory-service services/notification-service \
  -c security/sast/bandit.toml \
  -f json -o security/reports/bandit-report.json --exit-zero
echo "→ Report: security/reports/bandit-report.json"

echo ""
echo "=== Semgrep (Node.js) ==="
if command -v semgrep &>/dev/null; then
  semgrep --config p/javascript --config p/nodejs \
    services/product-service services/payment-service services/delivery-service \
    --json -o security/reports/semgrep-report.json --exit-code 0
  echo "→ Report: security/reports/semgrep-report.json"
else
  echo "semgrep not installed. Install: pip install semgrep"
fi
