#!/usr/bin/env bash
# Run secrets detection locally
set -euo pipefail

echo "=== Gitleaks ==="
if command -v gitleaks &>/dev/null; then
  gitleaks detect --source . --report-path security/reports/gitleaks-report.json --exit-code 0
  echo "→ Report: security/reports/gitleaks-report.json"
else
  echo "gitleaks not installed. See: https://github.com/gitleaks/gitleaks#installing"
fi
