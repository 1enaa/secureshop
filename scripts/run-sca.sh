#!/usr/bin/env bash
# Run SCA (dependency vulnerability scan) locally
set -euo pipefail

echo "=== Trivy filesystem scan ==="
if command -v trivy &>/dev/null; then
  trivy fs . \
    --ignorefile security/sca/.trivyignore \
    --severity HIGH,CRITICAL \
    --format json \
    --output security/reports/trivy-sca-report.json
  echo "→ Report: security/reports/trivy-sca-report.json"
else
  echo "trivy not installed. See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
fi
