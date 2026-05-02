#!/usr/bin/env bash
# Build and scan all container images
set -euo pipefail

SERVICES=(user-service product-service order-service payment-service notification-service inventory-service delivery-service)

for svc in "${SERVICES[@]}"; do
  echo "=== Building secureshop/${svc}:scan ==="
  docker build -t "secureshop/${svc}:scan" "./services/${svc}"

  echo "--- Trivy scanning secureshop/${svc}:scan ---"
  trivy image \
    --severity HIGH,CRITICAL \
    --format json \
    --output "security/reports/trivy-image-${svc}.json" \
    "secureshop/${svc}:scan"
done
echo "✅ All image scans complete. Reports in security/reports/"
