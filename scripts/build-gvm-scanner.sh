#!/usr/bin/env bash
# Build the RedAmon GVM vulnerability scanner image ahead of first use.
# Run this after stack changes that affect gvm_scan/Dockerfile.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose --profile tools build vuln-scanner
