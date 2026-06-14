#!/usr/bin/env bash
# Build the RedAmon graphql-cop sidecar image ahead of first use.
# Run this after stack changes that affect recon/graphql_scan/Dockerfile.
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -t redamon-graphql-cop:1.16 -f recon/graphql_scan/Dockerfile recon/graphql_scan
