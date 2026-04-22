#!/usr/bin/env bash
# Bootstrap the very first super_admin user in OpenIAM.
#
# Reads the same config.yaml / IAM_* env vars as iam-server, then
# drives the public service interfaces directly to create:
#
#   tenant -> application -> user -> super_admin role assignment
#
# Idempotent: rerunning with the same names reuses existing rows.
#
# Usage:
#   ./scripts/bootstrap.sh \
#       --tenant=acme \
#       --app=portal \
#       --email=admin@example.com \
#       --password='S3cretP@ss!'
#
# Defaults: --tenant=default --app=admin --role=super_admin
# Required: --email --password (must be >= 8 chars)
#
# The iam-server process does NOT need to be stopped.
set -euo pipefail

cd "$(dirname "$0")/.."

exec go run ./cmd/iam-bootstrap "$@"
