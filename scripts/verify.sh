#!/usr/bin/env bash
# Build and test with the release build tags.
set -euo pipefail
cd "$(dirname "$0")/.."

export GOPRIVATE=git.wrlog.cn
# Fetch wkernel over ssh on port 2222 without touching the global git config.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0='url.ssh://git@git.wrlog.cn:2222/.insteadOf'
export GIT_CONFIG_VALUE_0='https://git.wrlog.cn/'

TAGS=$(cat release/build_tags)
go build -tags "$TAGS" ./...
# api/keeper needs a running panel and common/mylego a real ACME server.
go test -tags "$TAGS" -count=1 $(go list ./... | grep -v -E '/api/keeper$|/common/mylego$')
