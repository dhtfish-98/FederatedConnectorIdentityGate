#!/usr/bin/env bash
set -euo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_root="${FCIG_BUILD_ROOT:-${source_root}/Build}"
dex_commit='c7ced47db7f9dc92192969e6c396e393275278eb'
dex_source="${build_root}/上游/dex-${dex_commit}"
dex_binary="${build_root}/环境/dex-fixed"

mkdir -p "${build_root}/环境/go/gopath" "${build_root}/环境/go/modcache" \
  "${build_root}/环境/go/cache" "${build_root}/环境/go/tmp" \
  "${build_root}/验证"
export GOPATH="${build_root}/环境/go/gopath"
export GOMODCACHE="${build_root}/环境/go/modcache"
export GOCACHE="${build_root}/环境/go/cache"
export GOTMPDIR="${build_root}/环境/go/tmp"
export GOTOOLCHAIN=auto
export GOWORK=off

if [[ ! -d "${dex_source}/.git" ]]; then
  mkdir -p "${dex_source}"
  git -C "${dex_source}" init -q
  git -C "${dex_source}" remote add origin https://github.com/dexidp/dex.git
fi
if [[ "$(git -C "${dex_source}" rev-parse HEAD 2>/dev/null || true)" != "${dex_commit}" ]]; then
  git -C "${dex_source}" fetch --depth=1 origin "${dex_commit}"
  git -C "${dex_source}" checkout -q --detach FETCH_HEAD
fi
[[ "$(git -C "${dex_source}" rev-parse HEAD)" == "${dex_commit}" ]]

(cd "${dex_source}" && go build -trimpath -o "${dex_binary}" ./cmd/dex)
go version -m "${dex_binary}" | grep -F "vcs.revision=${dex_commit}" >/dev/null
go version -m "${dex_binary}" | grep -F 'vcs.modified=false' >/dev/null

export FCIG_DEX_BIN="${dex_binary}"
export FCIG_BUILD_DIR="${build_root}/验证/live-fixtures"
export FCIG_EVIDENCE_PATH="${build_root}/验证/live-evidence.json"
mkdir -p "${FCIG_BUILD_DIR}"
(cd "${source_root}" && go build ./gate)
(cd "${source_root}" && go vet ./gate)
(cd "${source_root}" && go test -count=1 -v ./gate)

# Compile the public package from a distinct Go module under Build. The
# replace points at this exact source tree; no package bytes are copied into
# the consumer, and all consumer files and caches remain in Build.
consumer="${build_root}/验证/consumer"
mkdir -p "${consumer}"
cat > "${consumer}/go.mod" <<'EOF'
module fcig-consumer

go 1.27.0
EOF
(cd "${consumer}" && go mod edit \
  -require=github.com/dhtfish-98/FederatedConnectorIdentityGate@v0.1.1 \
  "-replace=github.com/dhtfish-98/FederatedConnectorIdentityGate=${source_root}")
cat > "${consumer}/gate_test.go" <<'EOF'
package consumer

import (
  "errors"
  "testing"
  "time"

  "github.com/dhtfish-98/FederatedConnectorIdentityGate/gate"
)

func TestExternalImport(t *testing.T) {
  if gate.Version != "0.1.1" {
    t.Fatalf("installed package version %q", gate.Version)
  }
  if _, err := gate.OpenStore("", time.Minute); !errors.Is(err, gate.ErrDenied) {
    t.Fatalf("invalid external call was not rejected: %v", err)
  }
}
EOF
(cd "${consumer}" && go test -mod=mod -count=1 -v .)
