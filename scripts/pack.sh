#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

VERSION="${VERSION:-dev}"
GOOS="linux"
GOARCH="$(go env GOARCH)"

PACK_NAME="xdpass-${VERSION}-${GOOS}-${GOARCH}"
PACK_DIR="${REPO_ROOT}/build/${PACK_NAME}"
PACK_ARCHIVE="${REPO_ROOT}/build/${PACK_NAME}.tar.gz"

cd "${REPO_ROOT}"

make build VERSION="${VERSION}"

rm -rf "${PACK_DIR}" "${PACK_ARCHIVE}"
install -d -m 0755 \
  "${PACK_DIR}/bin" \
  "${PACK_DIR}/deploy/config/agent" \
  "${PACK_DIR}/deploy/systemd" \
  "${PACK_DIR}/scripts"

install -m 0755 build/xdpass-agent "${PACK_DIR}/bin/xdpass-agent"
install -m 0644 deploy/config/agent/config.yaml "${PACK_DIR}/deploy/config/agent/config.yaml"
install -m 0644 deploy/systemd/xdpass-agent.service "${PACK_DIR}/deploy/systemd/xdpass-agent.service"
install -m 0755 scripts/install-systemd.sh "${PACK_DIR}/scripts/install-systemd.sh"

tar -C build -czf "${PACK_ARCHIVE}" "${PACK_NAME}"

echo "packed build/${PACK_NAME}.tar.gz"
