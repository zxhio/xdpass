#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="xdpass-agent"
INSTALL_BIN="/usr/local/bin/xdpass-agent"
CONFIG_DIR="/etc/xdpass/agent"
CONFIG_DEST="${CONFIG_DIR}/config.yaml"
LOG_DIR="/var/log/xdpass"
UNIT_DEST="/etc/systemd/system/xdpass-agent.service"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

BINARY_SRC="${REPO_ROOT}/bin/xdpass-agent"
CONFIG_SRC="${REPO_ROOT}/deploy/config/agent/config.yaml"
UNIT_SRC="${REPO_ROOT}/deploy/systemd/xdpass-agent.service"

FORCE=0
ENABLE_SERVICE=0
START_SERVICE=0

usage() {
  cat <<'USAGE'
Usage: scripts/install-systemd.sh [options]

Install xdpass for systemd deployment.

Options:
  --force   Overwrite existing config.
  --enable  Enable the systemd service.
  --start   Start the systemd service after installation.
  -h, --help  Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1 ;;
    --enable) ENABLE_SERVICE=1 ;;
    --start) START_SERVICE=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) echo "error: unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

[[ -f "${BINARY_SRC}" ]] || { echo "error: binary not found: ${BINARY_SRC}" >&2; exit 1; }
[[ -f "${CONFIG_SRC}" ]] || { echo "error: config source not found: ${CONFIG_SRC}" >&2; exit 1; }
[[ -f "${UNIT_SRC}" ]] || { echo "error: systemd unit not found: ${UNIT_SRC}" >&2; exit 1; }

install -d -m 0755 "${CONFIG_DIR}" "${LOG_DIR}"
install -m 0755 "${BINARY_SRC}" "${INSTALL_BIN}"
if [[ ! -e "${CONFIG_DEST}" || ${FORCE} -eq 1 ]]; then
  install -m 0644 "${CONFIG_SRC}" "${CONFIG_DEST}"
fi
install -m 0644 "${UNIT_SRC}" "${UNIT_DEST}"
systemctl daemon-reload

if [[ ${ENABLE_SERVICE} -eq 1 ]]; then
  systemctl enable "${SERVICE_NAME}.service"
fi

if [[ ${START_SERVICE} -eq 1 ]]; then
  if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    systemctl restart "${SERVICE_NAME}.service"
  else
    systemctl start "${SERVICE_NAME}.service"
  fi
fi
