#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh"
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go is required to build PTRmaker."
  exit 1
fi

echo "Building PTRmaker..."
go build -trimpath -ldflags="-s -w" -o /usr/local/bin/ptrmaker .

if ! id ptrmaker >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/ptrmaker --shell /usr/sbin/nologin ptrmaker
fi

install -d -o ptrmaker -g ptrmaker -m 0750 /var/lib/ptrmaker
install -d -m 0755 /etc/ptrmaker
install -m 0644 packaging/ptrmaker.env /etc/ptrmaker/ptrmaker.env
install -m 0644 packaging/ptrmaker.service /etc/systemd/system/ptrmaker.service

systemctl daemon-reload
systemctl enable --now ptrmaker

echo
echo "PTRmaker installed."
echo "Edit /etc/ptrmaker/ptrmaker.env to change runtime options."
echo "Status: systemctl status ptrmaker"
echo "Logs:   journalctl -u ptrmaker -f"
echo "HTTP:   http://127.0.0.1:8080/"
