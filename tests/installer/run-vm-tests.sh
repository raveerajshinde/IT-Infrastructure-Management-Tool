#!/usr/bin/env bash
# End-to-end installer test on CLEAN Ubuntu 22.04 and 24.04 VMs (requires Canonical Multipass on the test host).
#   ./tests/installer/run-vm-tests.sh dist/infrapilot-1.0.0.tar.gz [22.04 24.04]
# For each release: fresh install (unattended) → health check → API login → register a simulated-free
# device record → backup → corrupt-and-restore → re-run installer (idempotency/upgrade path) → uninstall --purge.
# Never touches real infrastructure.
set -Eeuo pipefail
PKG="${1:?package tarball}"; shift || true
RELEASES=("${@:-22.04 24.04}"); [[ $# -eq 0 ]] && RELEASES=(22.04 24.04)
NAME=$(basename "$PKG" .tar.gz | sed 's/-offline$//')
PASS='Inst@llTest-2026!x'
for rel in "${RELEASES[@]}"; do
  vm="ip-test-${rel//./}"
  echo "==================== Ubuntu $rel ($vm) ===================="
  multipass delete --purge "$vm" 2>/dev/null || true
  multipass launch "$rel" --name "$vm" --cpus 2 --memory 6G --disk 40G
  multipass transfer "$PKG" "$vm:/home/ubuntu/pkg.tar.gz"
  multipass exec "$vm" -- bash -ec "
    tar -xzf pkg.tar.gz
    cat > answers.env <<A
IP_HOSTNAME=$vm.local
IP_ADMIN_USER=admin
IP_ADMIN_PASSWORD=$PASS
IP_MSSQL_EDITION=Developer
IP_CONFIGURE_FIREWALL=Y
A
    cd $NAME
    echo '--- install'; sudo ./install.sh --non-interactive --answers ../answers.env --yes
    echo '--- health';  sudo infrapilot-health-check
    echo '--- login + API smoke'
    H='X-Requested-With: InfraPilot'
    curl -skf -c jar -H \"\$H\" -H 'Content-Type: application/json' https://127.0.0.1/api/auth/login -d '{\"username\":\"admin\",\"password\":\"$PASS\"}' >/dev/null
    curl -skf -b jar https://127.0.0.1/api/auth/me >/dev/null
    curl -skf -b jar -H \"\$H\" -H 'Content-Type: application/json' https://127.0.0.1/api/devices \
      -d '{\"hostname\":\"persist-check\",\"ip_address\":\"192.0.2.10\",\"device_type\":\"linux_server\",\"driver\":\"linux\",\"environment\":\"test\"}' >/dev/null
    echo '--- backup';  sudo infrapilot-backup
    BAK=\$(ls -1t /opt/infrapilot/backups/mssql/*.bak | head -1)
    echo '--- simulate data loss and restore'
    curl -skf -b jar -X DELETE -H \"\$H\" https://127.0.0.1/api/devices/1 >/dev/null
    sudo infrapilot-restore --db \"\$BAK\" --yes
    curl -skf -c jar -H \"\$H\" -H 'Content-Type: application/json' https://127.0.0.1/api/auth/login -d '{\"username\":\"admin\",\"password\":\"$PASS\"}' >/dev/null
    curl -skf -b jar 'https://127.0.0.1/api/devices?q=persist-check' | grep -q persist-check && echo 'restore verified: device present'
    echo '--- re-run installer (idempotent upgrade path)'; sudo ./install.sh --non-interactive --answers ../answers.env --yes
    sudo infrapilot-health-check --verify-audit
    echo '--- reboot persistence'; sudo reboot || true
  " || { echo "FAILED on $rel"; exit 1; }
  sleep 60
  multipass exec "$vm" -- bash -ec "sleep 60; sudo infrapilot-health-check && sudo infrapilot-uninstall --purge --yes --no-backup && ! test -d /opt/infrapilot"
  multipass delete --purge "$vm"
  echo "PASSED on Ubuntu $rel"
done
