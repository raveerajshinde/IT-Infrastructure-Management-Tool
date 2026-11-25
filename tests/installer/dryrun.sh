#!/bin/bash
# Installer logic test: runs install.sh, update, backup, restore, health-check and uninstall end to end
# on the current Ubuntu 22.04/24.04 host with docker/apt/systemctl/ufw/ss/curl replaced by stubs
# (tests/installer/stub-bin). Exercises the shell logic only - no containers are created.
# Run as root in a disposable VM/container:  sudo tests/installer/dryrun.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$(cd "$HERE/../.." && pwd)"; BIN="$HERE/stub-bin"
fail=0; pass() { echo "PASS  $1"; }; bad() { echo "FAIL  $1"; fail=1; }
run() { # run <name> <expect-rc> [ENV=VAL...]
  local name=$1 exp=$2; shift 2
  export STUB_STATE=/tmp/ipdry/$name/state; local P=/tmp/ipdry/$name/opt
  [[ "${KEEP:-0}" == 1 ]] || rm -rf /tmp/ipdry/$name; mkdir -p "$STUB_STATE" "$P"
  printf 'IP_HOSTNAME=test.local\nIP_HTTPS_PORT=%s\nIP_MSSQL_EDITION=Express\nIP_ADMIN_USER=admin\nIP_CONFIGURE_FIREWALL=Y\n' "${HTTPS_PORT:-443}" >/tmp/ipdry/$name/answers.env
  OUT=$(env "$@" PATH="$BIN:$PATH" timeout 300 bash "$SRC/install.sh" --non-interactive --answers /tmp/ipdry/$name/answers.env --prefix "$P" --yes 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; exit "${PIPESTATUS[0]}")
  local rc=$?; [[ $rc == "$exp" ]] && pass "$name (rc=$rc)" || { bad "$name (rc=$rc, expected $exp)"; echo "$OUT" | tail -15; }
}
backup_sys() { for f in /etc/docker/daemon.json /etc/apt/sources.list.d/docker.list /etc/cron.d/infrapilot-backup; do [[ -e $f ]] && echo "$f"; done; }
PRE=$(backup_sys)
run fresh 0;                         echo "$OUT" | grep -q "Password:" && pass "fresh prints admin password" || bad "no password"
run interrupted 1 STUB_EXIT=proxy
KEEP=1 run interrupted 0;            echo "$OUT" | grep -q "Resuming an interrupted" && pass "resume detected" || bad "resume not detected"
                                     [[ -f /tmp/ipdry/interrupted/opt/.install-complete ]] && pass "completion marker" || bad "no marker"
KEEP=1 run interrupted 0;            echo "$OUT" | grep -q "Found InfraPilot" && pass "completed install -> upgrade path" || bad "upgrade path"
# package copied via Windows/WinSCP: every script has lost its executable bit
NOEXEC=/tmp/ipdry/noexec-src; rm -rf "$NOEXEC"; mkdir -p "$NOEXEC"
tar -C "$SRC" --exclude=node_modules --exclude=dist --exclude=.git -cf - . | tar -C "$NOEXEC" -xf -
find "$NOEXEC" -name '*.sh' -exec chmod 644 {} +
ORIG_SRC=$SRC; SRC=$NOEXEC
run noexec 0
KEEP=1 run noexec 0;                 echo "$OUT" | grep -q "Update to .* complete" && pass "upgrade works without executable bits" || { bad "noexec upgrade"; echo "$OUT" | tail -8; }
SRC=$ORIG_SRC
mkdir -p /tmp/ipdry/stale/state && touch /tmp/ipdry/stale/state/volume_mssql
KEEP=1 run stale 1;                  echo "$OUT" | grep -q "Stale database volume" && pass "stale volume guard" || bad "stale guard"
run port80 0 STUB_BUSY=80 STUB_UFW_FAIL=1 STUB_VIRT=lxc
grep -q IP_HTTP_PORT=8080 /tmp/ipdry/port80/opt/.env && pass "busy port 80 -> 8080" || bad "port 80 fallback"
echo "$OUT" | grep -q "LXC" && pass "LXC warning" || bad "LXC warning"
run port443 1 STUB_BUSY=443
HTTPS_PORT=8443 run port8443 0 STUB_BUSY="443 80"
export STUB_STATE=/tmp/ipdry/fresh/state P=/tmp/ipdry/fresh/opt
PATH="$BIN:$PATH" bash "$SRC/backup.sh" --prefix "$P" >/dev/null 2>&1 && pass backup || bad backup
BAK=$(ls -t "$P"/backups/mssql/*.bak | head -1); CFG=$(ls -t "$P"/backups/config/*.tar.gz | head -1)
PATH="$BIN:$PATH" timeout 300 bash "$SRC/restore.sh" --prefix "$P" --db "$BAK" --config "$CFG" --yes >/dev/null 2>&1 && pass restore || bad restore
PATH="$BIN:$PATH" bash "$SRC/health-check.sh" --prefix "$P" --json | grep -q '"healthy":true' && pass health-check || bad health-check
PATH="$BIN:$PATH" timeout 200 bash "$SRC/uninstall.sh" --prefix "$P" --yes >/dev/null 2>&1 && pass uninstall || bad uninstall
# remove host files the dry run created (unless they existed before)
for f in /etc/docker/daemon.json /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc /etc/cron.d/infrapilot-backup; do grep -qx "$f" <<<"$PRE" || rm -f "$f"; done
rm -f /usr/local/sbin/infrapilot-*
[[ $fail == 0 ]] && echo "ALL INSTALLER DRY-RUN TESTS PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
