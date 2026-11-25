#!/usr/bin/env bash
# InfraPilot uninstall.
#   infrapilot-uninstall              stop and remove containers; KEEP data, secrets and backups
#   infrapilot-uninstall --purge      also delete the database volume, secrets and $IP_DIR (irreversible)
# Docker itself is not removed.
set -Eeuo pipefail
SRC_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOG_FILE="/var/log/infrapilot-uninstall-$(date +%Y%m%d-%H%M%S).log"
# shellcheck source=lib/common.sh
source "$SRC_DIR/lib/common.sh"
PURGE=0; YES=0; NOBACKUP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1 ;;
    --yes) YES=1 ;;
    --no-backup) NOBACKUP=1 ;;
    --prefix) IP_DIR="$2"; IP_COMPOSE_FILE="$IP_DIR/docker-compose.yml"; shift ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) die "Unknown option $1" ;;
  esac; shift
done
require_root
trap on_error ERR
[[ -f "$IP_COMPOSE_FILE" ]] || die "InfraPilot is not installed in $IP_DIR"

echo "${C_BOLD}Uninstall InfraPilot${C_RESET}"
if [[ $PURGE == 1 ]]; then
  echo "  ${C_RED}PURGE: the database, all credentials, secrets, certificates and audit history will be destroyed.${C_RESET}"
  [[ $NOBACKUP == 1 ]] || echo "  A final backup is written to /root/infrapilot-final-backup-<date>/ first."
  if [[ $YES == 0 ]]; then read -r -p "  Type the word PURGE to confirm: " a </dev/tty; [[ "$a" == PURGE ]] || die "Aborted"; fi
else
  echo "  Containers are removed; data (database volume, ${IP_DIR}) is kept for re-installation."
  [[ $YES == 1 ]] || ask_yes_no "Continue?" N || die "Aborted"
fi

if [[ $PURGE == 1 && $NOBACKUP == 0 ]]; then
  step "Final backup"
  bash "$SRC_DIR/backup.sh" --prefix "$IP_DIR" --label final --quiet --keep-days 3650 >>"$LOG_FILE" 2>&1 || die "Final backup failed; use --no-backup to skip"
  DEST="/root/infrapilot-final-backup-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$DEST"; chmod 700 "$DEST"
  cp -a "$IP_DIR/backups/." "$DEST/"; ok "Saved to $DEST"
fi

step "Stopping and removing containers"
if [[ $PURGE == 1 ]]; then run compose --profile tools down -v --remove-orphans; else run compose --profile tools down --remove-orphans; fi
ok "Containers removed"

step "Removing maintenance commands"
rm -f /usr/local/sbin/infrapilot-{update,backup,restore,health-check,uninstall} /etc/cron.d/infrapilot-backup
ok "Removed"

if [[ $PURGE == 1 ]]; then
  step "Deleting files and images"
  for img in "$(env_get IP_IMAGE_API)" "$(env_get IP_IMAGE_PROXY)"; do docker rmi "$img" >>"$LOG_FILE" 2>&1 || true; done
  [[ -d "$IP_DIR/secrets" ]] && find "$IP_DIR/secrets" -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf "$IP_DIR"
  ok "Deleted $IP_DIR"
  info "UFW rules for 80/443 were left in place; remove them with 'ufw delete allow 80/tcp' etc. if no longer needed."
fi
echo -e "\n${C_GREEN}Uninstall complete.${C_RESET}"
