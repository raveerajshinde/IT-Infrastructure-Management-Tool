#!/usr/bin/env bash
# InfraPilot backup: SQL Server full backup (verified) + configuration/secrets archive.
#   infrapilot-backup [--keep-days N] [--passphrase-file FILE] [--quiet]
#
# The configuration archive contains the vault key. Without it, stored credentials cannot be
# decrypted after a restore. Protect it: use --passphrase-file to encrypt it (AES-256, PBKDF2)
# and copy backups off the server.
set -Eeuo pipefail
SRC_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOG_FILE="/var/log/infrapilot-backup.log"
# shellcheck source=lib/common.sh
source "$SRC_DIR/lib/common.sh"
KEEP_DAYS=14; PASSFILE=""; QUIET=0; LABEL="manual"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-days) KEEP_DAYS="$2"; shift ;;
    --passphrase-file) PASSFILE="$2"; shift ;;
    --label) LABEL="$2"; shift ;;
    --prefix) IP_DIR="$2"; IP_COMPOSE_FILE="$IP_DIR/docker-compose.yml"; shift ;;
    --quiet) QUIET=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) die "Unknown option $1" ;;
  esac; shift
done
require_root
trap on_error ERR
[[ "$LABEL" =~ ^[a-z0-9-]+$ ]] || die "Invalid label"
[[ -f "$IP_COMPOSE_FILE" ]] || die "InfraPilot is not installed in $IP_DIR"
[[ $QUIET == 1 ]] || echo "${C_BOLD}InfraPilot backup${C_RESET}"

step "Database backup"
BAK=$(backup_db "$LABEL") || die "Database backup failed (see $LOG_FILE)"
ok "Database: $BAK ($(du -h "$BAK" | cut -f1)), verified with RESTORE VERIFYONLY"

step "Configuration and secrets"
TS=$(date +%Y%m%d-%H%M%S)
CFG="$IP_DIR/backups/config/infrapilot_config_${LABEL}_${TS}.tar.gz"
umask 077
tar -C "$IP_DIR" -czf "$CFG" .env docker-compose.yml secrets certs
if [[ -n "$PASSFILE" ]]; then
  [[ -r "$PASSFILE" ]] || die "Cannot read passphrase file"
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -in "$CFG" -out "$CFG.enc" -pass "file:$PASSFILE"
  shred -u "$CFG" 2>/dev/null || rm -f "$CFG"
  CFG="$CFG.enc"
  ok "Configuration: $CFG (encrypted)"
else
  ok "Configuration: $CFG"
  [[ $QUIET == 1 ]] || warn "Not encrypted — it contains the vault key. Use --passphrase-file and store it off-server."
fi
sha256sum "$BAK" "$CFG" >"$IP_DIR/backups/SHA256SUMS-${TS}"

step "Retention (${KEEP_DAYS} days)"
find "$IP_DIR/backups/mssql" -name '*.bak' -mtime "+${KEEP_DAYS}" -print -delete >>"$LOG_FILE" 2>&1 || true
find "$IP_DIR/backups/config" -name 'infrapilot_config_*' -mtime "+${KEEP_DAYS}" -print -delete >>"$LOG_FILE" 2>&1 || true
find "$IP_DIR/backups" -maxdepth 1 -name 'SHA256SUMS-*' -mtime "+${KEEP_DAYS}" -delete 2>/dev/null || true
ok "Old backups pruned"
tools python -m app.cli verify-audit >>"$LOG_FILE" 2>&1 && ok "Audit chain verified" || warn "Audit chain verification FAILED — investigate (see $LOG_FILE)"

step "Network share"
# Runs as root with read-only access to the backup folder so it can read the root-only archives;
# configured (and switched on/off) in Settings -> Backup storage.
if OFFSITE=$(compose --profile tools run --rm -T --user 0 --cap-add DAC_READ_SEARCH -v "$IP_DIR/backups:/backups:ro" \
      tools python -m app.cli offsite-upload --dir /backups 2>>"$LOG_FILE"); then
  while IFS= read -r line; do [[ "$line" == WARNING:* ]] && warn "${line#WARNING: }" || ok "$line"; done <<<"$OFFSITE"
else
  warn "Upload to the network share failed: ${OFFSITE:-see $LOG_FILE} (local backup is complete; status shown in Settings -> Backup storage)"
fi
[[ $QUIET == 1 ]] || echo -e "\nBackup complete. Copy ${IP_DIR}/backups to off-server storage."
