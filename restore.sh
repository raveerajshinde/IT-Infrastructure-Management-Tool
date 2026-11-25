#!/usr/bin/env bash
# InfraPilot restore.
#   infrapilot-restore --db FILE.bak [--config FILE.tar.gz[.enc] [--passphrase-file F]] [--yes]
#
# Restores the database (WITH REPLACE) and optionally configuration/secrets. A safety backup of
# the current database is taken first. After restore, migrations are applied (for restoring an
# older backup into a newer version) and the audit chain is verified.
set -Eeuo pipefail
SRC_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOG_FILE="/var/log/infrapilot-restore-$(date +%Y%m%d-%H%M%S).log"
# shellcheck source=lib/common.sh
source "$SRC_DIR/lib/common.sh"
DB_FILE=""; CFG_FILE=""; PASSFILE=""; YES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --db) DB_FILE="$2"; shift ;;
    --config) CFG_FILE="$2"; shift ;;
    --passphrase-file) PASSFILE="$2"; shift ;;
    --prefix) IP_DIR="$2"; IP_COMPOSE_FILE="$IP_DIR/docker-compose.yml"; shift ;;
    --yes) YES=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) die "Unknown option $1" ;;
  esac; shift
done
require_root
touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
trap on_error ERR
[[ -n "$DB_FILE" || -n "$CFG_FILE" ]] || die "Specify --db and/or --config"
[[ -z "$DB_FILE" || -f "$DB_FILE" ]] || die "Database backup not found: $DB_FILE"
[[ -z "$CFG_FILE" || -f "$CFG_FILE" ]] || die "Config backup not found: $CFG_FILE"
STEP_TOTAL=6

echo "${C_BOLD}InfraPilot restore${C_RESET}"
[[ -n "$DB_FILE" ]] && echo "  Database: $DB_FILE"
[[ -n "$CFG_FILE" ]] && echo "  Config:   $CFG_FILE"
echo "  ${C_YELLOW}The current database${CFG_FILE:+ and configuration} will be REPLACED. Services will be stopped briefly.${C_RESET}"
if [[ $YES == 0 ]]; then
  read -r -p "  Type RESTORE to continue: " a </dev/tty; [[ "$a" == "RESTORE" ]] || die "Aborted"
fi

step "Safety backup of the current state"
if compose ps -q mssql | grep -q .; then
  SAFETY=$(backup_db "pre-restore") && ok "Saved current database to $SAFETY" || warn "Could not back up the current database (continuing)"
fi
tar -C "$IP_DIR" -czf "$IP_DIR/backups/config/pre-restore-$(date +%Y%m%d-%H%M%S).tar.gz" .env docker-compose.yml secrets certs 2>/dev/null || true

step "Stopping application services"
run compose stop proxy api worker
ok "Stopped (SQL Server stays up)"

if [[ -n "$CFG_FILE" ]]; then
  step "Restoring configuration and secrets"
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  if [[ "$CFG_FILE" == *.enc ]]; then
    [[ -r "$PASSFILE" ]] || die "Encrypted config requires --passphrase-file"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$CFG_FILE" -out "$TMP/cfg.tgz" -pass "file:$PASSFILE" || die "Decryption failed (wrong passphrase?)"
  else cp "$CFG_FILE" "$TMP/cfg.tgz"; fi
  tar -tzf "$TMP/cfg.tgz" | grep -q '^secrets/vault_key$' || die "Archive does not look like an InfraPilot configuration backup"
  tar -C "$IP_DIR" -xzf "$TMP/cfg.tgz"
  chown root:"$IP_APP_UID" "$IP_DIR/.env" "$IP_DIR/secrets" "$IP_DIR"/secrets/{vault_key,db_password,mssql_sa_password}
  chmod 600 "$IP_DIR/secrets/mssql.env"
  ok "Configuration restored"
  run compose up -d mssql
else
  step "Configuration"; info "Keeping current configuration"
fi
wait_healthy mssql 300

if [[ -n "$DB_FILE" ]]; then
  step "Restoring database"
  NAME="restore_$(date +%s).bak"
  cp "$DB_FILE" "$IP_DIR/backups/mssql/$NAME"; chown 10001:0 "$IP_DIR/backups/mssql/$NAME"
  DB=$(env_get IP_DB_NAME); DB="${DB:-infrapilot}"
  run compose exec -T mssql bash -c "/opt/mssql-tools18/bin/sqlcmd -C -b -S localhost -U sa -P \"\$MSSQL_SA_PASSWORD\" -Q \"
    RESTORE VERIFYONLY FROM DISK = N'/var/opt/mssql/backup/${NAME}' WITH CHECKSUM;
    IF DB_ID(N'${DB}') IS NOT NULL ALTER DATABASE [${DB}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    RESTORE DATABASE [${DB}] FROM DISK = N'/var/opt/mssql/backup/${NAME}' WITH REPLACE, CHECKSUM, RECOVERY;
    ALTER DATABASE [${DB}] SET MULTI_USER;\""
  rm -f "$IP_DIR/backups/mssql/$NAME"
  ok "Database restored"
  # Re-map the application login to the restored database user and re-sync its password
  run tools python -m app.cli bootstrap-db --sa-password-file /run/secrets/mssql_sa_password
else
  step "Database"; info "Database not restored"
fi

step "Applying migrations and starting services"
run tools python -m app.cli migrate --sa-password-file /run/secrets/mssql_sa_password
apply_compose_overrides
run compose up -d
wait_healthy api 300
wait_healthy proxy 120
ok "Services running"

step "Verifying"
if tools python -m app.cli verify-audit >>"$LOG_FILE" 2>&1; then ok "Audit chain intact"; else warn "Audit chain verification failed — the backup may have been modified"; fi
bash "$SRC_DIR/health-check.sh" --prefix "$IP_DIR" || warn "Health check reported problems"
echo -e "\n${C_GREEN}Restore complete.${C_RESET} Log: $LOG_FILE"
