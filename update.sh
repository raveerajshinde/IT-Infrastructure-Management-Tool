#!/usr/bin/env bash
# InfraPilot safe upgrade / repair.
#   sudo ./update.sh            (run from the NEW release package directory)
#   infrapilot-update           (re-applies the installed release: repair / restart)
#
# Steps: backup → load/build new images → replace release files (keeping .env, secrets, certs)
# → migrate → restart → health check. On failure, the previous images are re-tagged and the
# pre-upgrade backup location is printed for a restore.
set -Eeuo pipefail
SRC_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOG_FILE="/var/log/infrapilot-update-$(date +%Y%m%d-%H%M%S).log"
# shellcheck source=lib/common.sh
source "$SRC_DIR/lib/common.sh"
# Permissions are often lost when the package is copied from Windows/WinSCP/browser downloads
chmod 755 "$SRC_DIR"/*.sh 2>/dev/null || true
YES=0; FROM_INSTALLER=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) YES=1 ;;
    --from-installer) FROM_INSTALLER=1 ;;
    --prefix) IP_DIR="$2"; IP_COMPOSE_FILE="$IP_DIR/docker-compose.yml"; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) die "Unknown option $1" ;;
  esac; shift
done
require_root
touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
trap on_error ERR
STEP_TOTAL=7
[[ -f "$IP_DIR/.env" ]] || die "No installation found in $IP_DIR — run install.sh"
NEW_VER=$(cat "$SRC_DIR/VERSION"); OLD_VER=$(env_get IP_VERSION)
OFFLINE=0; [[ -d "$SRC_DIR/bundle/images" ]] && OFFLINE=1
echo "${C_BOLD}InfraPilot update: ${OLD_VER:-unknown} → ${NEW_VER}${C_RESET}   (log: $LOG_FILE)"
if version_ge "${OLD_VER:-0}" "$NEW_VER" && [[ "$OLD_VER" != "$NEW_VER" ]]; then
  die "Installed version $OLD_VER is newer than $NEW_VER — downgrades are not supported (restore a backup instead)"
fi
[[ $YES == 1 || $FROM_INSTALLER == 1 ]] || ask_yes_no "Continue? A full backup is taken first" Y || die "Aborted"

step "Backing up database and configuration"
if compose ps -q mssql | grep -q .; then
  bash "$SRC_DIR/backup.sh" --prefix "$IP_DIR" --label "pre-upgrade" --quiet --keep-days 3650 >>"$LOG_FILE" 2>&1 \
    || bash "$IP_DIR/release/backup.sh" --prefix "$IP_DIR" --label "pre-upgrade" --quiet --keep-days 3650 >>"$LOG_FILE" 2>&1 \
    || die "Pre-upgrade backup failed; nothing was changed"
  PRE=$(ls -1t "$IP_DIR"/backups/mssql/infrapilot_pre-upgrade_*.bak | head -1)
  ok "Backup: $PRE"
else
  warn "SQL Server is not running — starting it to take a backup"
  run compose up -d mssql; wait_healthy mssql 300
  PRE=$(bash "$SRC_DIR/backup.sh" --prefix "$IP_DIR" --label pre-upgrade --quiet >>"$LOG_FILE" 2>&1 && ls -1t "$IP_DIR"/backups/mssql/*.bak | head -1)
fi

step "Preparing new images"
OLD_API=$(env_get IP_IMAGE_API); OLD_PROXY=$(env_get IP_IMAGE_PROXY)
NEW_API="infrapilot/api:${NEW_VER}"; NEW_PROXY="infrapilot/proxy:${NEW_VER}"
if [[ $OFFLINE == 1 ]]; then
  for tar in "$SRC_DIR"/bundle/images/*.tar*; do run docker load -i "$tar"; done
elif [[ -d "$SRC_DIR/backend" ]]; then
  run docker build -f "$SRC_DIR/backend/Dockerfile" -t "$NEW_API" "$SRC_DIR"
  run docker build -f "$SRC_DIR/frontend/Dockerfile" -t "$NEW_PROXY" "$SRC_DIR"
  run docker pull "$(env_get IP_IMAGE_MSSQL)" || warn "Could not refresh the SQL Server image (using local copy)"
fi
docker image inspect "$NEW_API" "$NEW_PROXY" >/dev/null 2>&1 || die "New images not available"
ok "Images ready"

step "Updating release files"
if [[ "$SRC_DIR" != "$IP_DIR/release" ]]; then
  rm -rf "$IP_DIR/release.prev"; [[ -d "$IP_DIR/release" ]] && mv "$IP_DIR/release" "$IP_DIR/release.prev"
  mkdir -p "$IP_DIR/release"; cp -a "$SRC_DIR/." "$IP_DIR/release/"; rm -rf "$IP_DIR/release/bundle/images"
fi
cp "$IP_DIR/docker-compose.yml" "$IP_DIR/docker-compose.yml.prev"
cp "$SRC_DIR/deploy/docker-compose.yml" "$IP_DIR/docker-compose.yml"
apply_compose_overrides
ensure_export_dir
# Add any new settings introduced by this release without touching existing values
while IFS='=' read -r k v; do
  [[ -z "$k" || "$k" == \#* ]] && continue
  grep -qE "^${k}=" "$IP_DIR/.env" || { echo "${k}=${v}" >>"$IP_DIR/.env"; info "Added new setting ${k}"; }
done <"$SRC_DIR/deploy/env.template"
env_set IP_IMAGE_API "$NEW_API"; env_set IP_IMAGE_PROXY "$NEW_PROXY"
ok "Configuration preserved (.env, secrets, certificates untouched)"

rollback() {
  err "Upgrade failed — rolling back to ${OLD_VER}"
  env_set IP_IMAGE_API "$OLD_API"; env_set IP_IMAGE_PROXY "$OLD_PROXY"; env_set IP_VERSION "$OLD_VER"
  [[ -f "$IP_DIR/docker-compose.yml.prev" ]] && cp "$IP_DIR/docker-compose.yml.prev" "$IP_DIR/docker-compose.yml"
  [[ -d "$IP_DIR/release.prev" ]] && { rm -rf "$IP_DIR/release"; mv "$IP_DIR/release.prev" "$IP_DIR/release"; }
  compose up -d >>"$LOG_FILE" 2>&1 || true
  err "If the database schema was already migrated, restore the pre-upgrade backup:"
  err "  infrapilot-restore --db ${PRE:-<backups/mssql/infrapilot_pre-upgrade_*.bak>}"
  exit 1
}
trap rollback ERR

step "Applying database migrations"
run compose up -d mssql; wait_healthy mssql 300
run tools python -m app.cli bootstrap-db --sa-password-file /run/secrets/mssql_sa_password
run tools python -m app.cli migrate --sa-password-file /run/secrets/mssql_sa_password
ok "Schema up to date"

step "Restarting services"
run compose up -d --remove-orphans
# The release tag can be unchanged (re-applying a fixed package of the same version), so always
# recreate the application containers from the freshly built images.
run compose up -d --no-deps --force-recreate api worker proxy
wait_healthy api 300
wait_healthy proxy 120
wait_healthy worker 300 || warn "Worker not yet healthy"
env_set IP_VERSION "$NEW_VER"
trap on_error ERR
ok "Running ${NEW_VER}"

step "Maintenance commands"
for s in update backup restore uninstall health-check; do chmod 750 "$IP_DIR/release/$s.sh"; ln -sf "$IP_DIR/release/$s.sh" "/usr/local/sbin/infrapilot-$s"; done
ok "Refreshed"

step "Health check"
bash "$IP_DIR/release/health-check.sh" --prefix "$IP_DIR" || warn "Health check reported problems"
docker image prune -f >>"$LOG_FILE" 2>&1 || true
echo "$NEW_VER $(date -Is)" >"$IP_DIR/.install-complete"
RUNNING=$(compose exec -T api python -c "from app.core.config import get_settings; print(get_settings().app_version)" 2>/dev/null | tr -d '\r' || true)
echo -e "\n${C_GREEN}Update to ${NEW_VER} complete.${C_RESET} API reports version: ${RUNNING:-unknown}. Pre-upgrade backup: ${PRE:-n/a}"
if [[ -n "$RUNNING" && "$RUNNING" != "$NEW_VER" ]]; then
  warn "The running API reports ${RUNNING}, expected ${NEW_VER} - run: sudo ./update.sh again from this package"
fi
