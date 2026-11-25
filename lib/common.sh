#!/usr/bin/env bash
# Shared helpers for InfraPilot installer and maintenance scripts.
# shellcheck disable=SC2034

IP_DIR="${IP_DIR:-/opt/infrapilot}"
IP_LOG_DIR="${IP_DIR}/logs"
IP_COMPOSE_FILE="${IP_DIR}/docker-compose.yml"
IP_MIN_RAM_MB=3800
IP_REC_RAM_MB=8000
IP_MIN_DISK_GB=20
IP_MIN_CPUS=2
IP_DOCKER_VERSION="27.3.1"
IP_COMPOSE_MIN="2.20.0"
IP_APP_UID=10001
IP_PROXY_UID=101

if [[ -t 1 ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_BLUE=$'\e[34m'; C_DIM=$'\e[2m'
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_DIM=""
fi

LOG_FILE="${LOG_FILE:-/tmp/infrapilot-$(date +%Y%m%d-%H%M%S).log}"
STEP_NO=0
STEP_TOTAL="${STEP_TOTAL:-0}"
CURRENT_STEP=""

_ts() { date '+%Y-%m-%d %H:%M:%S'; }
log()  { echo "[$(_ts)] $*" >>"$LOG_FILE"; }
info() { echo "  ${C_BLUE}•${C_RESET} $*"; log "INFO  $*"; }
ok()   { echo "  ${C_GREEN}✔${C_RESET} $*"; log "OK    $*"; }
warn() { echo "  ${C_YELLOW}!${C_RESET} $*"; log "WARN  $*"; }
err()  { echo "  ${C_RED}✖${C_RESET} $*" >&2; log "ERROR $*"; }
die()  { err "$*"; exit 1; }

step() {
  STEP_NO=$((STEP_NO + 1))
  CURRENT_STEP="$*"
  echo
  if [[ "$STEP_TOTAL" -gt 0 ]]; then
    echo "${C_BOLD}[${STEP_NO}/${STEP_TOTAL}] $*${C_RESET}"
  else
    echo "${C_BOLD}==> $*${C_RESET}"
  fi
  log "STEP  $*"
}

# Run a command, sending its output to the log; on failure show the tail of the log.
run() {
  log "RUN   $*"
  if ! "$@" >>"$LOG_FILE" 2>&1; then
    err "Command failed: $*"
    echo "${C_DIM}---- last log lines ($LOG_FILE) ----${C_RESET}" >&2
    tail -n 25 "$LOG_FILE" >&2 || true
    return 1
  fi
}

on_error() {
  local rc=$?
  echo >&2
  err "Failed during step: ${CURRENT_STEP:-unknown} (exit code $rc)"
  err "Full log: $LOG_FILE"
  echo "  The operation is safe to re-run after fixing the problem; completed steps are skipped." >&2
  exit "$rc"
}

require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo $0 $*)"; }

ask() { # ask "Question" default -> REPLY_VALUE
  local q="$1" def="${2:-}" a
  if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then REPLY_VALUE="$def"; return; fi
  read -r -p "  ${q}${def:+ [$def]}: " a </dev/tty || true
  REPLY_VALUE="${a:-$def}"
}

ask_yes_no() { # ask_yes_no "Question" Y|N
  local q="$1" def="${2:-N}" a
  if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then [[ "$def" =~ ^[Yy] ]]; return; fi
  read -r -p "  ${q} [$([[ $def =~ ^[Yy] ]] && echo Y/n || echo y/N)]: " a </dev/tty || true
  a="${a:-$def}"
  [[ "$a" =~ ^[Yy] ]]
}

ask_secret() { # ask_secret "Prompt" -> REPLY_VALUE (asks twice)
  local p1 p2
  while true; do
    read -r -s -p "  $1: " p1 </dev/tty; echo
    read -r -s -p "  Confirm: " p2 </dev/tty; echo
    [[ "$p1" == "$p2" ]] && break
    warn "Values do not match, try again."
  done
  REPLY_VALUE="$p1"
}

rand_alnum() { # rand_alnum length
  local n="${1:-32}" s=""
  while [[ ${#s} -lt $n ]]; do s+=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9'); done
  echo "${s:0:$n}"
}

# SQL Server password policy: upper, lower, digit, symbol; avoid characters that need quoting.
rand_sql_password() { echo "$(rand_alnum 28)Aa1!"; }

version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]; }

compose() { docker compose --project-directory "$IP_DIR" -f "$IP_COMPOSE_FILE" "$@"; }

env_get() { # env_get KEY [file]
  local f="${2:-$IP_DIR/.env}"
  [[ -f "$f" ]] || return 0
  grep -E "^$1=" "$f" | tail -n1 | cut -d= -f2-
}

env_set() { # env_set KEY VALUE [file]  (creates or replaces)
  local k="$1" v="$2" f="${3:-$IP_DIR/.env}"
  if grep -qE "^${k}=" "$f" 2>/dev/null; then
    local tmp; tmp=$(mktemp)
    awk -v k="$k" -v v="$v" -F= 'BEGIN{OFS="="} $1==k {print k"="v; next} {print}' "$f" >"$tmp" && cat "$tmp" >"$f" && rm -f "$tmp"
  else
    echo "${k}=${v}" >>"$f"
  fi
}

wait_healthy() { # wait_healthy service timeout_seconds
  local svc="$1" t="${2:-300}" start cid st
  start=$(date +%s)
  while true; do
    cid=$(compose ps -q "$svc" 2>/dev/null | head -n1)
    if [[ -n "$cid" ]]; then
      st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo unknown)
      [[ "$st" == "healthy" ]] && return 0
      [[ "$st" == "exited" || "$st" == "dead" ]] && { err "$svc exited"; compose logs --tail 40 "$svc" >&2 || true; return 1; }
    fi
    if (( $(date +%s) - start > t )); then
      err "$svc did not become healthy within ${t}s (state: ${st:-not started})"
      compose logs --tail 60 "$svc" >>"$LOG_FILE" 2>&1 || true
      compose logs --tail 20 "$svc" >&2 || true
      return 1
    fi
    sleep 5
  done
}

# Re-apply local adjustments to the shipped compose file (used by install and update).
apply_compose_overrides() {
  if [[ -s "$IP_DIR/secrets/ldap_bind_password" ]]; then
    sed -i -e 's/^  secrets: \[vault_key, db_password\]$/  secrets: [vault_key, db_password, ldap_bind_password]/' \
           -e 's/^    secrets: \[vault_key, db_password, mssql_sa_password\]$/    secrets: [vault_key, db_password, mssql_sa_password, ldap_bind_password]/' "$IP_COMPOSE_FILE"
    grep -q "^  ldap_bind_password:" "$IP_COMPOSE_FILE" || echo "  ldap_bind_password: { file: ./secrets/ldap_bind_password }" >>"$IP_COMPOSE_FILE"
  fi
}

ensure_export_dir() { # default folder for device backup copies (Settings -> Backup -> Folder on the server)
  mkdir -p /srv/infrapilot-exports
  chown 10001:10001 /srv/infrapilot-exports 2>/dev/null || true
  chmod 750 /srv/infrapilot-exports
}

tools() { compose --profile tools run --rm -T tools "$@"; }

backup_db() { # backup_db label -> prints path of .bak on host
  local label="${1:-manual}" ts name
  ts=$(date +%Y%m%d-%H%M%S)
  name="infrapilot_${label}_${ts}.bak"
  local db; db=$(env_get IP_DB_NAME); db="${db:-infrapilot}"
  mkdir -p "$IP_DIR/backups/mssql"
  chown 10001:0 "$IP_DIR/backups/mssql" 2>/dev/null || true
  chmod 770 "$IP_DIR/backups/mssql"
  # SQL Server in the container runs as uid 10001 (mssql)
  compose exec -T mssql bash -c "/opt/mssql-tools18/bin/sqlcmd -C -b -S localhost -U sa -P \"\$MSSQL_SA_PASSWORD\" \
    -Q \"BACKUP DATABASE [${db}] TO DISK = N'/var/opt/mssql/backup/${name}' WITH INIT, CHECKSUM, STATS = 25\"" >>"$LOG_FILE" 2>&1 \
    || return 1
  compose exec -T mssql bash -c "/opt/mssql-tools18/bin/sqlcmd -C -b -S localhost -U sa -P \"\$MSSQL_SA_PASSWORD\" \
    -Q \"RESTORE VERIFYONLY FROM DISK = N'/var/opt/mssql/backup/${name}' WITH CHECKSUM\"" >>"$LOG_FILE" 2>&1 \
    || return 1
  echo "$IP_DIR/backups/mssql/${name}"
}
