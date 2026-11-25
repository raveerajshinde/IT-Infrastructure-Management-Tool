#!/usr/bin/env bash
# InfraPilot health check. Exit code 0 = healthy, 1 = degraded/failed.
#   infrapilot-health-check [--prefix DIR] [--json] [--verify-audit]
set -uo pipefail
SRC_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOG_FILE="/dev/null"
# shellcheck source=lib/common.sh
source "$SRC_DIR/lib/common.sh"
JSON=0; VERIFY_AUDIT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) IP_DIR="$2"; IP_COMPOSE_FILE="$IP_DIR/docker-compose.yml"; shift ;;
    --json) JSON=1 ;;
    --verify-audit) VERIFY_AUDIT=1 ;;
    --quiet) ;;
    *) echo "Unknown option $1"; exit 2 ;;
  esac; shift
done
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 2; }
[[ -f "$IP_COMPOSE_FILE" ]] || { echo "InfraPilot is not installed in $IP_DIR"; exit 2; }

FAIL=0; RESULTS=()
check() { # check name status message
  RESULTS+=("{\"check\":\"$1\",\"status\":\"$2\",\"message\":\"${3//\"/\'}\"}")
  if [[ $JSON == 0 ]]; then
    case "$2" in ok) ok "$1: $3" ;; warn) warn "$1: $3" ;; *) err "$1: $3" ;; esac
  fi
  [[ "$2" == fail ]] && FAIL=1
  return 0
}

[[ $JSON == 0 ]] && echo "${C_BOLD}InfraPilot health check — $(date)${C_RESET}"
systemctl is-active --quiet docker && check docker ok "daemon running" || check docker fail "Docker daemon is not running"

for svc in mssql api worker proxy; do
  cid=$(compose ps -q "$svc" 2>/dev/null | head -1)
  if [[ -z "$cid" ]]; then check "$svc" fail "container not running"; continue; fi
  st=$(docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$cid")
  rs=$(docker inspect -f '{{.RestartCount}}' "$cid")
  case "$st" in
    running/healthy) check "$svc" ok "running, healthy (restarts: $rs)" ;;
    running/starting) check "$svc" warn "starting" ;;
    *) check "$svc" fail "state $st (restarts: $rs)" ;;
  esac
done

PORT=$(env_get IP_HTTPS_PORT); PORT="${PORT:-443}"
if out=$(curl -sk --max-time 10 "https://127.0.0.1:${PORT}/api/readyz"); then
  status=$(echo "$out" | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p' | head -1)
  case "$status" in
    ok) check api-readiness ok "database, vault and workers OK" ;;
    degraded) check api-readiness warn "API up but no worker heartbeat in the last 2 minutes" ;;
    *) check api-readiness fail "unexpected response: ${out:0:200}" ;;
  esac
else
  check api-readiness fail "https://127.0.0.1:${PORT}/api/readyz unreachable"
fi
code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://127.0.0.1:${PORT}/")
[[ "$code" == 200 ]] && check web-ui ok "served over HTTPS" || check web-ui fail "HTTP $code"

if [[ -f "$IP_DIR/certs/tls.crt" ]]; then
  end=$(openssl x509 -enddate -noout -in "$IP_DIR/certs/tls.crt" | cut -d= -f2)
  days=$(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
  if (( days < 0 )); then check tls-certificate fail "expired $((-days)) days ago"
  elif (( days < 30 )); then check tls-certificate warn "expires in $days days"
  else check tls-certificate ok "valid for $days days"; fi
fi

free=$(df -BG --output=avail "$IP_DIR" | tail -1 | tr -dc '0-9')
dfree=$(df -BG --output=avail /var/lib/docker 2>/dev/null | tail -1 | tr -dc '0-9')
(( free < 5 || ${dfree:-99} < 5 )) && check disk fail "low disk space (install dir ${free}G, docker ${dfree}G)" \
  || { (( free < 15 )) && check disk warn "${free}G free" || check disk ok "${free}G free (install dir), ${dfree}G (docker)"; }

last=$(ls -1t "$IP_DIR"/backups/mssql/*.bak 2>/dev/null | head -1)
if [[ -z "$last" ]]; then check backup warn "no database backup found yet"
else
  age=$(( ($(date +%s) - $(stat -c %Y "$last")) / 3600 ))
  (( age > 48 )) && check backup warn "last backup is ${age}h old ($(basename "$last"))" || check backup ok "last backup ${age}h ago"
fi

if [[ $VERIFY_AUDIT == 1 ]]; then
  if r=$(tools python -m app.cli verify-audit 2>&1); then check audit-chain ok "$(echo "$r" | tail -1)"; else check audit-chain fail "$(echo "$r" | tail -1)"; fi
fi

if [[ $JSON == 1 ]]; then
  (IFS=,; echo "{\"healthy\":$([[ $FAIL == 0 ]] && echo true || echo false),\"checks\":[${RESULTS[*]}]}")
else
  echo; [[ $FAIL == 0 ]] && echo "${C_GREEN}Overall: HEALTHY${C_RESET}" || echo "${C_RED}Overall: PROBLEMS FOUND${C_RESET} — see Troubleshooting Guide"
fi
exit $FAIL
