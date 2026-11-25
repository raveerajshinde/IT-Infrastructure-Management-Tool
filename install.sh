#!/usr/bin/env bash
# InfraPilot — single installer for Ubuntu Server 22.04 / 24.04 (x86-64).
#
#   sudo ./install.sh                      interactive installation / upgrade
#   sudo ./install.sh --non-interactive --answers answers.env
#   sudo ./install.sh --help
#
# Idempotent: re-running skips completed work, never regenerates existing secrets and never
# overwrites existing configuration without explicit confirmation. Existing installations are
# upgraded in place (data is backed up first).
set -Eeuo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(cat "$SRC_DIR/VERSION")"
LOG_FILE="/var/log/infrapilot-install-$(date +%Y%m%d-%H%M%S).log"
# shellcheck source=lib/common.sh
source "$SRC_DIR/lib/common.sh"
# Permissions are often lost when the package is copied from Windows/WinSCP/browser downloads
chmod 755 "$SRC_DIR"/*.sh 2>/dev/null || true

NONINTERACTIVE=0
ANSWERS=""
ASSUME_YES=0
SKIP_FIREWALL=0
OFFLINE=0
[[ -d "$SRC_DIR/bundle/images" ]] && OFFLINE=1

usage() {
  cat <<EOF
InfraPilot ${VERSION} installer

Options:
  --non-interactive        Do not prompt; values come from --answers or defaults
  --answers FILE           Answers file (KEY=VALUE, see deploy/answers.example.env)
  --prefix DIR             Installation directory (default /opt/infrapilot)
  --yes                    Assume "yes" for confirmations (upgrade, overwrite prompts stay safe)
  --skip-firewall          Do not configure UFW
  --offline                Force offline mode (requires bundle/ directory)
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) NONINTERACTIVE=1 ;;
    --answers) ANSWERS="$2"; shift ;;
    --prefix) IP_DIR="$2"; IP_COMPOSE_FILE="$IP_DIR/docker-compose.yml"; shift ;;
    --yes|-y) ASSUME_YES=1 ;;
    --skip-firewall) SKIP_FIREWALL=1 ;;
    --offline) OFFLINE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "Unknown option: $1" ;;
  esac
  shift
done

require_root "$@"
touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
trap on_error ERR
STEP_TOTAL=14

[[ -n "$ANSWERS" ]] && { [[ -f "$ANSWERS" ]] || die "Answers file not found: $ANSWERS"; set -a; # shellcheck disable=SC1090
  source "$ANSWERS"; set +a; }

cat <<EOF

${C_BOLD}InfraPilot ${VERSION} — Unified IT Infrastructure Management Platform${C_RESET}
Install directory: ${IP_DIR}    Log: ${LOG_FILE}    Mode: $([[ $OFFLINE == 1 ]] && echo offline || echo online)
EOF

# ───────────────────────────── 1. preflight ─────────────────────────────
step "Checking system compatibility"
# read os-release in a subshell: it defines VERSION/ID/NAME, which must not overwrite the installer's variables
OS_ID=$(. /etc/os-release && echo "${ID:-}"); OS_VERSION_ID=$(. /etc/os-release && echo "${VERSION_ID:-}")
OS_PRETTY=$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}"); OS_CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
[[ "$OS_ID" == "ubuntu" ]] || die "Ubuntu Server is required (found: $OS_PRETTY)"
case "$OS_VERSION_ID" in 22.04|24.04) ok "OS: $OS_PRETTY" ;; *) die "Ubuntu 22.04 or 24.04 is required (found ${OS_VERSION_ID:-?})" ;; esac
[[ "$(uname -m)" == "x86_64" ]] || die "x86-64 architecture is required (found $(uname -m))"
ok "Architecture: x86_64"
VIRT=$(systemd-detect-virt 2>/dev/null || true)
if [[ "$VIRT" == "lxc" ]]; then
  warn "Running inside an LXC container. Docker in (unprivileged) LXC can fail with"
  warn "'open sysctl net.ipv4.ip_unprivileged_port_start ... permission denied'. A full VM is recommended;"
  warn "on Proxmox enable nesting+keyctl and use Proxmox VE 9.1+ (see docs/TROUBLESHOOTING.md)."
fi
CPUS=$(nproc); RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
(( CPUS >= IP_MIN_CPUS )) || die "At least ${IP_MIN_CPUS} CPU cores required (found $CPUS)"
ok "CPU cores: $CPUS"
(( RAM_MB >= IP_MIN_RAM_MB )) || die "At least 4 GB RAM required (found ${RAM_MB} MB). SQL Server needs 2 GB on its own."
(( RAM_MB >= IP_REC_RAM_MB )) && ok "Memory: ${RAM_MB} MB" || warn "Memory: ${RAM_MB} MB (8 GB+ recommended for production)"
mkdir -p "$IP_DIR"
for d in "$IP_DIR" /var/lib; do
  FREE_GB=$(df -BG --output=avail "$d" | tail -1 | tr -dc '0-9')
  (( FREE_GB >= IP_MIN_DISK_GB )) || die "At least ${IP_MIN_DISK_GB} GB free required on $(df --output=target "$d" | tail -1) (found ${FREE_GB} GB)"
done
ok "Disk space: ${FREE_GB} GB free"
command -v systemctl >/dev/null || die "systemd is required"
# Only a *completed* installation (marker written at the end of this script / update.sh) is upgraded;
# an interrupted install is simply resumed - every step below is idempotent.
EXISTING=0; [[ -f "$IP_DIR/.install-complete" && -f "$IP_DIR/.env" && -f "$IP_DIR/docker-compose.yml" ]] && EXISTING=1
RESUMING=0; [[ $EXISTING == 0 && -f "$IP_DIR/docker-compose.yml" ]] && RESUMING=1
port_busy() { ss -ltnH "sport = :$1" 2>/dev/null | grep -q .; }
if [[ $RESUMING == 1 ]] && command -v docker >/dev/null; then
  # our own proxy from the interrupted run may hold the ports - stop it, it is restarted in step 10
  compose stop proxy >/dev/null 2>&1 || true
fi
if [[ $EXISTING == 0 ]]; then
  for p in 80 443; do port_busy "$p" && info "Port $p is in use (by: $(ss -ltnpH "sport = :$p" | head -1 | grep -o 'users:.*' || echo unknown)) - you can choose another port next"; done
  true
fi
if [[ $OFFLINE == 0 ]]; then
  if ! curl -fsS --max-time 10 -o /dev/null https://download.docker.com 2>/dev/null; then
    die "No internet access to download.docker.com. Use the offline bundle (infrapilot-${VERSION}-offline.tar.gz)."
  fi
  ok "Internet access available"
fi

# ───────────────────────────── 2. existing installation ─────────────────────────────
step "Detecting existing installation"
if [[ $EXISTING == 1 ]]; then
  INSTALLED=$(env_get IP_VERSION); INSTALLED="${INSTALLED:-unknown}"
  info "Found InfraPilot ${INSTALLED} in ${IP_DIR}"
  if [[ $ASSUME_YES == 1 ]] || ask_yes_no "Upgrade/repair it to ${VERSION}? Data is preserved and backed up first" Y; then
    UPD_ARGS=(--from-installer --prefix "$IP_DIR"); [[ $ASSUME_YES == 1 ]] && UPD_ARGS+=(--yes)
    exec bash "$SRC_DIR/update.sh" "${UPD_ARGS[@]}"
  fi
  die "Aborted by user; nothing was changed."
fi
if [[ $RESUMING == 1 ]]; then
  ok "Resuming an interrupted installation - completed steps are re-checked, data and secrets are kept"
else
  ok "No previous installation — performing a fresh install"
fi

# ───────────────────────────── 3. configuration wizard ─────────────────────────────
step "Configuration"
DEFAULT_HOST=$(hostname -f 2>/dev/null || hostname)
echo "  Answer the questions below (press Enter to accept the default)."
ask "Server DNS name used in the browser" "${IP_HOSTNAME:-$DEFAULT_HOST}"; IP_HOSTNAME="$REPLY_VALUE"
[[ "$IP_HOSTNAME" =~ ^[A-Za-z0-9.-]+$ ]] || die "Invalid hostname: $IP_HOSTNAME"
ask "HTTPS port" "${IP_HTTPS_PORT:-443}"; IP_HTTPS_PORT="$REPLY_VALUE"
[[ "$IP_HTTPS_PORT" =~ ^[0-9]+$ ]] && (( IP_HTTPS_PORT >= 1 && IP_HTTPS_PORT <= 65535 )) || die "Invalid port: $IP_HTTPS_PORT"
if port_busy "$IP_HTTPS_PORT"; then die "Port $IP_HTTPS_PORT is already in use. Re-run and choose another HTTPS port (e.g. 8443)."; fi
IP_HTTP_PORT="${IP_HTTP_PORT:-80}"
if port_busy "$IP_HTTP_PORT"; then
  for alt in 8080 8081 8082 8088 8090; do port_busy "$alt" || { warn "Port $IP_HTTP_PORT is in use; the HTTP->HTTPS redirect will listen on $alt instead"; IP_HTTP_PORT=$alt; break; }; done
fi
if [[ "$IP_HTTPS_PORT" == "443" ]]; then PUBLIC_URL="https://${IP_HOSTNAME}"; else PUBLIC_URL="https://${IP_HOSTNAME}:${IP_HTTPS_PORT}"; fi

echo
echo "  ${C_BOLD}TLS certificate${C_RESET}: a self-signed certificate is generated unless you provide one (PEM)."
ask "Path to certificate (blank = self-signed)" "${IP_TLS_CERT:-}"; IP_TLS_CERT="$REPLY_VALUE"
if [[ -n "$IP_TLS_CERT" ]]; then
  ask "Path to private key" "${IP_TLS_KEY:-}"; IP_TLS_KEY="$REPLY_VALUE"
  [[ -f "$IP_TLS_CERT" && -f "$IP_TLS_KEY" ]] || die "Certificate or key file not found"
  openssl x509 -in "$IP_TLS_CERT" -noout >/dev/null 2>&1 || die "Certificate is not valid PEM"
  [[ "$(openssl x509 -in "$IP_TLS_CERT" -noout -pubkey | openssl sha256)" == "$(openssl pkey -in "$IP_TLS_KEY" -pubout | openssl sha256)" ]] \
    || die "Certificate and private key do not match"
fi

echo
echo "  ${C_BOLD}SQL Server edition${C_RESET} (licensing is your responsibility):"
echo "    Express   — free, 10 GB per database (fine for most deployments)"
echo "    Developer — free, NOT licensed for production use"
echo "    Standard / Enterprise — requires your license; product key needed"
ask "Edition (Express/Developer/Standard/Enterprise)" "${IP_MSSQL_EDITION:-Express}"; IP_MSSQL_EDITION="$REPLY_VALUE"
case "$IP_MSSQL_EDITION" in
  Express|Developer) MSSQL_PID="$IP_MSSQL_EDITION" ;;
  Standard|Enterprise)
    ask "Product key (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)" "${IP_MSSQL_PRODUCT_KEY:-}"
    [[ "$REPLY_VALUE" =~ ^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$ ]] || die "Invalid product key format"
    MSSQL_PID="$REPLY_VALUE" ;;
  *) die "Unknown edition: $IP_MSSQL_EDITION" ;;
esac
MSSQL_MEM=$(( RAM_MB / 3 )); (( MSSQL_MEM < 2048 )) && MSSQL_MEM=2048
(( MSSQL_MEM > 16384 )) && MSSQL_MEM=16384

echo
echo "  ${C_BOLD}Initial administrator${C_RESET} (local account, Super Administrator role)"
ask "Username" "${IP_ADMIN_USER:-admin}"; IP_ADMIN_USER="$REPLY_VALUE"
[[ "$IP_ADMIN_USER" =~ ^[A-Za-z0-9._@-]{2,64}$ ]] || die "Invalid username"
ask "E-mail (optional)" "${IP_ADMIN_EMAIL:-}"; IP_ADMIN_EMAIL="$REPLY_VALUE"
GENERATED_ADMIN_PW=0
if [[ -n "${IP_ADMIN_PASSWORD:-}" ]]; then ADMIN_PW="$IP_ADMIN_PASSWORD"
elif [[ $NONINTERACTIVE == 1 ]]; then ADMIN_PW="$(rand_alnum 20)Aa1!"; GENERATED_ADMIN_PW=1
elif ask_yes_no "Generate a strong random password for the administrator?" Y; then ADMIN_PW="$(rand_alnum 20)Aa1!"; GENERATED_ADMIN_PW=1
else
  while true; do
    ask_secret "Administrator password (12+ chars, 3 of: upper/lower/digit/symbol)"; ADMIN_PW="$REPLY_VALUE"
    [[ ${#ADMIN_PW} -ge 12 ]] && break; warn "Too short."
  done
fi

echo
LDAP_ENABLED=false
if ask_yes_no "Configure Active Directory (LDAPS) sign-in now? (can be done later in Settings)" "${IP_LDAP_CONFIGURE:-N}"; then
  LDAP_ENABLED=true
  ask "LDAPS URL" "${IP_LDAP_URL:-ldaps://dc01.corp.local:636}"; IP_LDAP_URL="$REPLY_VALUE"
  [[ "$IP_LDAP_URL" == ldaps://* ]] || die "Only ldaps:// is accepted by the installer (StartTLS can be set later in Settings)"
  ask "Base DN" "${IP_LDAP_BASE_DN:-DC=corp,DC=local}"; IP_LDAP_BASE_DN="$REPLY_VALUE"
  ask "Service account bind DN" "${IP_LDAP_BIND_DN:-CN=svc-infrapilot,OU=Service Accounts,DC=corp,DC=local}"; IP_LDAP_BIND_DN="$REPLY_VALUE"
  if [[ -n "${IP_LDAP_BIND_PASSWORD:-}" ]]; then LDAP_PW="$IP_LDAP_BIND_PASSWORD"; else ask_secret "Service account password"; LDAP_PW="$REPLY_VALUE"; fi
  ask "AD group DN for Super Administrators" "${IP_LDAP_ADMIN_GROUP:-CN=InfraPilot-Admins,OU=Groups,DC=corp,DC=local}"; IP_LDAP_ADMIN_GROUP="$REPLY_VALUE"
  ask "Path to the domain CA certificate (PEM, blank = system CAs)" "${IP_LDAP_CA:-}"; IP_LDAP_CA="$REPLY_VALUE"
  [[ -z "$IP_LDAP_CA" || -f "$IP_LDAP_CA" ]] || die "CA file not found: $IP_LDAP_CA"
fi

CONFIGURE_UFW=0
if [[ $SKIP_FIREWALL == 0 ]] && ask_yes_no "Configure the UFW firewall (allow SSH, ${IP_HTTP_PORT}, ${IP_HTTPS_PORT})?" "${IP_CONFIGURE_FIREWALL:-Y}"; then CONFIGURE_UFW=1; fi

echo
echo "  ${C_BOLD}Summary${C_RESET}"
echo "    URL:            $PUBLIC_URL   (HTTP redirect on port ${IP_HTTP_PORT})"
echo "    TLS:            $([[ -n "$IP_TLS_CERT" ]] && echo "provided ($IP_TLS_CERT)" || echo "self-signed")"
echo "    SQL Server:     $IP_MSSQL_EDITION (memory limit ${MSSQL_MEM} MB)"
echo "    Administrator:  $IP_ADMIN_USER"
echo "    AD sign-in:     $LDAP_ENABLED"
echo "    Firewall:       $([[ $CONFIGURE_UFW == 1 ]] && echo configure UFW || echo unchanged)"
[[ $ASSUME_YES == 1 ]] || ask_yes_no "Proceed with installation?" Y || die "Aborted by user; nothing was changed."

# ───────────────────────────── 4. prerequisites ─────────────────────────────
step "Installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
if [[ $OFFLINE == 1 ]]; then
  info "Offline mode: using packages from the bundle"
  for c in curl openssl ss awk; do command -v "$c" >/dev/null || die "Missing '$c' — install it or use an Ubuntu server image that includes it"; done
else
  run apt-get update -q
  run apt-get install -y -q ca-certificates curl gnupg openssl iproute2 ufw jq
fi
ok "Prerequisites present"

# ───────────────────────────── 5. Docker ─────────────────────────────
step "Installing Docker Engine and Compose"
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  CV=$(docker compose version --short | sed 's/^v//')
  version_ge "$CV" "$IP_COMPOSE_MIN" || die "Docker Compose $CV is too old (need >= $IP_COMPOSE_MIN). Upgrade Docker first."
  ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?') and Compose $CV already installed"
else
  if [[ $OFFLINE == 1 ]]; then
    DEB_DIR="$SRC_DIR/bundle/debs/${OS_CODENAME}"
    [[ -d "$DEB_DIR" ]] || die "Bundle has no Docker packages for $OS_CODENAME"
    run dpkg -i "$DEB_DIR"/*.deb
  else
    install -m 0755 -d /etc/apt/keyrings
    run curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${OS_CODENAME} stable" \
      >/etc/apt/sources.list.d/docker.list
    run apt-get update -q
    PKG_VER=$(apt-cache madison docker-ce | awk '{print $3}' | grep -m1 "^5:${IP_DOCKER_VERSION}-" || true)
    if [[ -z "$PKG_VER" ]]; then
      warn "Pinned Docker ${IP_DOCKER_VERSION} not available for ${OS_CODENAME}; installing the latest stable"
      run apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
      run apt-get install -y -q "docker-ce=${PKG_VER}" "docker-ce-cli=${PKG_VER}" containerd.io docker-buildx-plugin docker-compose-plugin
      run apt-mark hold docker-ce docker-ce-cli
    fi
  fi
  run systemctl enable --now docker
  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin did not install correctly"
  ok "Docker $(docker version --format '{{.Server.Version}}') installed"
fi
# Bound container log growth host-wide if not configured
if [[ ! -f /etc/docker/daemon.json ]]; then
  mkdir -p /etc/docker
  echo '{ "log-driver": "json-file", "log-opts": { "max-size": "20m", "max-file": "5" }, "live-restore": true }' >/etc/docker/daemon.json
  run systemctl restart docker
fi

# ───────────────────────────── 6. files & secrets ─────────────────────────────
step "Creating directories, secrets and certificates"
umask 077
mkdir -p "$IP_DIR"/{secrets,certs,backups/mssql,backups/config,logs,release}
chmod 750 "$IP_DIR"; chmod 700 "$IP_DIR/secrets" "$IP_DIR/backups/config"
# Copy the release (sources, scripts, docs) so maintenance scripts work without the original package
if [[ "$(realpath "$SRC_DIR")" != "$(realpath "$IP_DIR/release")" ]]; then run cp -a "$SRC_DIR/." "$IP_DIR/release/"; fi
rm -rf "$IP_DIR/release/bundle/images" 2>/dev/null || true
cp "$SRC_DIR/deploy/docker-compose.yml" "$IP_COMPOSE_FILE"
chmod 640 "$IP_COMPOSE_FILE"

gen_secret() { # gen_secret name generator...
  local f="$IP_DIR/secrets/$1"; shift
  if [[ -s "$f" ]]; then info "Keeping existing secret $(basename "$f")"; else "$@" >"$f"; ok "Generated secret $(basename "$f")"; fi
}
# A SQL Server data volume only accepts the sa password it was initialised with. If the volume survived
# from an earlier attempt but the secrets did not (e.g. /opt/infrapilot was deleted), new secrets cannot work.
if [[ ! -s "$IP_DIR/secrets/mssql_sa_password" ]] && docker volume inspect infrapilot_mssql-data >/dev/null 2>&1; then
  err "A SQL Server data volume (infrapilot_mssql-data) from an earlier installation exists, but its"
  err "secrets in $IP_DIR/secrets are gone, so the database password cannot match."
  err "  - If that earlier installation held no data you need, remove it and re-run the installer:"
  err "      docker rm -f \$(docker ps -aq --filter label=com.docker.compose.project=infrapilot) 2>/dev/null; docker volume rm infrapilot_mssql-data infrapilot_runner-data"
  err "  - If it holds data, restore the original $IP_DIR/secrets directory from your backup first."
  die "Stale database volume without matching secrets"
fi
gen_secret vault_key bash -c 'echo "v1:$(openssl rand -base64 32)"'
gen_secret db_password rand_sql_password
gen_secret mssql_sa_password rand_sql_password
if [[ ! -s "$IP_DIR/secrets/mssql.env" ]]; then
  printf 'ACCEPT_EULA=Y\nMSSQL_PID=%s\nMSSQL_SA_PASSWORD=%s\n' "$MSSQL_PID" "$(cat "$IP_DIR/secrets/mssql_sa_password")" >"$IP_DIR/secrets/mssql.env"
fi
LDAP_PW_FILE=""
if [[ "$LDAP_ENABLED" == true ]]; then
  printf '%s' "$LDAP_PW" >"$IP_DIR/secrets/ldap_bind_password"; LDAP_PW_FILE=/run/secrets/ldap_bind_password
  [[ -n "$IP_LDAP_CA" ]] && cp "$IP_LDAP_CA" "$IP_DIR/certs/ldap-ca.pem"
fi
# Containers run as uid 10001 (app) — they must read the secrets they mount (root:10001 0640)
chown root:"$IP_APP_UID" "$IP_DIR/secrets" "$IP_DIR/secrets"/{vault_key,db_password,mssql_sa_password}
chmod 750 "$IP_DIR/secrets"; chmod 640 "$IP_DIR/secrets"/{vault_key,db_password,mssql_sa_password}
chmod 600 "$IP_DIR/secrets/mssql.env"
[[ -f "$IP_DIR/secrets/ldap_bind_password" ]] && { chown root:"$IP_APP_UID" "$IP_DIR/secrets/ldap_bind_password"; chmod 640 "$IP_DIR/secrets/ldap_bind_password"; }

if [[ -s "$IP_DIR/certs/tls.crt" ]]; then
  info "Keeping existing TLS certificate"
elif [[ -n "$IP_TLS_CERT" ]]; then
  cp "$IP_TLS_CERT" "$IP_DIR/certs/tls.crt"; cp "$IP_TLS_KEY" "$IP_DIR/certs/tls.key"; ok "Installed provided certificate"
else
  IPADDR=$(hostname -I | awk '{print $1}')
  run openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes -keyout "$IP_DIR/certs/tls.key" -out "$IP_DIR/certs/tls.crt" \
    -subj "/CN=${IP_HOSTNAME}/O=InfraPilot" -addext "subjectAltName=DNS:${IP_HOSTNAME},DNS:localhost${IPADDR:+,IP:${IPADDR}}" \
    -addext "keyUsage=digitalSignature,keyEncipherment" -addext "extendedKeyUsage=serverAuth"
  ok "Generated self-signed certificate for ${IP_HOSTNAME} (replace later with a CA-signed one: see Admin Manual)"
fi
chown root:"$IP_PROXY_UID" "$IP_DIR/certs/tls.key" "$IP_DIR/certs/tls.crt"; chmod 640 "$IP_DIR/certs/tls.key"; chmod 644 "$IP_DIR/certs/tls.crt"
chmod 755 "$IP_DIR/certs"

# Fresh install (an existing, completed installation never reaches this point - it is upgraded by update.sh),
# so a .env left behind by an interrupted attempt is regenerated rather than trusted.
if [[ -f "$IP_DIR/.env" ]]; then
  cp -p "$IP_DIR/.env" "$IP_DIR/.env.incomplete-$(date +%Y%m%d%H%M%S)"
  info "Regenerating .env left by an interrupted install (old copy kept as .env.incomplete-*)"
fi
{
  cp "$SRC_DIR/deploy/env.template" "$IP_DIR/.env"
  env_set IP_VERSION "$VERSION"; env_set IP_PUBLIC_URL "$PUBLIC_URL"; env_set IP_HTTPS_PORT "$IP_HTTPS_PORT"; env_set IP_HTTP_PORT "$IP_HTTP_PORT"
  env_set IP_IMAGE_API "infrapilot/api:${VERSION}"; env_set IP_IMAGE_PROXY "infrapilot/proxy:${VERSION}"
  env_set IP_MSSQL_MEMORY_MB "$MSSQL_MEM"
  if [[ "$LDAP_ENABLED" == true ]]; then
    env_set IP_LDAP_ENABLED true; env_set IP_LDAP_URL "$IP_LDAP_URL"; env_set IP_LDAP_BASE_DN "$IP_LDAP_BASE_DN"
    env_set IP_LDAP_BIND_DN "$IP_LDAP_BIND_DN"; env_set IP_LDAP_BIND_PASSWORD_FILE "$LDAP_PW_FILE"
    env_set IP_LDAP_GROUP_ROLE_MAP "${IP_LDAP_ADMIN_GROUP}=Super Administrator"
    [[ -f "$IP_DIR/certs/ldap-ca.pem" ]] || env_set IP_LDAP_CA_FILE ""
  fi
  chmod 640 "$IP_DIR/.env"; chown root:"$IP_APP_UID" "$IP_DIR/.env"
  ok "Wrote $IP_DIR/.env"
}
apply_compose_overrides
chown 10001:0 "$IP_DIR/backups/mssql"; chmod 770 "$IP_DIR/backups/mssql"   # SQL Server container user
ensure_export_dir

# ───────────────────────────── 7. images ─────────────────────────────
step "Preparing container images"
API_IMG="infrapilot/api:${VERSION}"; PROXY_IMG="infrapilot/proxy:${VERSION}"; MSSQL_IMG=$(env_get IP_IMAGE_MSSQL)
if [[ $OFFLINE == 1 ]]; then
  for tar in "$SRC_DIR"/bundle/images/*.tar*; do info "Loading $(basename "$tar")"; run docker load -i "$tar"; done
else
  info "Building $API_IMG (a few minutes on first install)"
  run docker build -f "$SRC_DIR/backend/Dockerfile" -t "$API_IMG" "$SRC_DIR"
  info "Building $PROXY_IMG"
  run docker build -f "$SRC_DIR/frontend/Dockerfile" -t "$PROXY_IMG" "$SRC_DIR"
  info "Pulling $MSSQL_IMG"
  run docker pull "$MSSQL_IMG"
fi
for img in "$API_IMG" "$PROXY_IMG" "$MSSQL_IMG"; do docker image inspect "$img" >/dev/null 2>&1 || die "Image missing: $img"; done
ok "Images ready"

# ───────────────────────────── 8. database ─────────────────────────────
step "Starting SQL Server"
run compose up -d mssql
wait_healthy mssql 420
ok "SQL Server is running"

step "Creating database and running migrations"
run tools python -m app.cli bootstrap-db --sa-password-file /run/secrets/mssql_sa_password
run tools python -m app.cli migrate --sa-password-file /run/secrets/mssql_sa_password
ok "Schema is up to date"

# ───────────────────────────── 9. administrator ─────────────────────────────
step "Creating the initial administrator"
ADMIN_OUT=$(printf '%s\n' "$ADMIN_PW" | compose --profile tools run --rm -T tools python -m app.cli create-admin --username "$IP_ADMIN_USER" \
     ${IP_ADMIN_EMAIL:+--email "$IP_ADMIN_EMAIL"} --if-missing 2>&1) || { echo "$ADMIN_OUT" >>"$LOG_FILE";
  die "Could not create the administrator (see $LOG_FILE). Password policy: 12+ characters, 3 character classes."; }
echo "$ADMIN_OUT" >>"$LOG_FILE"
if [[ "$ADMIN_OUT" == *"left unchanged"* ]]; then
  # The account was created by an earlier, interrupted run of this installer whose password was never
  # displayed. Set it to the password chosen/generated in this run so the summary below is correct.
  printf '%s\n' "$ADMIN_PW" | compose --profile tools run --rm -T tools python -m app.cli reset-admin-password --username "$IP_ADMIN_USER" >>"$LOG_FILE" 2>&1 \
    || die "Could not set the administrator password (see $LOG_FILE)"
  ok "Administrator '$IP_ADMIN_USER' already existed from the interrupted run - password set to the one from this run"
else
  ok "Administrator '$IP_ADMIN_USER' ready"
fi

# ───────────────────────────── 10. start ─────────────────────────────
step "Starting InfraPilot services"
run compose up -d --force-recreate api worker proxy
wait_healthy api 300
wait_healthy proxy 120
wait_healthy worker 300 || warn "Worker not yet reporting healthy — check: docker compose logs worker"
ok "All services started"

# ───────────────────────────── 11. firewall ─────────────────────────────
step "Configuring firewall"
if [[ $CONFIGURE_UFW == 1 ]]; then
  if { command -v ufw >/dev/null || apt-get install -y -q ufw >>"$LOG_FILE" 2>&1; } \
     && ufw allow OpenSSH >>"$LOG_FILE" 2>&1 && ufw allow "${IP_HTTP_PORT}/tcp" >>"$LOG_FILE" 2>&1 \
     && ufw allow "${IP_HTTPS_PORT}/tcp" >>"$LOG_FILE" 2>&1 \
     && { ufw status | grep -q "Status: active" || ufw --force enable >>"$LOG_FILE" 2>&1; }; then
    ok "UFW active: SSH, ${IP_HTTP_PORT} (redirect), ${IP_HTTPS_PORT} (HTTPS) allowed"
  else
    warn "UFW could not be configured on this host (common inside LXC containers) - configure the firewall manually"
  fi
  info "Note: Docker manages its own iptables rules for published ports; only ${IP_HTTP_PORT}/${IP_HTTPS_PORT} are published."
else
  info "Firewall left unchanged"
fi

# ───────────────────────────── 12. maintenance tools ─────────────────────────────
step "Installing maintenance commands"
for s in update backup restore uninstall health-check; do
  chmod 750 "$IP_DIR/release/$s.sh"
  ln -sf "$IP_DIR/release/$s.sh" "/usr/local/sbin/infrapilot-$s"
done
cat >/etc/cron.d/infrapilot-backup <<EOF
# Nightly InfraPilot backup (database + configuration), keeps 14 days
30 1 * * * root /usr/local/sbin/infrapilot-backup --quiet --keep-days 14 >>${IP_DIR}/logs/backup.log 2>&1
EOF
chmod 644 /etc/cron.d/infrapilot-backup
ok "Commands: infrapilot-{update,backup,restore,health-check,uninstall}; nightly backup scheduled 01:30"

# ───────────────────────────── 13. validation ─────────────────────────────
step "Validating the installation"
if bash "$IP_DIR/release/health-check.sh" --prefix "$IP_DIR" >>"$LOG_FILE" 2>&1; then ok "Health check passed"; else
  warn "Health check reported problems:"; bash "$IP_DIR/release/health-check.sh" --prefix "$IP_DIR" || true; fi
cp "$LOG_FILE" "$IP_DIR/logs/" 2>/dev/null || true
echo "$VERSION $(date -Is)" >"$IP_DIR/.install-complete"

cat <<EOF

${C_GREEN}${C_BOLD}InfraPilot ${VERSION} is installed.${C_RESET}

  Open:            ${C_BOLD}${PUBLIC_URL}${C_RESET}
  Administrator:   ${IP_ADMIN_USER}
EOF
if [[ $GENERATED_ADMIN_PW == 1 ]]; then
  echo "  Password:        ${C_BOLD}${ADMIN_PW}${C_RESET}   (shown once — store it in your password manager)"
fi
cat <<EOF

  First steps:
    1. Sign in and enable two-factor authentication (Settings → My account).
    2. Follow the onboarding wizard: store a credential, register a device, test connectivity.
    3. Configure SMTP and (optionally) Active Directory in Settings; assign roles to your team.
    4. Replace the self-signed certificate if used (Deployment Guide §6).

  Install directory: ${IP_DIR}     Secrets: ${IP_DIR}/secrets (root only — back them up securely)
  Log file:          ${LOG_FILE}
  Maintenance:       infrapilot-health-check | infrapilot-backup | infrapilot-update | infrapilot-restore
EOF
