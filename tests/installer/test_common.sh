#!/usr/bin/env bash
# Unit tests for lib/common.sh helpers (no root/Docker needed):  bash tests/installer/test_common.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOG_FILE=/dev/null
# shellcheck source=../../lib/common.sh
source "$ROOT/lib/common.sh"
FAILS=0
t() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; FAILS=$((FAILS+1)); fi; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
printf 'A=1\nB=two\n# comment\n' >"$TMP/.env"
env_set B three "$TMP/.env"; env_set C "x=y z" "$TMP/.env"
t "env_set replaces existing key"   '[[ "$(env_get B "$TMP/.env")" == three ]]'
t "env_set appends new key with ="  '[[ "$(env_get C "$TMP/.env")" == "x=y z" ]]'
t "env_set keeps other keys"        '[[ "$(env_get A "$TMP/.env")" == 1 ]] && grep -q "# comment" "$TMP/.env"'
t "env_get missing key is empty"    '[[ -z "$(env_get NOPE "$TMP/.env")" ]]'
p=$(rand_sql_password)
t "sql password length >= 30"       '[[ ${#p} -ge 30 ]]'
t "sql password meets complexity"   '[[ "$p" =~ [A-Z] && "$p" =~ [a-z] && "$p" =~ [0-9] && "$p" =~ [^A-Za-z0-9] ]]'
t "sql password has no quotes"      '[[ "$p" != *"'"'"'"* && "$p" != *\"* ]]'
a=$(rand_alnum 64); b=$(rand_alnum 64)
t "random secrets differ"           '[[ "$a" != "$b" && ${#a} -eq 64 ]]'
t "version_ge equal"                'version_ge 2.20.0 2.20.0'
t "version_ge greater"              'version_ge 2.29.7 2.20.0'
t "version_ge less"                 '! version_ge 2.9.0 2.20.0'
NONINTERACTIVE=1
ask "q" "dflt"; t "ask returns default when non-interactive" '[[ "$REPLY_VALUE" == dflt ]]'
t "ask_yes_no default Y"            'ask_yes_no "q" Y'
t "ask_yes_no default N"            '! ask_yes_no "q" N'
for s in install update backup restore uninstall health-check; do
  t "$s.sh has valid syntax"        "bash -n '$ROOT/$s.sh'"
done
t "compose file references all secrets" 'for s in vault_key db_password mssql_sa_password; do grep -q "./secrets/$s" "$ROOT/deploy/docker-compose.yml" || exit 1; done'
echo; [[ $FAILS == 0 ]] && echo "All installer helper tests passed" || { echo "$FAILS failure(s)"; exit 1; }
