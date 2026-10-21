#!/usr/bin/env bash
# php2shell-update.sh
# Aggiorna PHP alle versioni che correggono CVE-2026-109618 / CVE-2026-109619
# e riavvia PHP-FPM e i processi gestiti da supervisor (Horizon, Reverb, code, Octane).
# Uso: sudo bash php2shell-update.sh
# Non installa versioni nuove: aggiorna solo i pacchetti PHP gia' presenti.
# Mantiene i php.ini esistenti (--force-confold).

set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Lancia lo script come root: sudo bash $0"
  exit 1
fi

# Versioni minime corrette (advisory php.net del 21/10/2026)
declare -A FIXED=( [8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12 )

STATUS=0
echo "===== $(hostname) - $(date '+%F %T %Z') ====="

VERSIONS=$(ls /etc/php 2>/dev/null | grep -E '^[0-9]+\.[0-9]+$' | sort -V)
if [ -z "$VERSIONS" ]; then
  echo "Nessuna installazione PHP trovata in /etc/php"
  exit 1
fi
echo "Versioni PHP installate: $(echo $VERSIONS)"

echo
echo "## 1. Aggiornamento indice pacchetti"
if ! apt-get update -qq; then
  echo "ERRORE: apt-get update fallito"
  exit 1
fi

PKGS=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'php*' 2>/dev/null \
  | awk '$1=="ii" && $2 ~ /^php([0-9]+\.[0-9]+(-.*)?|-common)$/ {print $2}')

echo
echo "## 2. Aggiornamento pacchetti PHP"
if [ -n "$PKGS" ]; then
  DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y \
    -o Dpkg::Options::=--force-confold $PKGS
else
  echo "Nessun pacchetto PHP da aggiornare trovato"
fi

echo
echo "## 3. Riavvio PHP-FPM"
for v in $VERSIONS; do
  if systemctl list-unit-files "php$v-fpm.service" 2>/dev/null | grep -q "php$v-fpm"; then
    if systemctl restart "php$v-fpm"; then
      echo "php$v-fpm riavviato"
    else
      echo "ERRORE: riavvio di php$v-fpm fallito"
      STATUS=1
    fi
  fi
done

echo
echo "## 4. Riavvio processi supervisor (Horizon, Reverb, code, Octane...)"
if command -v supervisorctl >/dev/null 2>&1; then
  supervisorctl restart all
else
  echo "supervisor non presente, salto"
fi

echo
echo "## 5. Verifica versioni"
for v in $VERSIONS; do
  want="${FIXED[$v]:-}"
  if [ -z "$want" ]; then
    echo "KO    PHP $v: ramo senza patch ufficiale, va migrato a 8.2 o superiore"
    STATUS=1
    continue
  fi
  for bin in "php$v" "php-fpm$v"; do
    command -v "$bin" >/dev/null 2>&1 || continue
    have=$("$bin" -v 2>/dev/null | head -1 | awk '{print $2}' | cut -d- -f1)
    if dpkg --compare-versions "$have" ge "$want"; then
      echo "OK    $bin $have"
    else
      echo "KO    $bin $have (serve almeno $want)"
      STATUS=1
    fi
  done
done

echo
echo "## 6. Processi PHP ancora sul binario vecchio"
OLD=""
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$exe" in
    *php*"(deleted)")
      cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-120)
      OLD="${OLD}PID $(basename "$p"): $cmd"$'\n'
      ;;
  esac
done
if [ -n "$OLD" ]; then
  echo "KO    Questi processi usano ancora il PHP vecchio, vanno riavviati:"
  printf '%s' "$OLD"
  STATUS=1
else
  echo "OK    Nessun processo PHP sul binario vecchio"
fi

echo
if [ "$STATUS" -eq 0 ]; then
  echo "===== $(hostname): AGGIORNATO ====="
else
  echo "===== $(hostname): CONTROLLA LE RIGHE KO ====="
fi
exit "$STATUS"