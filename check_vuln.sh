#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# check_vuln.sh — CVE-2026-109618 / CVE-2026-109619 exposure check
# PHP session.upload_progress UAF → RCE (CVSS 9.2)
#
# Uso:  bash check_vuln.sh           (read-only, non modifica nulla)
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYA='\033[0;36m'; RST='\033[0m'

echo -e "${CYA}═══════════════════════════════════════════════════════════${RST}"
echo -e "${CYA}  CVE-2026-109618/619 — PHP upload_progress UAF checker${RST}"
echo -e "${CYA}═══════════════════════════════════════════════════════════${RST}"
echo ""
echo -e "Host:     $(hostname -f 2>/dev/null || hostname)"
echo -e "Data:     $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo -e "Kernel:   $(uname -srm)"
echo ""

# ── Trova tutti i binari PHP presenti ────────────────────────────────
PHP_BINS=()

for p in \
  /usr/bin/php /usr/local/bin/php /usr/bin/php8.* /usr/bin/php7.* \
  /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php \
  /opt/cpanel/ea-php*/root/usr/bin/php \
  /opt/plesk/php/*/bin/php \
  /opt/remi/php*/root/usr/bin/php \
  /opt/homebrew/bin/php
do
  for f in $p; do
    [ -x "$f" ] 2>/dev/null && PHP_BINS+=("$f")
  done
done

command -v php &>/dev/null && PHP_BINS+=("$(command -v php)")

# Deduplica per realpath (compatibile bash 3)
UNIQUE_BINS=()
_SEEN_LIST=""
for b in "${PHP_BINS[@]}"; do
  rp="$(realpath "$b" 2>/dev/null || echo "$b")"
  case "$_SEEN_LIST" in
    *"|${rp}|"*) ;;  # già visto
    *)
      _SEEN_LIST="${_SEEN_LIST}|${rp}|"
      UNIQUE_BINS+=("$b")
      ;;
  esac
done

if [[ ${#UNIQUE_BINS[@]} -eq 0 ]]; then
  echo -e "${GRN}[OK] Nessun binario PHP trovato su questo server.${RST}"
  exit 0
fi

# ── Versioni patchate (aggiornare appena i fix escono) ───────────────
PATCHED_84="8.4.20"
PATCHED_83="8.3.25"
PATCHED_82="8.2.35"

version_gte() {
  printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

VULN_COUNT=0
SAFE_COUNT=0

for PHP in "${UNIQUE_BINS[@]}"; do
  echo -e "${CYA}───────────────────────────────────────────────────────${RST}"
  echo -e "Binario:  ${PHP}"

  # Verifica che il binario supporti -r (php-fpm non lo supporta)
  if ! "$PHP" -r 'echo "OK";' 2>/dev/null | grep -q '^OK$'; then
    echo -e "  ${YEL}(saltato — il binario non supporta -r, probabilmente php-fpm)${RST}"
    continue
  fi

  VER_FULL=$("$PHP" -v 2>/dev/null | head -1 || echo "N/A")
  echo -e "Versione: ${VER_FULL}"

  VER=$("$PHP" -r 'echo PHP_VERSION;' 2>/dev/null || echo "0.0.0")
  MAJOR=$("$PHP" -r 'echo PHP_MAJOR_VERSION;' 2>/dev/null || echo "0")
  MINOR=$("$PHP" -r 'echo PHP_MINOR_VERSION;' 2>/dev/null || echo "0")
  SAPI=$("$PHP" -r 'echo php_sapi_name();' 2>/dev/null || echo "unknown")
  echo -e "SAPI:     ${SAPI}"

  UP_ENABLED=$("$PHP" -r "echo ini_get('session.upload_progress.enabled');" 2>/dev/null || echo "?")
  UP_FREQ=$("$PHP" -r "echo ini_get('session.upload_progress.freq');" 2>/dev/null || echo "?")
  UP_MINFREQ=$("$PHP" -r "echo ini_get('session.upload_progress.min_freq');" 2>/dev/null || echo "?")
  UP_CLEANUP=$("$PHP" -r "echo ini_get('session.upload_progress.cleanup');" 2>/dev/null || echo "?")

  echo -e "upload_progress.enabled  = ${UP_ENABLED}"
  echo -e "upload_progress.freq     = ${UP_FREQ}"
  echo -e "upload_progress.min_freq = ${UP_MINFREQ}"
  echo -e "upload_progress.cleanup  = ${UP_CLEANUP}"

  # ── Verdetto ──
  VULN="no"
  REASON=""

  if [[ "$MAJOR" -le 7 ]]; then
    VULN="yes"
    REASON="PHP ${VER} è EOL — nessun patch disponibile"
  elif [[ "$MAJOR" -eq 8 ]]; then
    case "$MINOR" in
      4) version_gte "$VER" "$PATCHED_84" && { VULN="no"; REASON="PHP ${VER} >= ${PATCHED_84} (patchato)"; } \
                                           || { VULN="yes"; REASON="PHP ${VER} < ${PATCHED_84}"; } ;;
      3) version_gte "$VER" "$PATCHED_83" && { VULN="no"; REASON="PHP ${VER} >= ${PATCHED_83} (patchato)"; } \
                                           || { VULN="yes"; REASON="PHP ${VER} < ${PATCHED_83}"; } ;;
      2) version_gte "$VER" "$PATCHED_82" && { VULN="no"; REASON="PHP ${VER} >= ${PATCHED_82} (patchato)"; } \
                                           || { VULN="yes"; REASON="PHP ${VER} < ${PATCHED_82}"; } ;;
      *) VULN="yes"; REASON="PHP 8.${MINOR} — verifica manualmente se il patch esiste" ;;
    esac
  else
    VULN="unknown"; REASON="PHP ${VER} — versione futura, verifica manuale"
  fi

  if [[ "$UP_ENABLED" == "" || "$UP_ENABLED" == "0" ]]; then
    if [[ "$VULN" == "yes" ]]; then
      VULN="mitigato"
      REASON="${REASON}, MA upload_progress.enabled = OFF (vettore chiuso)"
    fi
  fi

  echo ""
  case "$VULN" in
    yes)
      echo -e "  ${RED}▶ VULNERABILE${RST}  ${REASON}"
      echo -e "  ${RED}  upload_progress.enabled = ON → vettore raggiungibile via qualsiasi endpoint POST${RST}"
      ((VULN_COUNT++)) || true
      ;;
    mitigato)
      echo -e "  ${YEL}▶ CODICE VULNERABILE MA MITIGATO${RST}  ${REASON}"
      ((SAFE_COUNT++)) || true
      ;;
    no)
      echo -e "  ${GRN}▶ PATCHATO${RST}  ${REASON}"
      ((SAFE_COUNT++)) || true
      ;;
    *)
      echo -e "  ${YEL}▶ VERIFICA MANUALE${RST}  ${REASON}"
      ;;
  esac
done

# ── Processi PHP attivi ──────────────────────────────────────────────
echo ""
echo -e "${CYA}───────────────────────────────────────────────────────────${RST}"
echo -e "Processi PHP/lsphp attivi:"
ps aux 2>/dev/null | grep -E '[p]hp-fpm|[l]sphp|[p]hp-cgi' | head -10 || echo "  (nessuno)"

# ── Porte web ────────────────────────────────────────────────────────
echo ""
echo -e "Porte web in ascolto (80/443/8080):"
(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E ':80\b|:443\b|:8080\b' | head -10 || echo "  (nessuna)"

# ── Riepilogo ────────────────────────────────────────────────────────
echo ""
echo -e "${CYA}═══════════════════════════════════════════════════════════${RST}"
if [[ $VULN_COUNT -gt 0 ]]; then
  echo -e "${RED}  ESITO: ${VULN_COUNT} installazione/i PHP VULNERABILE/I${RST}"
  echo ""
  echo -e "  Rimedi:"
  echo -e "  1. Aggiornare PHP alla versione patchata"
  echo -e "  2. Mitigazione immediata — aggiungere in php.ini:"
  echo -e "     ${YEL}session.upload_progress.enabled = 0${RST}"
  echo -e "     poi: systemctl restart php*-fpm  (o lsws / apache)"
  echo -e "  3. WAF: bloccare POST con campo PHP_SESSION_UPLOAD_PROGRESS"
else
  echo -e "${GRN}  ESITO: nessuna installazione PHP vulnerabile trovata${RST}"
fi
echo -e "${CYA}═══════════════════════════════════════════════════════════${RST}"
