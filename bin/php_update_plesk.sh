#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# php_update_plesk.sh
# Aggiorna PHP alle versioni che correggono CVE-2026-109618 / CVE-2026-109619
# su server gestiti da Plesk Obsidian.
#
# Uso:
#   sudo bash php_update_plesk.sh                  # aggiorna + riavvia
#   sudo bash php_update_plesk.sh --check           # solo verifica, non modifica nulla
#   sudo bash php_update_plesk.sh --dry-run         # mostra cosa farebbe senza eseguire
#
# Plesk gestisce PHP tramite il proprio installer (plesk installer),
# NON tramite apt-get/yum direttamente. Questo script usa:
#   - plesk installer update              → aggiorna il catalogo
#   - plesk installer --select-release-current --install-component phpX.Y
#                                          → installa/aggiorna la versione
#
# PHP è installato in /opt/plesk/php/<versione>/
# I servizi FPM si chiamano plesk-php<XY>-fpm
#
# Basato su: https://github.com/giagara/php-cves-labs/blob/main/bin/php_update.sh
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYA='\033[0;36m'; RST='\033[0m'

# ── Argomenti ────────────────────────────────────────────────────────────────
MODE="update"  # update | check | dry-run
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)    MODE="check";   shift ;;
    --dry-run)  MODE="dry-run"; shift ;;
    -h|--help)
      echo "Uso: sudo bash $0 [--check | --dry-run]"
      echo ""
      echo "  (nessuna opzione)  Aggiorna PHP e riavvia i servizi"
      echo "  --check            Solo verifica versioni, nessuna modifica"
      echo "  --dry-run          Mostra cosa farebbe senza eseguire"
      exit 0
      ;;
    *) echo "Opzione sconosciuta: $1"; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo -e "${RED}Lancia lo script come root: sudo bash $0${RST}"
  exit 1
fi

# ── Versioni minime corrette (advisory php.net 21/10/2026) ───────────────────
declare -A FIXED=(
  [7.1]="EOL"
  [7.2]="EOL"
  [7.3]="EOL"
  [7.4]="EOL"
  [8.0]="EOL"
  [8.1]="EOL"
  [8.2]="8.2.35"
  [8.3]="8.3.36"
  [8.4]="8.4.27"
  [8.5]="8.5.12"
)

STATUS=0

echo -e "${CYA}═══════════════════════════════════════════════════════════════${RST}"
echo -e "${CYA}  CVE-2026-109618/619 — Aggiornamento PHP per Plesk${RST}"
echo -e "${CYA}  $(hostname) — $(date '+%F %T %Z')${RST}"
echo -e "${CYA}  Modalità: ${MODE}${RST}"
echo -e "${CYA}═══════════════════════════════════════════════════════════════${RST}"
echo ""

# ── Detect Plesk ─────────────────────────────────────────────────────────────
if ! command -v plesk &>/dev/null; then
  echo -e "${RED}ERRORE: comando 'plesk' non trovato — questo script è per server Plesk.${RST}"
  echo "Per server non-Plesk (Debian/Ubuntu standard) usa php_update.sh"
  exit 1
fi

if [[ ! -d /opt/plesk/php ]]; then
  echo -e "${RED}ERRORE: /opt/plesk/php non trovato — nessun PHP installato tramite Plesk.${RST}"
  exit 1
fi

# ── Verifica che Plesk Installer non sia già in esecuzione ───────────────────
if plesk installer --query-status 2>/dev/null | grep -qi "running"; then
  echo -e "${RED}ERRORE: Plesk Installer è già in esecuzione.${RST}"
  echo "Attendi il completamento o controlla con: plesk installer --query-status"
  exit 1
fi
echo -e "${GRN}Plesk Installer: disponibile${RST}"
echo ""

# ── Rileva versioni installate ───────────────────────────────────────────────
VERSIONS=$(ls /opt/plesk/php/ 2>/dev/null | grep -E '^[0-9]+\.[0-9]+$' | sort -V)
if [[ -z "$VERSIONS" ]]; then
  echo -e "${RED}Nessuna installazione PHP trovata in /opt/plesk/php/${RST}"
  exit 1
fi
echo -e "Versioni PHP Plesk installate: ${CYA}$(echo $VERSIONS | tr '\n' ' ')${RST}"
echo ""

# ── Rileva stato catalogo Plesk ──────────────────────────────────────────────
echo -e "${CYA}── Stato catalogo Plesk ──${RST}"
CATALOG=$(plesk installer --select-release-current --show-components 2>/dev/null | grep -i 'php')
if [[ -n "$CATALOG" ]]; then
  echo "$CATALOG" | while read -r line; do
    if echo "$line" | grep -q '\[upgrade\]'; then
      echo -e "  ${YEL}$line${RST}"
    elif echo "$line" | grep -q '\[up2date\]'; then
      echo -e "  ${GRN}$line${RST}"
    else
      echo -e "  $line"
    fi
  done
else
  echo -e "  ${YEL}Impossibile leggere il catalogo Plesk${RST}"
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Verifica versioni attuali (pre-update)
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}── 1. Stato attuale ──${RST}"

declare -A CURRENT_VER=()
declare -A NEEDS_UPDATE=()

for v in $VERSIONS; do
  BIN="/opt/plesk/php/$v/bin/php"
  if [[ -x "$BIN" ]]; then
    have=$("$BIN" -v 2>/dev/null | head -1 | awk '{print $2}' | cut -d- -f1)
    CURRENT_VER[$v]="$have"
    want="${FIXED[$v]:-}"

    if [[ "$want" == "EOL" ]]; then
      echo -e "  ${RED}[EOL]${RST}  PHP $v ($have) — end-of-life, nessun fix ufficiale"
      echo -e "         ${YEL}→ Mitigazione: session.upload_progress.enabled = Off${RST}"
      echo -e "         ${YEL}→ Piano: migrare a PHP 8.2+${RST}"
      STATUS=1
      NEEDS_UPDATE[$v]="eol"
    elif [[ -z "$want" ]]; then
      echo -e "  ${YEL}[???]${RST}  PHP $v ($have) — versione non in tabella, verificare manualmente"
      STATUS=1
      NEEDS_UPDATE[$v]="unknown"
    else
      if printf '%s\n%s\n' "$want" "$have" | sort -V -C; then
        echo -e "  ${GRN}[OK]${RST}   PHP $v ($have) — già patchato (>= $want)"
        NEEDS_UPDATE[$v]="no"
      else
        echo -e "  ${RED}[KO]${RST}   PHP $v ($have) — serve almeno $want"
        NEEDS_UPDATE[$v]="yes"
        STATUS=1
      fi
    fi
  else
    echo -e "  ${YEL}[???]${RST}  PHP $v — binario non trovato in /opt/plesk/php/$v/bin/php"
  fi
done
echo ""

if [[ "$MODE" == "check" ]]; then
  echo -e "${CYA}═══════════════════════════════════════════════════════════════${RST}"
  if [[ "$STATUS" -eq 0 ]]; then
    echo -e "${GRN}  Tutte le versioni PHP sono patchate.${RST}"
  else
    echo -e "${YEL}  Alcune versioni richiedono aggiornamento (vedi sopra).${RST}"
  fi
  echo -e "${CYA}═══════════════════════════════════════════════════════════════${RST}"
  exit "$STATUS"
fi

# Controlla se c'è qualcosa da aggiornare
ANY_UPDATE="no"
for v in "${!NEEDS_UPDATE[@]}"; do
  [[ "${NEEDS_UPDATE[$v]}" == "yes" ]] && ANY_UPDATE="yes"
done

if [[ "$ANY_UPDATE" == "no" ]]; then
  echo -e "${GRN}Tutte le versioni PHP supportate sono già patchate. Niente da aggiornare.${RST}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Aggiornamento catalogo Plesk Installer
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}── 2. Aggiornamento catalogo Plesk Installer ──${RST}"

if [[ "$MODE" == "dry-run" ]]; then
  echo -e "  ${YEL}[DRY-RUN] plesk installer update${RST}"
else
  if plesk installer update 2>&1 | tail -5; then
    echo -e "  ${GRN}Catalogo aggiornato${RST}"
  else
    echo -e "  ${YEL}ATTENZIONE: aggiornamento catalogo potrebbe essere fallito${RST}"
    echo -e "  ${YEL}Proseguo comunque con l'installazione...${RST}"
  fi
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Aggiornamento PHP tramite Plesk Installer
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}── 3. Aggiornamento PHP tramite Plesk Installer ──${RST}"

COMPONENTS_TO_UPGRADE=""
for v in $VERSIONS; do
  [[ "${NEEDS_UPDATE[$v]:-}" != "yes" ]] && continue

  COMPONENT="php${v}"

  if echo "$CATALOG" | grep -qi "${COMPONENT}.*\[upgrade\]"; then
    echo -e "  ${CYA}PHP $v: upgrade disponibile nel catalogo Plesk${RST}"
  else
    echo -e "  ${YEL}PHP $v: [upgrade] non trovato nel catalogo — provo comunque${RST}"
  fi
  COMPONENTS_TO_UPGRADE="${COMPONENTS_TO_UPGRADE} --install-component ${COMPONENT}"
done

if [[ -z "$COMPONENTS_TO_UPGRADE" ]]; then
  echo -e "  ${GRN}Nessun componente da aggiornare${RST}"
else
  CMD="plesk installer --select-release-current${COMPONENTS_TO_UPGRADE}"

  if [[ "$MODE" == "dry-run" ]]; then
    echo -e "  ${YEL}[DRY-RUN] $CMD${RST}"
  else
    echo -e "  Eseguo: ${CYA}$CMD${RST}"
    echo ""
    if eval "$CMD" 2>&1; then
      echo ""
      echo -e "  ${GRN}Aggiornamento Plesk completato${RST}"
    else
      echo ""
      echo -e "  ${RED}ERRORE: Plesk Installer ha restituito un errore${RST}"
      echo -e "  ${YEL}Controlla il log: /var/log/plesk/install/autoinstaller3.log${RST}"
      STATUS=1
    fi
  fi
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Riavvio PHP-FPM (servizi Plesk)
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}── 4. Riavvio PHP-FPM Plesk ──${RST}"

for v in $VERSIONS; do
  VER_SHORT=$(echo "$v" | tr -d '.')
  SVC="plesk-php${VER_SHORT}-fpm"

  if systemctl list-unit-files "${SVC}.service" &>/dev/null \
     && systemctl list-unit-files "${SVC}.service" | grep -q "$SVC"; then
    if [[ "$MODE" == "dry-run" ]]; then
      echo -e "  ${YEL}[DRY-RUN] systemctl restart $SVC${RST}"
    else
      if systemctl restart "$SVC" 2>/dev/null; then
        echo -e "  ${GRN}$SVC riavviato${RST}"
      else
        echo -e "  ${RED}ERRORE: riavvio di $SVC fallito${RST}"
        STATUS=1
      fi
    fi
  else
    echo -e "  ${YEL}PHP $v: servizio $SVC non trovato (potrebbe non essere attivo)${RST}"
  fi
done
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Riavvio web server (Apache/nginx)
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}── 5. Riavvio web server ──${RST}"

for svc in apache2 httpd nginx; do
  if systemctl is-active "$svc" &>/dev/null; then
    if [[ "$MODE" == "dry-run" ]]; then
      echo -e "  ${YEL}[DRY-RUN] systemctl reload $svc${RST}"
    else
      if systemctl reload "$svc" 2>/dev/null || systemctl restart "$svc"; then
        echo -e "  ${GRN}$svc ricaricato${RST}"
      else
        echo -e "  ${RED}ERRORE: ricaricamento di $svc fallito${RST}"
        STATUS=1
      fi
    fi
  fi
done
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Riavvio supervisor (Horizon, Reverb, code, Octane...)
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}── 6. Riavvio processi supervisor ──${RST}"

if command -v supervisorctl &>/dev/null; then
  if [[ "$MODE" == "dry-run" ]]; then
    echo -e "  ${YEL}[DRY-RUN] supervisorctl restart all${RST}"
  else
    supervisorctl restart all 2>&1 | while read -r line; do
      echo "  $line"
    done
  fi
else
  echo -e "  supervisor non presente, salto"
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — Verifica versioni (post-update)
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}── 7. Verifica versioni post-aggiornamento ──${RST}"

FINAL_STATUS=0
for v in $VERSIONS; do
  want="${FIXED[$v]:-}"

  BIN="/opt/plesk/php/$v/bin/php"
  if [[ -x "$BIN" ]]; then
    have=$("$BIN" -v 2>/dev/null | head -1 | awk '{print $2}' | cut -d- -f1)

    if [[ "$want" == "EOL" ]]; then
      echo -e "  ${RED}[EOL]${RST}  $BIN $have — end-of-life, disabilitare upload_progress"
      FINAL_STATUS=1
    elif [[ -z "$want" ]]; then
      echo -e "  ${YEL}[???]${RST}  $BIN $have — verifica manuale"
      FINAL_STATUS=1
    elif printf '%s\n%s\n' "$want" "$have" | sort -V -C; then
      echo -e "  ${GRN}[OK]${RST}   $BIN $have (>= $want)"
    else
      echo -e "  ${RED}[KO]${RST}   $BIN $have (serve almeno $want)"
      FINAL_STATUS=1
    fi
  fi

  FPM="/opt/plesk/php/$v/sbin/php-fpm"
  if [[ -x "$FPM" ]]; then
    have=$("$FPM" -v 2>/dev/null | head -1 | awk '{print $2}' | cut -d- -f1)
    if [[ -n "$want" && "$want" != "EOL" ]]; then
      if printf '%s\n%s\n' "$want" "$have" | sort -V -C; then
        echo -e "  ${GRN}[OK]${RST}   $FPM $have"
      else
        echo -e "  ${RED}[KO]${RST}   $FPM $have (serve almeno $want)"
        FINAL_STATUS=1
      fi
    fi
  fi
done
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 8 — Processi PHP ancora sul binario vecchio
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}── 8. Processi PHP su binario vecchio ──${RST}"

OLD=""
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$exe" in
    *php*"(deleted)")
      cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-120)
      pid=$(basename "$p")
      OLD="${OLD}  PID $pid: $cmd"$'\n'
      ;;
  esac
done

if [[ -n "$OLD" ]]; then
  echo -e "  ${RED}Questi processi usano ancora il binario PHP vecchio:${RST}"
  printf '%s' "$OLD"
  echo -e "  ${YEL}→ Riavviarli manualmente o aspettare il prossimo restart${RST}"
  FINAL_STATUS=1
else
  echo -e "  ${GRN}OK — Nessun processo PHP sul binario vecchio${RST}"
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# STEP 9 — Verifica mitigazione per versioni EOL
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}── 9. Mitigazione versioni EOL ──${RST}"

EOL_FOUND=0
for v in $VERSIONS; do
  want="${FIXED[$v]:-}"
  [[ "$want" != "EOL" ]] && continue

  EOL_FOUND=1
  INI="/opt/plesk/php/$v/etc/php.ini"
  CONFDIR="/opt/plesk/php/$v/etc/php.d"

  UP_ENABLED="unknown"
  for f in "$INI" "$CONFDIR"/*.ini; do
    [[ -f "$f" ]] || continue
    val=$(grep -iE '^\s*session\.upload_progress\.enabled\s*=' "$f" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
    [[ -n "$val" ]] && UP_ENABLED="$val"
  done

  if [[ "$UP_ENABLED" == "0" || "$UP_ENABLED" == "Off" || "$UP_ENABLED" == "off" ]]; then
    echo -e "  ${GRN}[OK]${RST}   PHP $v (EOL): upload_progress.enabled = Off"
  else
    echo -e "  ${RED}[KO]${RST}   PHP $v (EOL): upload_progress.enabled = $UP_ENABLED"
    echo -e "         ${YEL}Aggiungi a $INI:${RST}"
    echo -e "         ${YEL}  session.upload_progress.enabled = Off${RST}"
    echo -e "         ${YEL}  session.use_only_cookies = On${RST}"
    FINAL_STATUS=1
  fi
done

if [[ "$EOL_FOUND" -eq 0 ]]; then
  echo -e "  ${GRN}Nessuna versione PHP EOL installata${RST}"
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# VERDETTO FINALE
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${CYA}═══════════════════════════════════════════════════════════════${RST}"
if [[ "$FINAL_STATUS" -eq 0 && "$STATUS" -eq 0 ]]; then
  echo -e "${GRN}  $(hostname): AGGIORNATO — tutte le versioni PHP sono patchate${RST}"
elif [[ "$MODE" == "dry-run" ]]; then
  echo -e "${YEL}  $(hostname): DRY-RUN completato — nessuna modifica effettuata${RST}"
else
  echo -e "${RED}  $(hostname): CONTROLLA LE RIGHE KO SOPRA${RST}"
fi
echo -e "${CYA}═══════════════════════════════════════════════════════════════${RST}"
echo ""
echo -e "Log Plesk Installer: ${CYA}/var/log/plesk/install/autoinstaller3.log${RST}"

exit $(( STATUS | FINAL_STATUS ))
