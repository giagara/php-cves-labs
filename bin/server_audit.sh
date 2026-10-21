#!/bin/bash
# ============================================================================
#  CVE-2026-109618/109619 — Server Compromise Audit
#
#  Esegui come root:  sudo bash server_audit.sh [--webroot /var/www] [--log-dir /var/log/nginx]
#
#  Lo script esegue tutti i controlli in read-only, non modifica nulla.
#  Output: report con severity per ogni check e verdetto finale.
# ============================================================================
set -uo pipefail

# ------- colori -------
RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYA='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

# ------- parametri -------
WEBROOT="/var/www"
LOG_DIR=""
DAYS=7
REPORT_FILE=""

usage() {
  echo "Usage: sudo bash $0 [OPTIONS]"
  echo ""
  echo "  --webroot DIR      Webroot da scansionare          (default: /var/www)"
  echo "  --log-dir DIR      Directory log web server        (auto-detect)"
  echo "  --days N           Giorni indietro per file recenti (default: 7)"
  echo "  --report FILE      Salva report su file            (default: stdout)"
  echo "  -h, --help         Mostra questo help"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --webroot)  WEBROOT="$2";      shift 2;;
    --log-dir)  LOG_DIR="$2";      shift 2;;
    --days)     DAYS="$2";         shift 2;;
    --report)   REPORT_FILE="$2";  shift 2;;
    -h|--help)  usage;;
    *)          echo "Opzione sconosciuta: $1"; usage;;
  esac
done

# ------- redirect output se --report -------
if [[ -n "$REPORT_FILE" ]]; then
  exec > >(tee "$REPORT_FILE") 2>&1
fi

# ------- contatori -------
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
INFO=0
EVIDENCE_LINES=()

finding() {
  local sev="$1"; shift
  local msg="$*"
  case "$sev" in
    CRITICAL) CRITICAL=$((CRITICAL+1)); echo -e "  ${RED}[CRITICAL]${RST} $msg";;
    HIGH)     HIGH=$((HIGH+1));       echo -e "  ${YEL}[HIGH]${RST}     $msg";;
    MEDIUM)   MEDIUM=$((MEDIUM+1));   echo -e "  ${YEL}[MEDIUM]${RST}   $msg";;
    LOW)      LOW=$((LOW+1));         echo -e "  ${CYA}[LOW]${RST}      $msg";;
    INFO)     INFO=$((INFO+1));       echo -e "  ${GRN}[INFO]${RST}     $msg";;
  esac
  EVIDENCE_LINES+=("[$sev] $msg")
}

ok() {
  echo -e "  ${GRN}[OK]${RST}       $*"
}

section() {
  echo ""
  echo -e "${BLD}══════════════════════════════════════════════════════════════${RST}"
  echo -e "${BLD}  $*${RST}"
  echo -e "${BLD}══════════════════════════════════════════════════════════════${RST}"
}

# ============================================================================
section "0. SYSTEM INFO"
# ============================================================================
echo -e "  Hostname:   $(hostname -f 2>/dev/null || hostname)"
echo -e "  Date:       $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo -e "  Kernel:     $(uname -r)"
echo -e "  Uptime:     $(uptime -p 2>/dev/null || uptime)"
echo -e "  User:       $(whoami)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo -e "\n  ${RED}ATTENZIONE: non sei root. Alcuni controlli saranno incompleti.${RST}"
  echo -e "  Rilancia con: sudo bash $0"
fi

# ============================================================================
section "1. PHP ENVIRONMENT"
# ============================================================================
PHP_MAJOR=0
if ! command -v php &>/dev/null; then
  finding INFO "PHP CLI non trovato nel PATH — controlla manualmente"
  PHP_VER="unknown"
  SESS_DIR="/tmp"
  UPLOAD_PROGRESS="unknown"
  USE_ONLY_COOKIES="unknown"
else
  PHP_VER=$(php -r 'echo PHP_VERSION;' 2>/dev/null)
  PHP_SAPI=$(php -r 'echo php_sapi_name();' 2>/dev/null)
  SESS_DIR=$(php -r 'echo ini_get("session.save_path") ?: "/tmp";' 2>/dev/null)
  UPLOAD_PROGRESS=$(php -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)
  UPLOAD_CLEANUP=$(php -r 'echo ini_get("session.upload_progress.cleanup");' 2>/dev/null)
  USE_ONLY_COOKIES=$(php -r 'echo ini_get("session.use_only_cookies");' 2>/dev/null)

  echo -e "  PHP Version:              $PHP_VER"
  echo -e "  SAPI:                     $PHP_SAPI"
  echo -e "  session.save_path:        $SESS_DIR"
  echo -e "  upload_progress.enabled:  $UPLOAD_PROGRESS"
  echo -e "  upload_progress.cleanup:  $UPLOAD_CLEANUP"
  echo -e "  use_only_cookies:         $USE_ONLY_COOKIES"

  PHP_MAJOR=$(echo "$PHP_VER" | cut -d. -f1)
  if [[ "$PHP_MAJOR" -ge 8 ]]; then
    finding MEDIUM "PHP $PHP_VER — famiglia 8.x, potenzialmente affetta da CVE-2026-109618/109619"
  else
    ok "PHP $PHP_VER — le CVE UAF (109618/109619) colpiscono PHP 8.x"
    finding LOW "PHP $PHP_VER — versione EOL, aggiornamento consigliato"
  fi

  if [[ "$UPLOAD_PROGRESS" == "1" || "$UPLOAD_PROGRESS" == "On" ]]; then
    finding MEDIUM "upload_progress.enabled = On — superficie di attacco per session injection"
  else
    ok "upload_progress.enabled = Off — vettore injection disabilitato"
  fi

  if [[ "$USE_ONLY_COOKIES" != "1" && "$USE_ONLY_COOKIES" != "On" ]]; then
    finding MEDIUM "use_only_cookies = Off — session fixation via POST body possibile"
  else
    ok "use_only_cookies = On — session fixation via POST bloccata"
  fi
fi

# ============================================================================
section "2. SESSION FILE ANALYSIS — PHP Code Injection"
# ============================================================================
echo -e "  Scanning: $SESS_DIR/sess_*"

SESS_TOTAL=$(find "$SESS_DIR" -maxdepth 1 -name 'sess_*' -type f 2>/dev/null | wc -l)
echo -e "  Sessioni trovate: $SESS_TOTAL"

if [[ "$SESS_TOTAL" -eq 0 ]]; then
  ok "Nessun file di sessione presente"
else
  INJECTED_PHP=$(grep -rl '<?php\|<?=' "$SESS_DIR"/sess_* 2>/dev/null || true)
  INJECTED_FUNCS=$(grep -rl 'system(\|exec(\|passthru(\|shell_exec(\|popen(\|proc_open(\|eval(\|assert(' "$SESS_DIR"/sess_* 2>/dev/null || true)
  INJECTED_B64=$(grep -rl 'base64_decode(' "$SESS_DIR"/sess_* 2>/dev/null || true)
  INJECTED_WRITE=$(grep -rl 'file_put_contents(' "$SESS_DIR"/sess_* 2>/dev/null || true)
  INJECTED_UPLOAD=$(grep -rlP 'upload_progress_.*<\?' "$SESS_DIR"/sess_* 2>/dev/null || true)

  if [[ -n "$INJECTED_PHP" ]]; then
    COUNT=$(echo "$INJECTED_PHP" | wc -l)
    finding CRITICAL "$COUNT file di sessione contengono <?php — injection confermata!"
    echo "$INJECTED_PHP" | head -10 | while read -r f; do
      echo -e "    ${RED}→ $f${RST}"
      grep -oP '.{0,60}<\?php.{0,80}' "$f" 2>/dev/null | head -3 | while read -r line; do
        echo -e "      ${RED}$line${RST}"
      done
    done
  else
    ok "Nessun <?php trovato nei file di sessione"
  fi

  if [[ -n "$INJECTED_FUNCS" ]]; then
    COUNT=$(echo "$INJECTED_FUNCS" | wc -l)
    finding CRITICAL "$COUNT file di sessione contengono funzioni pericolose (system/exec/eval/...)"
    echo "$INJECTED_FUNCS" | head -10 | while read -r f; do
      echo -e "    ${RED}→ $f${RST}"
    done
  fi

  if [[ -n "$INJECTED_B64" ]]; then
    COUNT=$(echo "$INJECTED_B64" | wc -l)
    finding HIGH "$COUNT file di sessione contengono base64_decode() — payload offuscato"
    echo "$INJECTED_B64" | head -5 | while read -r f; do
      echo -e "    ${YEL}→ $f${RST}"
    done
  fi

  if [[ -n "$INJECTED_WRITE" ]]; then
    COUNT=$(echo "$INJECTED_WRITE" | wc -l)
    finding CRITICAL "$COUNT file di sessione contengono file_put_contents() — tentativo scrittura file"
    echo "$INJECTED_WRITE" | head -5 | while read -r f; do
      echo -e "    ${RED}→ $f${RST}"
    done
  fi

  if [[ -n "$INJECTED_UPLOAD" ]]; then
    COUNT=$(echo "$INJECTED_UPLOAD" | wc -l)
    finding CRITICAL "$COUNT file contengono upload_progress_* con codice PHP — exploit CVE-2026-109618"
  fi

  if [[ -z "$INJECTED_PHP" && -z "$INJECTED_FUNCS" ]]; then
    ok "Nessun codice sospetto nei file di sessione"
  fi
fi

# ============================================================================
section "3. LOG ANALYSIS — Attack Patterns"
# ============================================================================

if [[ -z "$LOG_DIR" ]]; then
  for candidate in /var/log/nginx /var/log/apache2 /var/log/httpd; do
    if [[ -d "$candidate" ]]; then
      LOG_DIR="$candidate"
      break
    fi
  done
  if [[ -z "$LOG_DIR" ]] && ls /var/www/vhosts/*/logs/access_log >/dev/null 2>&1; then
    LOG_DIR="/var/www/vhosts/*/logs"
  fi
fi

if [[ -z "$LOG_DIR" ]]; then
  finding LOW "Directory log non trovata — specifica con --log-dir"
else
  echo -e "  Log dir: $LOG_DIR"
  ACCESS_LOGS=$(find $LOG_DIR -maxdepth 1 -name 'access*' -type f 2>/dev/null || true)
  ERROR_LOGS=$(find $LOG_DIR -maxdepth 1 -name 'error*' -type f 2>/dev/null || true)
  if [[ -n "$ACCESS_LOGS" ]]; then
    LOG_COUNT=$(echo "$ACCESS_LOGS" | wc -l | tr -d ' ')
  else
    LOG_COUNT=0
  fi
  echo -e "  Access log files: $LOG_COUNT"

  if [[ "$LOG_COUNT" -eq 0 ]]; then
    finding LOW "Nessun access log trovato in $LOG_DIR"
  fi

  echo ""
  echo -e "  ${BLD}3a. Tentativi LFI${RST}"
  if [[ "$LOG_COUNT" -gt 0 ]]; then
    LFI_HITS=$(grep -rhiE '(page|file|include|view|template|lang|path|doc|load)=.*(sess_|/tmp/|/var/lib/php|\.\.\/|%2e%2e|php://|data://|expect://|zip://)' $ACCESS_LOGS 2>/dev/null | wc -l | tr -d ' ')
  else
    LFI_HITS=0
  fi
  if [[ "$LFI_HITS" -gt 0 ]]; then
    finding HIGH "$LFI_HITS righe con pattern LFI negli access log"
    grep -rhiE '(page|file|include|view|template|lang|path|doc|load)=.*(sess_|/tmp/|/var/lib/php|\.\.\/|%2e%2e|php://|data://)' $ACCESS_LOGS 2>/dev/null | tail -5 | while read -r line; do
      echo -e "    ${YEL}→ ${line:0:200}${RST}"
    done
  else
    ok "Nessun pattern LFI trovato negli access log"
  fi

  echo ""
  echo -e "  ${BLD}3b. Inclusione file di sessione via URL${RST}"
  if [[ "$LOG_COUNT" -gt 0 ]]; then
    SESS_LFI_FILTERED=$(grep -rhi 'sess_' $ACCESS_LOGS 2>/dev/null | grep -vi 'PHPSESSID' 2>/dev/null | wc -l | tr -d ' ')
  else
    SESS_LFI_FILTERED=0
  fi
  if [[ "$SESS_LFI_FILTERED" -gt 0 ]]; then
    finding CRITICAL "$SESS_LFI_FILTERED righe con 'sess_' (non PHPSESSID) — possibile inclusione file di sessione"
    grep -rhi 'sess_' $ACCESS_LOGS 2>/dev/null | grep -vi 'PHPSESSID' | tail -5 | while read -r line; do
      echo -e "    ${RED}→ ${line:0:200}${RST}"
    done
  else
    ok "Nessun tentativo di inclusione session file"
  fi

  echo ""
  echo -e "  ${BLD}3c. Path traversal${RST}"
  if [[ "$LOG_COUNT" -gt 0 ]]; then
    TRAVERSAL=$(grep -rhE '\.\./\.\.|%2e%2e' $ACCESS_LOGS 2>/dev/null | wc -l | tr -d ' ')
  else
    TRAVERSAL=0
  fi
  if [[ "$TRAVERSAL" -gt 0 ]]; then
    finding HIGH "$TRAVERSAL righe con path traversal"
    grep -rhE '\.\./\.\.|%2e%2e' $ACCESS_LOGS 2>/dev/null | tail -3 | while read -r line; do
      echo -e "    ${YEL}→ ${line:0:200}${RST}"
    done
  else
    ok "Nessun path traversal nei log"
  fi

  echo ""
  echo -e "  ${BLD}3d. PHP wrapper abuse${RST}"
  if [[ "$LOG_COUNT" -gt 0 ]]; then
    WRAPPER=$(grep -rhiE 'php://(filter|input)|data://' $ACCESS_LOGS 2>/dev/null | wc -l | tr -d ' ')
  else
    WRAPPER=0
  fi
  if [[ "$WRAPPER" -gt 0 ]]; then
    finding HIGH "$WRAPPER righe con PHP wrapper (php://filter, php://input, data://)"
  else
    ok "Nessun PHP wrapper abuse"
  fi

  echo ""
  echo -e "  ${BLD}3e. POST con body anomalo (> 500KB, heap spray)${RST}"
  if [[ "$LOG_COUNT" -gt 0 ]]; then
    LARGE_POST=$(awk '/POST / && $10 > 500000 {c++} END {print c+0}' $ACCESS_LOGS 2>/dev/null)
    LARGE_POST=${LARGE_POST:-0}
  else
    LARGE_POST=0
  fi
  if [[ "$LARGE_POST" -gt 0 ]]; then
    finding MEDIUM "$LARGE_POST POST con body > 500KB — possibile heap spray"
  else
    ok "Nessun POST con body anomalo"
  fi

  echo ""
  echo -e "  ${BLD}3f. IP con più POST (burst)${RST}"
  if [[ "$LOG_COUNT" -gt 0 ]]; then
    TOP_POSTERS=$(awk '/POST / {print $1}' $ACCESS_LOGS 2>/dev/null | sort | uniq -c | sort -rn | head -5 || true)
    if [[ -n "$TOP_POSTERS" ]]; then
      echo "$TOP_POSTERS" | while read -r count ip; do
        if [[ "$count" -gt 500 ]]; then
          finding MEDIUM "IP $ip ha $count POST — volume anomalo"
        else
          echo -e "    $count POST da $ip"
        fi
      done
    fi
  fi
fi

# ============================================================================
section "4. CRASH ANALYSIS — Segfault / UAF"
# ============================================================================

SEGFAULTS_DMESG=$(dmesg 2>/dev/null | grep -ci 'segfault.*php' || true)
[[ -z "$SEGFAULTS_DMESG" ]] && SEGFAULTS_DMESG=0
SEGFAULTS_SYSLOG=$(grep -rhi 'segfault\|signal 11\|SIGSEGV' /var/log/syslog* /var/log/messages* /var/log/kern.log* 2>/dev/null | wc -l | tr -d ' ')
[[ -z "$SEGFAULTS_SYSLOG" ]] && SEGFAULTS_SYSLOG=0
FPM_CRASHES=$(grep -rhi 'exited on signal\|aborting\|children.*died' /var/log/php*fpm*.log* 2>/dev/null | wc -l | tr -d ' ')
[[ -z "$FPM_CRASHES" ]] && FPM_CRASHES=0

echo -e "  Segfault in dmesg:    $SEGFAULTS_DMESG"
echo -e "  Segfault in syslog:   $SEGFAULTS_SYSLOG"
echo -e "  FPM crash:            $FPM_CRASHES"

TOTAL_CRASHES=$((SEGFAULTS_DMESG + SEGFAULTS_SYSLOG + FPM_CRASHES))
if [[ "$TOTAL_CRASHES" -gt 20 ]]; then
  finding HIGH "$TOTAL_CRASHES crash PHP — possibile tentativo UAF ripetuto"
  dmesg 2>/dev/null | grep -i 'segfault.*php' | tail -5 | while read -r line; do
    echo -e "    ${YEL}→ $line${RST}"
  done
elif [[ "$TOTAL_CRASHES" -gt 5 ]]; then
  finding MEDIUM "$TOTAL_CRASHES crash PHP — anomalo, verificare le date"
elif [[ "$TOTAL_CRASHES" -gt 0 ]]; then
  finding LOW "$TOTAL_CRASHES crash PHP"
else
  ok "Nessun crash PHP trovato"
fi

# ============================================================================
section "5. WEBSHELL SCAN"
# ============================================================================
echo -e "  Scanning: $WEBROOT"

if [[ ! -d "$WEBROOT" ]]; then
  finding LOW "Webroot $WEBROOT non trovata — specifica con --webroot"
else
  ALL_SHELLS=""

  for pattern in 'eval(\$_' 'system(\$_' 'base64_decode(\$_' 'assert(\$_' 'preg_replace.*\/e' 'create_function.*\$_' 'call_user_func.*\$_'; do
    HITS=$(find "$WEBROOT" -name '*.php' -exec grep -l "$pattern" {} \; 2>/dev/null || true)
    [[ -n "$HITS" ]] && ALL_SHELLS="$ALL_SHELLS"$'\n'"$HITS"
  done

  NAMED=$(find "$WEBROOT" -regextype posix-extended -iregex '.*(shell|cmd|backdoor|c99|r57|wso|alfa|b374k|upload_shell|spy|hack)\.php' 2>/dev/null || true)
  [[ -n "$NAMED" ]] && ALL_SHELLS="$ALL_SHELLS"$'\n'"$NAMED"

  ALL_SHELLS=$(echo "$ALL_SHELLS" | sort -u | grep -v '^$' || true)

  if [[ -n "$ALL_SHELLS" ]]; then
    COUNT=$(echo "$ALL_SHELLS" | wc -l)
    finding CRITICAL "$COUNT potenziali webshell trovate!"
    echo "$ALL_SHELLS" | while read -r f; do
      SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo "?")
      MTIME=$(stat -c '%y' "$f" 2>/dev/null || stat -f '%Sm' "$f" 2>/dev/null || echo "?")
      echo -e "    ${RED}→ $f (${SIZE}B, modified: $MTIME)${RST}"
    done
  else
    ok "Nessuna webshell trovata"
  fi
fi

# ============================================================================
section "6. SUSPICIOUS RECENT FILES"
# ============================================================================
echo -e "  Cercando file degli ultimi $DAYS giorni..."

TMP_PHP=$(find /tmp /var/tmp /dev/shm -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) -mtime -"$DAYS" 2>/dev/null || true)
if [[ -n "$TMP_PHP" ]]; then
  COUNT=$(echo "$TMP_PHP" | wc -l)
  finding CRITICAL "$COUNT file PHP in directory temporanee"
  echo "$TMP_PHP" | while read -r f; do
    echo -e "    ${RED}→ $(ls -la "$f" 2>/dev/null)${RST}"
  done
else
  ok "Nessun PHP in /tmp /var/tmp /dev/shm"
fi

SUID_NEW=$(timeout 30 find / -perm -4000 -mtime -"$DAYS" 2>/dev/null | grep -v '/usr/\|/bin/\|/sbin/\|/snap/' || true)
if [[ -n "$SUID_NEW" ]]; then
  COUNT=$(echo "$SUID_NEW" | wc -l)
  finding CRITICAL "$COUNT file SUID nuovi fuori da /usr /bin /sbin"
  echo "$SUID_NEW" | while read -r f; do
    echo -e "    ${RED}→ $(ls -la "$f" 2>/dev/null)${RST}"
  done
else
  ok "Nessun file SUID sospetto"
fi

# ============================================================================
section "7. PROCESSES & NETWORK"
# ============================================================================

echo -e "  ${BLD}7a. Processi PHP sospetti${RST}"
SUSP_PROC=$(ps aux 2>/dev/null | grep -E 'php.*(\ -r\ |eval|base64|system|exec|shell)' | grep -v 'grep\|server_audit' || true)
if [[ -n "$SUSP_PROC" ]]; then
  COUNT=$(echo "$SUSP_PROC" | wc -l)
  finding CRITICAL "$COUNT processi PHP sospetti"
  echo "$SUSP_PROC" | while read -r line; do
    echo -e "    ${RED}→ $line${RST}"
  done
else
  ok "Nessun processo PHP sospetto"
fi

echo ""
echo -e "  ${BLD}7b. Connessioni outbound web services${RST}"
OUTBOUND=$(ss -tnp 2>/dev/null | grep -E 'php|apache|nginx|httpd|www-data|caddy' | grep -v 'LISTEN' || true)
if [[ -n "$OUTBOUND" ]]; then
  COUNT=$(echo "$OUTBOUND" | wc -l)
  finding MEDIUM "$COUNT connessioni outbound da processi web"
  echo "$OUTBOUND" | head -10 | while read -r line; do
    echo -e "    ${YEL}→ $line${RST}"
  done
else
  ok "Nessuna connessione outbound web"
fi

echo ""
echo -e "  ${BLD}7c. Porte C2 comuni in ascolto${RST}"
C2_PORTS=$(ss -tlnp 2>/dev/null | grep -E ':(4444|5555|6666|8888|9001|1234|31337|4443|4445|1337|6667|6697) ' || true)
if [[ -n "$C2_PORTS" ]]; then
  COUNT=$(echo "$C2_PORTS" | wc -l)
  finding HIGH "$COUNT servizi su porte C2 comuni"
  echo "$C2_PORTS" | while read -r line; do
    echo -e "    ${RED}→ $line${RST}"
  done
else
  ok "Nessun servizio su porte C2"
fi

# ============================================================================
section "8. USERS & PERSISTENCE"
# ============================================================================

echo -e "  ${BLD}8a. Utenti con UID 0${RST}"
ROOT_USERS=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null || true)
if [[ -n "$ROOT_USERS" ]]; then
  finding CRITICAL "Utenti con UID 0 oltre root: $ROOT_USERS"
else
  ok "Solo root ha UID 0"
fi

echo ""
echo -e "  ${BLD}8b. Chiavi SSH${RST}"
find /home /root -name authorized_keys -type f 2>/dev/null | while read -r f; do
  KEY_COUNT=$(wc -l < "$f" 2>/dev/null || echo 0)
  MTIME=$(stat -c '%y' "$f" 2>/dev/null || stat -f '%Sm' "$f" 2>/dev/null || echo "?")
  OWNER=$(stat -c '%U' "$f" 2>/dev/null || stat -f '%Su' "$f" 2>/dev/null || echo "?")
  echo -e "    $f — $KEY_COUNT chiavi — owner: $OWNER — modified: $MTIME"
  if [[ "$KEY_COUNT" -gt 5 ]]; then
    finding MEDIUM "$f contiene $KEY_COUNT chiavi — verificare"
  fi
done

echo ""
echo -e "  ${BLD}8c. Crontab sospette${RST}"
CRON_SUSP=0
for u in $(cut -f1 -d: /etc/passwd 2>/dev/null); do
  CRON=$(crontab -l -u "$u" 2>/dev/null | grep -v '^#' | grep -v '^$' || true)
  if [[ -n "$CRON" ]]; then
    echo "$CRON" | while read -r line; do
      if echo "$line" | grep -qiE 'curl.*\||wget.*\||python.*-c|perl.*-e|bash.*-c|nc |ncat |php.*-r|base64|/dev/tcp|mkfifo'; then
        finding HIGH "Crontab sospetta ($u): $line"
        CRON_SUSP=1
      fi
    done
  fi
done
if [[ "$CRON_SUSP" -eq 0 ]]; then
  ok "Nessuna crontab sospetta"
fi

echo ""
echo -e "  ${BLD}8d. Systemd services recenti${RST}"
SVC_NEW=$(find /etc/systemd/system /run/systemd/system -name '*.service' -mtime -"$DAYS" 2>/dev/null | grep -v '/run/systemd/generator' || true)
if [[ -n "$SVC_NEW" ]]; then
  COUNT=$(echo "$SVC_NEW" | wc -l)
  finding MEDIUM "$COUNT servizi systemd nuovi/modificati negli ultimi $DAYS giorni"
  echo "$SVC_NEW" | while read -r f; do
    echo -e "    ${YEL}→ $f${RST}"
  done
else
  ok "Nessun servizio systemd sospetto"
fi

# ============================================================================
section "9. MITIGATION STATUS"
# ============================================================================

echo -e "  ${BLD}Checklist:${RST}"

if [[ "$UPLOAD_PROGRESS" == "0" || "$UPLOAD_PROGRESS" == "Off" || "$UPLOAD_PROGRESS" == "" ]]; then
  echo -e "  ${GRN}[PASS]${RST} upload_progress.enabled = Off"
else
  echo -e "  ${RED}[FAIL]${RST} upload_progress.enabled = On — disabilitare"
fi

if [[ "$USE_ONLY_COOKIES" == "1" || "$USE_ONLY_COOKIES" == "On" ]]; then
  echo -e "  ${GRN}[PASS]${RST} use_only_cookies = On"
else
  echo -e "  ${RED}[FAIL]${RST} use_only_cookies = Off — attivare"
fi

if [[ "$PHP_MAJOR" -ge 8 ]]; then
  echo -e "  ${YEL}[WARN]${RST} PHP $PHP_VER — verificare che la patch CVE-2026-109618/109619 sia applicata"
else
  echo -e "  ${GRN}[INFO]${RST} PHP $PHP_VER — non affetto dalla UAF, ma aggiornare comunque"
fi

# ============================================================================
# VERDETTO FINALE
# ============================================================================
echo ""
echo -e "${BLD}╔════════════════════════════════════════════════════════════════════╗${RST}"
echo -e "${BLD}║                        REPORT FINALE                              ║${RST}"
echo -e "${BLD}╠════════════════════════════════════════════════════════════════════╣${RST}"
printf "${BLD}║${RST}  %-10s %s\n" "CRITICAL:" "$CRITICAL"
printf "${BLD}║${RST}  %-10s %s\n" "HIGH:" "$HIGH"
printf "${BLD}║${RST}  %-10s %s\n" "MEDIUM:" "$MEDIUM"
printf "${BLD}║${RST}  %-10s %s\n" "LOW:" "$LOW"
printf "${BLD}║${RST}  %-10s %s\n" "INFO:" "$INFO"
echo -e "${BLD}╠════════════════════════════════════════════════════════════════════╣${RST}"

if [[ "$CRITICAL" -gt 0 ]]; then
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  ${RED}${BLD}VERDETTO: SERVER PROBABILMENTE COMPROMESSO${RST}                   ${BLD}║${RST}"
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  Trovati $CRITICAL finding CRITICAL.                                       ${BLD}║${RST}"
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  ${RED}Azioni immediate richieste:${RST}                                    ${BLD}║${RST}"
  echo -e "${BLD}║${RST}    1. Isolare il server (bloccare outbound)                    ${BLD}║${RST}"
  echo -e "${BLD}║${RST}    2. NON spegnere — preservare evidenze volatili              ${BLD}║${RST}"
  echo -e "${BLD}║${RST}    3. Dump: ps auxf, ss -tnp, session files, /tmp              ${BLD}║${RST}"
  echo -e "${BLD}║${RST}    4. Contattare incident response                             ${BLD}║${RST}"
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  VERDICT="COMPROMISED"
elif [[ "$HIGH" -gt 0 ]]; then
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  ${YEL}${BLD}VERDETTO: TENTATIVO DI ATTACCO RILEVATO${RST}                      ${BLD}║${RST}"
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  Trovati $HIGH finding HIGH. L'attacco potrebbe non essere         ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  andato a buon fine, ma il server e' stato preso di mira.      ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  Applicare mitigazioni e aumentare il monitoraggio.            ${BLD}║${RST}"
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  VERDICT="ATTACKED"
elif [[ "$MEDIUM" -gt 0 ]]; then
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  ${YEL}${BLD}VERDETTO: SUPERFICIE DI ATTACCO ESPOSTA${RST}                      ${BLD}║${RST}"
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  Nessun attacco confermato, ma la configurazione espone        ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  una superficie di attacco. Hardening consigliato.             ${BLD}║${RST}"
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  VERDICT="EXPOSED"
else
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  ${GRN}${BLD}VERDETTO: NESSUNA COMPROMISSIONE RILEVATA${RST}                    ${BLD}║${RST}"
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  Nessun indicatore di attacco o compromissione.                ${BLD}║${RST}"
  echo -e "${BLD}║${RST}  Mantenere PHP aggiornato e monitorare.                        ${BLD}║${RST}"
  echo -e "${BLD}║${RST}                                                                ${BLD}║${RST}"
  VERDICT="CLEAN"
fi

echo -e "${BLD}╚════════════════════════════════════════════════════════════════════╝${RST}"
echo ""

if [[ ${#EVIDENCE_LINES[@]} -gt 0 ]]; then
  echo -e "${BLD}Evidenze raccolte:${RST}"
  for e in "${EVIDENCE_LINES[@]}"; do
    echo "  $e"
  done
  echo ""
fi

echo "Audit completato: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "Verdetto: $VERDICT"

if [[ -n "$REPORT_FILE" ]]; then
  echo ""
  echo "Report salvato in: $REPORT_FILE"
fi

exit 0
