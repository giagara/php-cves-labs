#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# mitigate_apache.sh — CVE-2026-109618/619 Apache mitigation
# Blocca tutti i POST multipart/form-data a livello Apache (mod_rewrite)
# Basato su: https://github.com/syhunt/php2shell-protection
#
# Uso:  bash mitigate_apache.sh --check   (solo verifica)
#       sudo bash mitigate_apache.sh       (applica + testa)
#       sudo bash mitigate_apache.sh --remove  (rimuove)
# ─────────────────────────────────────────────────────────────────────
set -eu

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; CYA='\033[0;36m'; RST='\033[0m'

TAG_START="# >>> CVE-2026-109618/619 MITIGATION >>>"
TAG_END="# <<< CVE-2026-109618/619 MITIGATION <<<"

ACTION="${1:-apply}"

# ── Trova i .htaccess da gestire ─────────────────────────────────────
collect_targets() {
  TARGETS_FILE=$(mktemp)

  # Percorsi standard
  for d in /var/www/html /var/www /srv/www/htdocs; do
    [ -d "$d" ] && echo "${d}/.htaccess" >> "$TARGETS_FILE"
  done

  # DocumentRoot dai virtual host Apache
  for confdir in /etc/apache2/sites-enabled /etc/httpd/conf.d; do
    [ -d "$confdir" ] || continue
    for conf in "$confdir"/*.conf; do
      [ -f "$conf" ] || continue
      grep -i '^\s*DocumentRoot' "$conf" 2>/dev/null | while IFS= read -r line; do
        dr=$(echo "$line" | sed 's/^[[:space:]]*DocumentRoot[[:space:]]*//' | tr -d '"' | tr -d "'")
        [ -d "$dr" ] && echo "${dr}/.htaccess"
      done >> "$TARGETS_FILE"
    done
  done

  # Deduplica
  sort -u "$TARGETS_FILE"
  rm -f "$TARGETS_FILE"
}

# ── Verifica mod_rewrite ─────────────────────────────────────────────
check_mod_rewrite() {
  if command -v apache2ctl >/dev/null 2>&1; then
    apache2ctl -M 2>/dev/null | grep -qi rewrite && return 0
  fi
  if command -v httpd >/dev/null 2>&1; then
    httpd -M 2>/dev/null | grep -qi rewrite && return 0
  fi
  if command -v apachectl >/dev/null 2>&1; then
    apachectl -M 2>/dev/null | grep -qi rewrite && return 0
  fi
  return 1
}

# ── La regola da inserire ────────────────────────────────────────────
write_rule() {
  cat <<'ENDRULE'
# >>> CVE-2026-109618/619 MITIGATION >>>
# Blocca POST multipart/form-data - PHP session.upload_progress UAF
# Fonte: https://github.com/syhunt/php2shell-protection
# Rimuovere dopo aggiornamento PHP
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^POST$ [NC]
RewriteCond %{HTTP:Content-Type} ^[[:space:]]*multipart/form-data([;,[:space:]]|$) [NC]
RewriteRule ^ - [F,L]
# <<< CVE-2026-109618/619 MITIGATION <<<
ENDRULE
}

# ── CHECK ────────────────────────────────────────────────────────────
do_check() {
  echo -e "${CYA}═══════════════════════════════════════════════════${RST}"
  echo -e "${CYA}  CVE-2026-109618/619 — Apache mitigation check${RST}"
  echo -e "${CYA}═══════════════════════════════════════════════════${RST}"
  echo ""

  if check_mod_rewrite; then
    echo -e "${GRN}[✓] mod_rewrite attivo${RST}"
  else
    echo -e "${RED}[✗] mod_rewrite NON trovato${RST}"
    echo -e "    ${YEL}sudo a2enmod rewrite && sudo systemctl restart apache2${RST}"
  fi

  FOUND=0
  for htfile in $(collect_targets); do
    if [ -f "$htfile" ] && grep -q "CVE-2026-109618" "$htfile" 2>/dev/null; then
      echo -e "${GRN}[✓] Regola presente: ${htfile}${RST}"
      FOUND=$((FOUND + 1))
    elif [ -f "$htfile" ]; then
      echo -e "${YEL}[-] .htaccess esiste SENZA regola: ${htfile}${RST}"
    else
      echo -e "${YEL}[-] .htaccess non presente: ${htfile}${RST}"
    fi
  done

  [ "$FOUND" -eq 0 ] && echo -e "\n${RED}  Nessuna mitigazione Apache attiva${RST}"

  # Test con curl
  echo ""
  echo -e "Test funzionale (curl):"
  HOST=$(hostname -f 2>/dev/null || hostname)
  for SCHEME in https http; do
    URL="${SCHEME}://${HOST}/"
    RESP=$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
      -H "Content-Type: multipart/form-data; boundary=test" \
      --data-binary "$(printf -- '--test\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\ny\r\n--test--\r\n')" \
      "$URL" 2>/dev/null || echo "ERR")
    if [ "$RESP" = "403" ]; then
      echo -e "  ${GRN}[✓] POST multipart → ${URL} → 403 BLOCCATO${RST}"
    elif [ "$RESP" = "ERR" ]; then
      echo -e "  ${YEL}[-] ${URL} non raggiungibile${RST}"
    else
      echo -e "  ${RED}[✗] POST multipart → ${URL} → HTTP ${RESP} (passa!)${RST}"
    fi
  done
}

# ── APPLY ────────────────────────────────────────────────────────────
do_apply() {
  echo -e "${CYA}═══════════════════════════════════════════════════${RST}"
  echo -e "${CYA}  CVE-2026-109618/619 — Applicazione regola Apache${RST}"
  echo -e "${CYA}═══════════════════════════════════════════════════${RST}"
  echo ""

  if ! check_mod_rewrite; then
    echo -e "${YEL}[!] mod_rewrite non trovato, provo ad attivarlo...${RST}"
    if command -v a2enmod >/dev/null 2>&1; then
      a2enmod rewrite 2>/dev/null && echo -e "${GRN}    attivato${RST}"
    else
      echo -e "${RED}[!] Attiva mod_rewrite manualmente e rilancia${RST}"
    fi
  fi

  APPLIED=0
  for htfile in $(collect_targets); do
    # Già presente?
    if [ -f "$htfile" ] && grep -q "CVE-2026-109618" "$htfile" 2>/dev/null; then
      echo -e "${GRN}[✓] Già presente: ${htfile}${RST}"
      APPLIED=$((APPLIED + 1))
      continue
    fi

    DIR=$(dirname "$htfile")
    [ ! -d "$DIR" ] && continue

    # Backup
    if [ -f "$htfile" ]; then
      cp "$htfile" "${htfile}.bak.$(date +%Y%m%d%H%M%S)"
      echo -e "${CYA}[~] Backup: ${htfile}.bak.*${RST}"
    fi

    # Inserisci regola IN CIMA
    TMPFILE=$(mktemp)
    write_rule > "$TMPFILE"
    echo "" >> "$TMPFILE"
    [ -f "$htfile" ] && cat "$htfile" >> "$TMPFILE"
    mv "$TMPFILE" "$htfile"

    echo -e "${GRN}[✓] Regola applicata: ${htfile}${RST}"
    APPLIED=$((APPLIED + 1))
  done

  if [ "$APPLIED" -eq 0 ]; then
    echo -e "${RED}[!] Nessun DocumentRoot trovato.${RST}"
    echo -e "    Copia questa regola nel .htaccess della tua webroot:"
    echo ""
    write_rule
    exit 1
  fi

  echo ""
  echo -e "${CYA}[~] Riavvio Apache...${RST}"
  systemctl restart apache2 2>/dev/null || systemctl restart httpd 2>/dev/null || service apache2 restart 2>/dev/null || service httpd restart 2>/dev/null || true
  echo -e "${GRN}[✓] Fatto${RST}"
  echo ""
  do_check
}

# ── REMOVE ───────────────────────────────────────────────────────────
do_remove() {
  echo -e "${CYA}═══════════════════════════════════════════════════${RST}"
  echo -e "${CYA}  CVE-2026-109618/619 — Rimozione regola Apache${RST}"
  echo -e "${CYA}═══════════════════════════════════════════════════${RST}"
  echo ""

  REMOVED=0
  for htfile in $(collect_targets); do
    if [ -f "$htfile" ] && grep -q "CVE-2026-109618" "$htfile" 2>/dev/null; then
      cp "$htfile" "${htfile}.bak.$(date +%Y%m%d%H%M%S)"
      sed -i "/$TAG_START/,/$TAG_END/d" "$htfile"
      echo -e "${GRN}[✓] Rimossa da: ${htfile}${RST}"
      REMOVED=$((REMOVED + 1))
    fi
  done

  if [ "$REMOVED" -eq 0 ]; then
    echo -e "${YEL}[-] Nessuna regola trovata${RST}"
  else
    systemctl restart apache2 2>/dev/null || systemctl restart httpd 2>/dev/null || true
    echo -e "${GRN}[✓] POST multipart ora passano normalmente${RST}"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────
case "$ACTION" in
  --check)  do_check  ;;
  --remove) do_remove ;;
  *)        do_apply  ;;
esac
