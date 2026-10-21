# Recon & Incident Detection — CVE-2026-109618 / CVE-2026-109619

Comandi per verificare se i tuoi server PHP hanno subito tentativi di attacco
tramite `session.upload_progress` (UAF / Session Injection + LFI).

Esegui tutto come **root** o con `sudo`.

---

## 0. Informazioni preliminari sul server

```bash
# Versione PHP e SAPI
php -v
php -r "echo php_sapi_name();"

# Configurazione session e upload_progress
php -i | grep -E "session\.(upload_progress|save_path|use_only_cookies|serialize_handler)"

# Path sessioni attivo
php -r "echo ini_get('session.save_path');" && echo

# Moduli caricati (cerca moduli insoliti)
php -m | sort
```

> **Nota**: CVE-2026-109618/109619 (UAF) colpiscono PHP 8.x.
> La Chain A (session injection + LFI) funziona su **qualsiasi** PHP con
> `upload_progress.enabled = On` (default), ma richiede una LFI nell'app.

---

## 1. Analisi file di sessione — Injection PHP nel filename

L'attaccante inietta codice PHP nel campo `filename` di un multipart upload.
Il codice finisce nel file di sessione serializzato dentro `upload_progress_*`.

```bash
# Dove sono le sessioni
SESS_DIR=$(php -r "echo ini_get('session.save_path') ?: '/tmp';")
echo "Session dir: $SESS_DIR"

# Conta sessioni
find "$SESS_DIR" -name 'sess_*' -type f 2>/dev/null | wc -l

# CRITICO: cerca codice PHP dentro i file di sessione
# Un file di sessione legittimo NON contiene mai <?php
grep -rl '<?php' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl '<?=' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl '<?' "$SESS_DIR"/sess_* 2>/dev/null | head -20

# Cerca pattern specifici dell'exploit (payload comuni)
grep -rl 'system(' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl 'exec(' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl 'passthru(' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl 'shell_exec(' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl 'popen(' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl 'proc_open(' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl 'eval(' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl 'base64_decode(' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl 'file_put_contents(' "$SESS_DIR"/sess_* 2>/dev/null
grep -rl 'assert(' "$SESS_DIR"/sess_* 2>/dev/null

# Cerca qualsiasi cosa che sembra codice dentro le sessioni
# (il campo upload_progress contiene il filename, che è il vettore)
grep -rP 'upload_progress_.*<\?' "$SESS_DIR"/sess_* 2>/dev/null

# Mostra il contenuto dei file sospetti (se trovati)
# grep -l '<?php' "$SESS_DIR"/sess_* 2>/dev/null | xargs -I{} sh -c 'echo "=== {} ===" && cat "{}"'
```

**Se trovi anche solo un `<?php` in un file `sess_*`, è un tentativo di injection.**

---

## 2. Analisi access log — Pattern di attacco

### 2a. Multipart upload sospette su endpoint non-upload

```bash
# Adatta LOG_DIR al tuo server
# Apache
LOG_DIR="/var/log/apache2"
# Nginx
# LOG_DIR="/var/log/nginx"
# Plesk
# LOG_DIR="/var/www/vhosts/*/logs"

# POST con multipart su pagine che normalmente non ricevono file upload
# L'attaccante usa PHP_SESSION_UPLOAD_PROGRESS, quindi fa POST multipart
# su qualsiasi endpoint PHP (anche /index.php, /login.php, ecc.)
grep -h "POST.*multipart" "$LOG_DIR"/access*.log* 2>/dev/null | tail -50

# Cerca header PHP_SESSION_UPLOAD_PROGRESS nei log (se loggato)
grep -rhi "PHP_SESSION_UPLOAD_PROGRESS" "$LOG_DIR"/ 2>/dev/null | tail -20
```

### 2b. Tentativi di LFI (file inclusion)

```bash
# Pattern LFI classici nei parametri URL
grep -rhiE '(page|file|include|view|template|lang|path|doc|load)=' "$LOG_DIR"/access*.log* 2>/dev/null \
  | grep -iE '(sess_|/tmp/|/var/lib/php|\.\.\/|%2e%2e|php://|data://|expect://|zip://)' \
  | tail -50

# Tentativi di includere file di sessione via LFI
grep -rhi 'sess_' "$LOG_DIR"/access*.log* 2>/dev/null \
  | grep -vi 'PHPSESSID' \
  | tail -20

# Path traversal
grep -rhE '\.\./\.\.' "$LOG_DIR"/access*.log* 2>/dev/null | tail -20
grep -rhE '%2e%2e' "$LOG_DIR"/access*.log* 2>/dev/null | tail -20

# PHP wrapper abuse (php://filter, php://input, data://)
grep -rhiE 'php://(filter|input)|data://' "$LOG_DIR"/access*.log* 2>/dev/null | tail -20
```

### 2c. Volume anomalo di POST su singolo endpoint

```bash
# L'attacco spray (Chain D) invia ~149 campi per request
# Cerca burst di POST dallo stesso IP su breve finestra temporale
awk '/POST / {print $1}' "$LOG_DIR"/access*.log 2>/dev/null \
  | sort | uniq -c | sort -rn | head -20

# POST con body molto grandi (spray = ~149 * 5120 byte ~ 760KB)
# Se il log registra body size:
awk '/POST / && $10 > 500000 {print $0}' "$LOG_DIR"/access*.log 2>/dev/null | tail -20
```

---

## 3. Analisi error log — Crash e segfault

La Chain D (UAF heap spray) provoca crash di php-fpm/apache worker.

```bash
# Segfault di PHP worker (segnale 11 = SIGSEGV)
grep -rhi 'segfault\|signal 11\|SIGSEGV\|core dump' "$LOG_DIR"/error*.log* 2>/dev/null | tail -20
grep -rhi 'segfault\|signal 11\|SIGSEGV' /var/log/syslog* /var/log/messages* /var/log/kern.log* 2>/dev/null | tail -20

# PHP Fatal error legati a sessioni
grep -rhi 'session\|upload_progress' "$LOG_DIR"/error*.log* /var/log/php*.log* 2>/dev/null | tail -30

# FPM crash log
grep -rhi 'exited on signal\|aborting\|children.*died' /var/log/php*fpm*.log* 2>/dev/null | tail -20

# Dmesg: segfault recenti
dmesg | grep -i 'segfault\|php' | tail -20
```

**Segfault ripetuti di php-fpm in breve tempo = possibile tentativo UAF.**

---

## 4. Indicatori di compromissione (post-exploitation)

Se l'attaccante è riuscito a eseguire codice (Chain A con LFI funzionante):

### 4a. File sospetti scritti di recente

```bash
# File creati/modificati nelle ultime 48 ore in directory tmp/web
find /tmp /var/tmp /dev/shm -type f -mtime -2 -ls 2>/dev/null
find /var/www -name '*.php' -mtime -2 -ls 2>/dev/null | head -30

# Webshell classiche
find /var/www -name '*.php' -exec grep -l 'eval(\$_' {} \; 2>/dev/null
find /var/www -name '*.php' -exec grep -l 'system(\$_' {} \; 2>/dev/null
find /var/www -name '*.php' -exec grep -l 'base64_decode(\$_' {} \; 2>/dev/null
find /var/www -name '*.php' -exec grep -l 'assert(\$_' {} \; 2>/dev/null

# File con nomi sospetti nella webroot
find /var/www -regextype posix-extended \
  -regex '.*(shell|cmd|backdoor|c99|r57|wso|alfa|b374k|mini|micro|tiny)\.php' \
  2>/dev/null

# File SUID creati di recente (escalation)
find / -perm -4000 -mtime -7 -ls 2>/dev/null | grep -v '/usr/\|/bin/'

# Crontab sospette
for u in $(cut -f1 -d: /etc/passwd); do
  crontab -l -u "$u" 2>/dev/null | grep -v '^#' | grep -v '^$' && echo "^^^ user: $u"
done
cat /etc/cron.d/* 2>/dev/null | grep -v '^#'
```

### 4b. Processi e connessioni anomale

```bash
# Processi PHP che non dovrebbero esserci
ps aux | grep -E 'php.*-r|php.*eval|php.*base64' | grep -v grep

# Connessioni in uscita dal web server (reverse shell?)
ss -tnp | grep -E ':80|:443|php|apache|nginx|www-data' | grep -v 'LISTEN'

# Connessioni su porte strane (C2)
ss -tnp | grep -E ':(4444|5555|6666|8888|9001|1234|31337)' 2>/dev/null
```

### 4c. Utenti e accessi

```bash
# Utenti aggiunti di recente
awk -F: '$3>=1000 && $3<65534 {print $1,$3,$7}' /etc/passwd
grep -E ':0:' /etc/passwd | grep -v '^root'

# Login recenti
last -20
lastb -20 2>/dev/null

# Chiavi SSH aggiunte
find /home /root -name authorized_keys -exec ls -la {} \; -exec cat {} \; 2>/dev/null
```

---

## 5. Script one-liner di triage rapido

Copia e incolla questo blocco per un check veloce:

```bash
#!/bin/bash
# Quick triage per CVE-2026-109618/109619
echo "=== PHP VERSION ==="
php -v 2>/dev/null | head -1

echo -e "\n=== SESSION CONFIG ==="
php -i 2>/dev/null | grep -E "upload_progress\.(enabled|cleanup)|save_path|use_only_cookies"

SESS_DIR=$(php -r "echo ini_get('session.save_path') ?: '/tmp';" 2>/dev/null)
echo -e "\n=== SESSION FILES: $SESS_DIR ==="
TOTAL=$(find "$SESS_DIR" -name 'sess_*' -type f 2>/dev/null | wc -l)
INFECTED=$(grep -rl '<?' "$SESS_DIR"/sess_* 2>/dev/null | wc -l)
echo "Totali: $TOTAL  |  Con codice PHP: $INFECTED"

if [ "$INFECTED" -gt 0 ]; then
  echo "[!!!] ATTENZIONE: trovati file di sessione con codice PHP iniettato!"
  grep -rl '<?' "$SESS_DIR"/sess_* 2>/dev/null
fi

echo -e "\n=== SEGFAULT RECENTI ==="
dmesg 2>/dev/null | grep -ci 'segfault.*php'
grep -rchi 'segfault\|signal 11' /var/log/syslog* /var/log/messages* 2>/dev/null | paste -sd+ | bc

echo -e "\n=== FILE SOSPETTI RECENTI (ultimi 2 giorni) ==="
find /tmp /var/tmp /dev/shm -type f -mtime -2 -name '*.php' -ls 2>/dev/null | head -10

echo -e "\n=== WEBSHELL SCAN ==="
SHELLS=$(find /var/www -name '*.php' -exec grep -l 'eval(\$_\|system(\$_\|base64_decode(\$_' {} \; 2>/dev/null | wc -l)
echo "File con pattern webshell: $SHELLS"

echo -e "\n=== CONNESSIONI OUTBOUND PHP ==="
ss -tnp 2>/dev/null | grep -E 'php|apache|www-data' | grep -v LISTEN | head -10

echo -e "\n=== DONE ==="
```

---

## 6. Interpretazione risultati

| Segnale | Significato | Gravità |
|---|---|---|
| `<?php` dentro `sess_*` | Tentativo di session injection | **CRITICO** — qualcuno ha provato l'exploit |
| Segfault ripetuti di php-fpm | Tentativo Chain D (heap UAF) | **ALTO** — attacco in corso |
| LFI + sess_ negli access log | Tentativo di trigger Chain A | **CRITICO** — se seguito da 200, possibile RCE |
| File .php nuovi in /tmp o webroot | Post-exploitation | **COMPROMESSO** — analisi forense necessaria |
| Webshell trovata | Backdoor attiva | **COMPROMESSO** — IR immediato |
| Connessioni outbound da php | Possibile reverse shell | **COMPROMESSO** — isolare il server |

### Se trovi segni di compromissione:

1. **NON spegnere il server** — perdi evidenze volatili (RAM, connessioni)
2. **Isola dalla rete** (blocca outbound, non inbound) se possibile
3. **Dump delle evidenze**: `ps auxf > /root/ps.txt && ss -tnp > /root/ss.txt && cp -a "$SESS_DIR" /root/sessions_backup`
4. **Contatta il tuo team di incident response**

---

## 7. Mitigazione immediata

```bash
# Disabilita upload_progress (mitigazione senza patch)
# Aggiungi a php.ini o pool config:
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
echo "session.upload_progress.enabled = Off" >> /etc/php/$PHP_VER/fpm/conf.d/99-cve-2026-fix.ini

# Forza use_only_cookies (blocca session fixation via POST)
echo "session.use_only_cookies = On" >> /etc/php/$PHP_VER/fpm/conf.d/99-cve-2026-fix.ini

# Reload (non restart, per non perdere stato)
systemctl reload php*-fpm

# Verifica
php -i | grep upload_progress.enabled
```

> **Fix definitivo**: aggiornare PHP all'ultima patch release.
