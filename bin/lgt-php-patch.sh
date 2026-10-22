#!/usr/bin/env bash
# lgt-php-patch.sh — aggiorna PHP (pacchetti Ondřej Surý su Debian/Ubuntu) per CVE-2026-109618 / CVE-2026-109619
#
#   sudo bash lgt-php-patch.sh                     solo controllo + simulazione (non installa nulla)
#   sudo bash lgt-php-patch.sh --apply             installa, riavvia, verifica
#   sudo bash lgt-php-patch.sh --add-sury [...]    aggiunge packages.sury.org se manca, con priorità sul PPA
#                                                  (/etc/apt/preferences.d/lgt-sury-php.pref, Pin-Priority 600)
#
# Passi: 1 stato attuale · 2 repository Ondřej (accetta il cambio di Label solo per Ondřej)
#        3 pacchetti da aggiornare (PHP + estensioni incluse; le PECL a parte, non bloccanti)
#        4 installazione · 5 riavvii (php-fpm, Apache se mod_php, supervisorctl restart all) · 6 verifica
set -uo pipefail

APPLY=0; ADD_SURY=0
for a in "$@"; do case "$a" in --apply) APPLY=1;; --add-sury) ADD_SURY=1;; *) echo "opzione sconosciuta: $a"; exit 64;; esac; done
[ "$(id -u)" -eq 0 ] || { echo "Lancia lo script come root"; exit 1; }

declare -A FIXED=( [8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12 )
SURY_FPR="15058500A0235D97F5D10063B188E2B695BD4743"
SURY_LIST=/etc/apt/sources.list.d/lgt-sury-php.list
SURY_PREF=/etc/apt/preferences.d/lgt-sury-php.pref
CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
VERSIONS=$(for d in /etc/php/*/; do d=${d%/}; d=${d##*/}; [[ $d =~ ^[0-9]+\.[0-9]+$ ]] && echo "$d"; done | sort -V)
[ -n "$VERSIONS" ] || { echo "Nessun PHP in /etc/php"; exit 1; }
STATUS=0
echo "===== $(hostname) — $(date '+%F %T') — $([ "$APPLY" = 1 ] && echo APPLY || echo 'SOLO CONTROLLO') ====="

phpv() { for v in $VERSIONS; do for b in "php$v" "php-fpm$v"; do command -v "$b" >/dev/null && printf '  %-12s %s\n' "$b" "$("$b" -v 2>/dev/null | head -1)"; done; done; }

echo; echo "## 1. Stato attuale"
phpv
MODS_BEFORE=$(for v in $VERSIONS; do command -v "php$v" >/dev/null && "php$v" -m 2>/dev/null | sed "s/^/$v /"; done)

echo; echo "## 2. Repository Ondřej"
if [ "$ADD_SURY" = 1 ] && [ ! -f "$SURY_LIST" ]; then
  if ! curl -fsI "https://packages.sury.org/php/dists/$CODENAME/Release" >/dev/null; then
    echo "KO    $CODENAME non è coperta da packages.sury.org: non lo aggiungo"; exit 1
  fi
  curl -fsSLo /tmp/debsuryorg-archive-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb && dpkg -i /tmp/debsuryorg-archive-keyring.deb >/dev/null
  fpr=$(gpg --show-keys --with-colons /usr/share/keyrings/debsuryorg-archive-keyring.gpg 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')
  [ "$fpr" = "$SURY_FPR" ] || { echo "KO    impronta della chiave sury inattesa ($fpr): mi fermo"; exit 1; }
  echo "deb [signed-by=/usr/share/keyrings/debsuryorg-archive-keyring.gpg] https://packages.sury.org/php/ $CODENAME main" > "$SURY_LIST"
  echo "aggiunto $SURY_LIST (chiave $fpr)"
fi
# precedenza a sury.org sul PPA per i pacchetti che offre (a parità di versione upstream vincerebbe il PPA)
if [ "$ADD_SURY" = 1 ] && [ -f "$SURY_LIST" ] && [ ! -f "$SURY_PREF" ]; then
  printf '# lgt: preferire packages.sury.org al PPA ondrej (php2shell, %s)\nPackage: *\nPin: origin packages.sury.org\nPin-Priority: 600\n' "$(date +%F)" > "$SURY_PREF"
  echo "aggiunto $SURY_PREF (priorità 600 a packages.sury.org)"
fi
ONDREJ_FILES=$(grep -lsE '^[^#]*(ondrej|packages\.sury\.org)' /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources)
[ -n "$ONDREJ_FILES" ] || echo "ATTENZIONE: nessun repository Ondřej: i pacchetti arrivano dalla distro"
echo "$ONDREJ_FILES" | sed 's/^/  /'
# aggiorna solo i repository Ondřej, accettando il cambio di Label solo per loro; ritenta i 503 di Launchpad
if [ -n "$ONDREJ_FILES" ]; then
  T=$(mktemp -d); for f in $ONDREJ_FILES; do ln -s "$f" "$T/"; done
  LOG=$(mktemp)
  echo "--- apt-get update (solo Ondřej) ---"
  apt-get update --allow-releaseinfo-change-label -o Dir::Etc::sourcelist=/dev/null \
    -o Dir::Etc::sourceparts="$T" -o APT::Get::List-Cleanup=0 2>&1 | tee "$LOG"
  if grep -qE '^(Err|E):' "$LOG"; then
    echo "ATTENZIONE: alcuni indici non aggiornati, si usano quelli vecchi"
  else
    echo "indici aggiornati"
  fi
  rm -rf "$T" "$LOG"
fi

echo; echo "## 3. Pacchetti"
# PHP ed estensioni incluse = pacchetti dal sorgente phpX.Y (+ php-common); il resto sono PECL
CORE=$(dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${source:Package}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null \
  | awk -F'|' '$1 ~ /^ii/ && ($3 ~ /^php[0-9]+\.[0-9]+$/ || $2=="php-common") {print $2}')
PECL=$(dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${source:Package}\n' 'php[0-9]*' 2>/dev/null \
  | awk -F'|' '$1 ~ /^ii/ && $3 !~ /^php[0-9]+\.[0-9]+$/ {print $2}')
echo "PHP + estensioni incluse: $(echo $CORE)"
echo "PECL (non bloccanti):    $(echo ${PECL:-nessuna})"
for v in $VERSIONS; do
  cand=$(apt-cache policy "php$v-common" | awk '/Candidate:/{print $2}')
  printf '  PHP %-4s installato %-45s disponibile %s\n' "$v" "$(dpkg-query -W -f='${Version}' "php$v-common" 2>/dev/null)" "$cand"
  want=${FIXED[$v]:-}
  if [ -n "$want" ] && dpkg --compare-versions "${cand%%-*}" lt "$want"; then
    echo "        ↳ la versione disponibile è < $want: patch non nei repository (Ondřej in ritardo? provare --add-sury)"
  fi
done
echo "Simulazione:"
apt-get -s install --only-upgrade $CORE 2>/dev/null | grep -E '^(Inst|Remv)' | sed 's/^/  /'
if apt-get -s install --only-upgrade $CORE 2>/dev/null | grep -q '^Remv'; then
  echo "KO    la simulazione rimuove pacchetti: mi fermo"; exit 1
fi
[ "$APPLY" = 1 ] || { echo; echo "Solo controllo: nulla installato. Per applicare: sudo bash $0 --apply"; exit 0; }

echo; echo "## 4. Installazione"
DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y -o Dpkg::Options::=--force-confold $CORE \
  || { echo "KO    installazione fallita: nessun riavvio"; exit 1; }
if [ -n "$PECL" ]; then
  DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y -o Dpkg::Options::=--force-confold $PECL \
    || echo "ATTENZIONE: PECL non aggiornate (es. 503 Launchpad): restano le versioni attuali, compatibili. Rifare più avanti."
fi

echo; echo "## 5. Riavvii"
for v in $VERSIONS; do
  systemctl list-unit-files "php$v-fpm.service" | grep -q "php$v-fpm" || continue
  if "php-fpm$v" -t >/dev/null 2>&1 && systemctl restart "php$v-fpm"; then echo "php$v-fpm riavviato"
  else echo "KO    php$v-fpm: test o riavvio fallito"; STATUS=1; fi
done
if command -v apache2ctl >/dev/null && apache2ctl -M 2>/dev/null | grep -q 'php.*_module'; then
  apache2ctl configtest >/dev/null 2>&1 && systemctl restart apache2 && echo "apache2 riavviato (mod_php)" || { echo "KO    apache2"; STATUS=1; }
fi
if command -v supervisorctl >/dev/null; then supervisorctl restart all && echo "supervisor: restart all" || { echo "KO    supervisor"; STATUS=1; }; fi

echo; echo "## 6. Verifica"
for v in $VERSIONS; do
  want=${FIXED[$v]:-}; have=$("php$v" -v 2>/dev/null | head -1 | awk '{print $2}' | cut -d- -f1)
  if zgrep -qsE 'CVE-2026-10961[89]' "/usr/share/doc/php$v-common/changelog.Debian.gz"; then echo "OK    PHP $v: changelog cita i CVE"
  elif [ -n "$want" ] && [ -n "$have" ] && dpkg --compare-versions "$have" ge "$want"; then echo "OK    PHP $v: $have >= $want"
  else echo "KO    PHP $v: ${have:-?} non patchato"; STATUS=1; fi
done
phpv
MODS_AFTER=$(for v in $VERSIONS; do command -v "php$v" >/dev/null && "php$v" -m 2>/dev/null | sed "s/^/$v /"; done)
MISSING=$(comm -23 <(sort <<< "$MODS_BEFORE") <(sort <<< "$MODS_AFTER"))
if [ -n "$MISSING" ]; then echo "KO    estensioni sparite dopo l'aggiornamento:"; echo "$MISSING" | sed 's/^/  /'; STATUS=1
else echo "OK    stesse estensioni caricate di prima"; fi
OLD=$(for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null) && [[ $e == *php*"(deleted)" ]] && echo "PID ${p#/proc/}: $e"; done)
if [ -n "$OLD" ]; then echo "KO    processi ancora sul PHP vecchio:"; echo "$OLD" | sed 's/^/  /'; STATUS=1
else echo "OK    nessun processo sul PHP vecchio"; fi

echo; [ "$STATUS" = 0 ] && echo "===== $(hostname): AGGIORNATO =====" || echo "===== $(hostname): CONTROLLA LE RIGHE KO ====="
exit "$STATUS"