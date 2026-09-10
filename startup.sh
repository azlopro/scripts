#!/usr/bin/env bash
#
# Lukker serveren ned: firewall på selve maskinen + SSH uden kodeord.
#
# ⚠ Begge dele kan låse dig ude, hvis noget er sat forkert. Derfor har det her
# script en dødemandsknap: når ændringerne er lagt på, starter en nedtælling,
# der ruller ALT tilbage om 10 minutter — medmindre du når at bekræfte fra en
# NY forbindelse, at du stadig kan komme ind.
#
# Sådan bruges den (scp først — scriptet skal ligge PÅ maskinen, så du kan
# bekræfte bagefter fra en ny forbindelse):
#   1)  scp haerdning.sh <server>:/tmp/
#       ssh <server> 'install -m700 /tmp/haerdning.sh /usr/local/sbin/ && haerdning.sh'
#   2)  åbn et NYT terminalvindue og prøv:  ssh <server>
#   3)  virker det:  ssh <server> haerdning.sh --behold
#       virker det ikke: lav ingenting. Om 10 minutter er alt som før.
#
#   haerdning.sh --fortryd    ruller tilbage med det samme
#   haerdning.sh --status     viser hvad der er lagt på

set -euo pipefail

SSH_DROP=/etc/ssh/sshd_config.d/00-ithjaelpnu-haerdning.conf
FORTRYD=/usr/local/sbin/haerdning-fortryd.sh
FRIST=600   # sekunder

[ "$(id -u)" -eq 0 ] || { echo "kør som root" >&2; exit 1; }

rolle() {
  if [ -f /etc/passbolt/passbolt.php ]; then echo passbolt
  elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^mysql-container$'; then echo netlock
  else echo ukendt; fi
}
ROLLE="$(rolle)"

# genstart_ssh håndterer forskellen mellem Ubuntu-udgaverne.
#
# ⚠ 24.04 starter som udgangspunkt sshd via SOCKET-AKTIVERING: ssh.service er
# ikke kørende mellem forbindelser, og "systemctl reload ssh" fejler på en unit,
# der ikke kører. Hver ny forbindelse starter en frisk sshd, som læser
# konfigurationen forfra — så dér er en reload slet ikke nødvendig.
# På 22.04 kører sshd som almindelig dæmon og SKAL have besked.
# Enheden hedder ssh på begge; sshd findes kun som alias på nogle images.
genstart_ssh() {
  if systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || return 1
  elif systemctl is-active --quiet sshd 2>/dev/null; then
    systemctl reload sshd 2>/dev/null || systemctl restart sshd 2>/dev/null || return 1
  fi
  # Kører den slet ikke, er den socket-aktiveret: næste forbindelse læser selv
  # den nye konfiguration. Intet at gøre.
  return 0
}

# ---------------------------------------------------------------- --status
if [ "${1:-}" = "--status" ]; then
  echo "rolle: $ROLLE"
  echo "ufw: $(ufw status 2>/dev/null | head -1)"
  ufw status numbered 2>/dev/null | sed -n '3,12p' | sed 's/^/  /'
  echo "sshd effektivt:"
  sshd -T 2>/dev/null | grep -iE "^(permitrootlogin|passwordauthentication|port) " | sed 's/^/  /'
  echo "nedtælling aktiv: $(systemctl is-active haerdning-fortryd.timer 2>/dev/null || echo nej)"
  exit 0
fi

# ---------------------------------------------------------------- --behold
if [ "${1:-}" = "--behold" ]; then
  systemctl stop haerdning-fortryd.timer 2>/dev/null || true
  rm -f "$FORTRYD"
  echo "✓ Beholdt. Nedtællingen er stoppet, ændringerne bliver."
  echo
  sshd -T 2>/dev/null | grep -iE "^(permitrootlogin|passwordauthentication) " | sed 's/^/  /'
  ufw status 2>/dev/null | head -1 | sed 's/^/  /'
  exit 0
fi

# ---------------------------------------------------------------- --fortryd
if [ "${1:-}" = "--fortryd" ]; then
  [ -x "$FORTRYD" ] && exec "$FORTRYD"
  echo "der er ikke noget at fortryde"; exit 0
fi

# ------------------------------------------------------------------ anvend
echo "== hærder $ROLLE-serveren =="

# Fortryd-scriptet skrives FØRST. Går noget galt undervejs, findes vejen
# tilbage allerede.
cat > "$FORTRYD" <<'EOF'
#!/usr/bin/env bash
# Ruller hærdningen tilbage. Kaldes af timeren, hvis ingen bekræftede.
set -uo pipefail
logger -t haerdning "ruller hærdning tilbage — ingen bekræftelse modtaget"
rm -f /etc/ssh/sshd_config.d/00-ithjaelpnu-haerdning.conf
# Samme forsigtighed som ved påsætningen: reload kun hvis den kører.
if systemctl is-active --quiet ssh; then systemctl reload ssh 2>/dev/null || systemctl restart ssh
elif systemctl is-active --quiet sshd; then systemctl reload sshd 2>/dev/null || systemctl restart sshd
fi
ufw --force disable
systemctl stop haerdning-fortryd.timer 2>/dev/null || true
rm -f /usr/local/sbin/haerdning-fortryd.sh
EOF
chmod 700 "$FORTRYD"

echo "→ starter nedtælling på $((FRIST / 60)) minutter …"
systemd-run --unit=haerdning-fortryd --on-active="$FRIST" --timer-property=AccuracySec=1s \
  "$FORTRYD" >/dev/null

# ------------------------------------------------------------------- SSH
# ⚠ Ubuntus cloud-billede lægger "PasswordAuthentication yes" i
# /etc/ssh/sshd_config.d/50-cloud-init.conf. sshd bruger den FØRSTE værdi den
# møder, og filerne læses i talrækkefølge — derfor hedder vores 00-, ellers
# ville cloud-init'ens vinde, og ændringen ville se ud til ikke at virke.
echo "→ slår kodeordslogin fra i SSH …"
cat > "$SSH_DROP" <<'EOF'
# Lagt på af intern/scripts/haerdning.sh. Læses før 50-cloud-init.conf.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
chmod 644 "$SSH_DROP"

# Fuld sti: sshd ligger i /usr/sbin, som ikke altid er i PATH for en
# ikke-interaktiv ssh-kommando.
if ! /usr/sbin/sshd -t 2>/dev/null; then
  echo "FEJL: sshd afviser konfigurationen — ruller tilbage nu" >&2
  "$FORTRYD"; exit 1
fi
genstart_ssh || { echo "FEJL: kunne ikke genindlæse ssh — ruller tilbage" >&2; "$FORTRYD"; exit 1; }

# Kontrollér at det, der står i filen, også er det sshd faktisk bruger.
# Er der en 50-cloud-init.conf, der vinder, opdages det HER og ikke i morgen.
if /usr/sbin/sshd -T 2>/dev/null | grep -qi "^passwordauthentication yes"; then
  echo "FEJL: kodeordslogin er STADIG slået til — en anden fil vinder over vores." >&2
  echo "      Se rækkefølgen med: ls /etc/ssh/sshd_config.d/" >&2
  "$FORTRYD"; exit 1
fi

# -------------------------------------------------------------- firewall
echo "→ sætter firewall op …"
command -v ufw >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y ufw >/dev/null 2>&1

# Reglerne lægges på FØR ufw tændes. Modsat rækkefølge lukker den igangværende
# SSH-forbindelse i samme sekund, som den aktiveres.
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
# ⚠ Bevidst "allow" og IKKE "limit". ufw limit spærrer en IP efter 6
# forbindelser på 30 sekunder — og vi arbejder selv med scp efterfulgt af ssh
# i hurtig rækkefølge, hvilket ville udløse den mod Christians egen adresse.
# Beskyttelsen mod gentagne gæt ligger allerede i fail2ban med sshd-jail.
ufw allow 22/tcp comment 'SSH' >/dev/null

if [ "$ROLLE" = netlock ]; then
  # Agenterne på kundemaskinerne taler direkte med rmm.ithjaelpnu.dk.
  ufw allow 80/tcp comment 'NetLock-agenter' >/dev/null
  ufw allow 443/tcp comment 'NetLock-agenter' >/dev/null
  DOCKER_REGLER_FOER=$(iptables -S DOCKER 2>/dev/null | wc -l)
fi
# Passbolt får INTET andet end 22: alt web går gennem Cloudflare Tunnel, som
# er en udgående forbindelse og derfor ikke kræver en åben port.

ufw --force enable >/dev/null
echo "→ firewall aktiv:"
ufw status | sed -n '1,10p' | sed 's/^/  /'

if [ "$ROLLE" = netlock ]; then
  # At tænde ufw skriver iptables-kæderne om. Docker lægger sine egne regler
  # i DOCKER-kæden, og forsvinder de, holder agenterne op med at kunne nå
  # serveren — uden at noget her ser forkert ud. Så vi tæller efter.
  DOCKER_REGLER_EFTER=$(iptables -S DOCKER 2>/dev/null | wc -l)
  if [ "$DOCKER_REGLER_EFTER" -lt "$DOCKER_REGLER_FOER" ]; then
    echo "⚠ Dockers regler blev færre ($DOCKER_REGLER_FOER → $DOCKER_REGLER_EFTER) — genstarter docker …"
    systemctl restart docker
    sleep 5
    echo "  nu: $(iptables -S DOCKER 2>/dev/null | wc -l) regler, containere: $(docker ps -q | wc -l) kørende"
  else
    echo "  Dockers regler er intakte ($DOCKER_REGLER_EFTER), agenterne kan stadig nå serveren"
  fi
  echo
  echo "⚠ BEMÆRK: Docker publicerer porte uden om ufw (den skriver sine egne"
  echo "  iptables-regler i DOCKER-kæden). 80 og 443 ville derfor være åbne"
  echo "  uanset hvad der står ovenfor. De SKAL være åbne her, så det er ikke"
  echo "  et problem — men reglen beskytter ikke det, du måske tror den gør."
  echo "  Det er Hetzners firewall, der er lag nummer et for containerne."
fi

cat <<EOF

=========================================================================
 NEDTÆLLING KØRER — alt rulles tilbage om $((FRIST / 60)) minutter.

 Gør nu, i et NYT terminalvindue:

     ssh -o ControlPath=none $ROLLE

 ⚠ "-o ControlPath=none" er ikke pynt. ~/.ssh/config genbruger en åben
 forbindelse i 60 sekunder, og uden det ville du teste den gamle
 forbindelse, der allerede er inde — og få grønt lys på en dør, der
 i virkeligheden er låst.

 Virker det, så bekræft:

     ssh $ROLLE haerdning.sh --behold

 Virker det IKKE: lav ingenting. Serveren stiller sig selv tilbage.
=========================================================================
EOF
