

#!/bin/sh
# takeover.sh — portable, dependency-minimal system inventory & SSH login audit
# POSIX sh. No external deps beyond core utils; gracefully degrades.
# Outputs to takeover_<hostname>_<timestamp>/ with SUMMARY.txt, report.html, CSVs, and .tgz (+optional AES-256).
#
# Env knobs:
#   DURATION=300   sampling seconds for net top-talkers
#   INTERVAL=5     seconds between samples
#   ENCRYPT=1      encrypt .tgz with AES-256 (needs openssl); PASS=... provides passphrase
#   DNS_LOOKUP=1   reverse-dns enrichment for top-talkers (0 to disable)
#   NO_PDF=1       skip PDF attempt

set -u
umask 077

# ---------- tiny helpers (no custom funcs used inside sh -c) ----------
log() { printf '%s\n' "$*" >&2; }
cap() { # cap <outfile> <cmd> [args...]
  out="$1"; shift || :
  if [ "$#" -eq 0 ]; then : >"$out"; return; fi
  cmd="$1"; shift || :
  if command -v "$cmd" >/dev/null 2>&1; then
    ("$cmd" "$@") >"$out" 2>&1 || { rc=$?; printf '\n[exit %s]\n' "$rc" >>"$out"; }
  else
    printf 'MISSING: %s\n' "$cmd" >"$out"
  fi
}
cap_sh() { out="$1"; shift; sh -c "$*" >"$out" 2>&1 || { rc=$?; printf '\n[exit %s]\n' "$rc" >>"$out"; }; }
now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date; }
html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
newline() { printf '\n'; }

# ---------- setup ----------
HOST="$(hostname 2>/dev/null || echo unknown)"
TS="$(date +%Y%m%d_%H%M%S 2>/dev/null || date | tr ' :+' '__-_')"
OUTDIR="takeover_${HOST}_${TS}"
mkdir -p "$OUTDIR" || OUTDIR="./takeover_${TS}"
for d in files csv logs etc find services net agents security cron systemd login software ssh; do
  mkdir -p "$OUTDIR/$d"
done
: "${DURATION:=300}"; : "${INTERVAL:=5}"; : "${DNS_LOOKUP:=1}"
log "[+] Output dir: $OUTDIR"
log "[+] Sampling network for ${DURATION}s (interval ${INTERVAL}s)"

# ---------- basic system info ----------
cap "$OUTDIR/os-release.txt" cat /etc/os-release
cap "$OUTDIR/uname.txt" uname -a
cap "$OUTDIR/uptime.txt" uptime
if command -v lscpu >/dev/null 2>&1; then cap "$OUTDIR/cpuinfo.txt" lscpu; else cap "$OUTDIR/cpuinfo.txt" cat /proc/cpuinfo; fi
cap "$OUTDIR/meminfo.txt" cat /proc/meminfo
if command -v lsblk >/dev/null 2>&1; then cap "$OUTDIR/lsblk.txt" lsblk -a -o NAME,KNAME,FSTYPE,SIZE,TYPE,MOUNTPOINT,LABEL,UUID; else printf 'MISSING: lsblk\n' >"$OUTDIR/lsblk.txt"; fi
cap "$OUTDIR/df.txt" df -hTP
cap "$OUTDIR/mount.txt" mount
cap_sh "$OUTDIR/swaps.txt" 'command -v swapon >/dev/null 2>&1 && swapon --show'
cap_sh "$OUTDIR/ps.txt" 'ps auxww'
cap_sh "$OUTDIR/sysctl.txt" 'command -v sysctl >/dev/null 2>&1 && sysctl -a'
cap "$OUTDIR/resolv.conf.txt" cat /etc/resolv.conf
cap "$OUTDIR/hosts.txt" cat /etc/hosts
{
  date
  newline
  if command -v timedatectl >/dev/null 2>&1; then timedatectl; fi
} >"$OUTDIR/time.txt" 2>&1

# ---------- networking ----------
if command -v ip >/dev/null 2>&1; then
  cap_sh "$OUTDIR/net/ip_addr.txt" 'ip -o addr'
  cap_sh "$OUTDIR/net/ip_link.txt" 'ip -o link'
  cap_sh "$OUTDIR/net/routes_v4.txt" 'ip route'
  cap_sh "$OUTDIR/net/routes_v6.txt" 'ip -6 route'
else
  if command -v ifconfig >/dev/null 2>&1; then cap "$OUTDIR/net/ip_addr.txt" ifconfig -a; else echo 'MISSING: ip/ifconfig' >"$OUTDIR/net/ip_addr.txt"; fi
fi
if command -v ss >/dev/null 2>&1; then cap "$OUTDIR/net/listen.txt" ss -tulpen; cap "$OUTDIR/net/connections_now.txt" ss -antu
elif command -v netstat >/dev/null 2>&1; then cap "$OUTDIR/net/listen.txt" netstat -tulpen; cap "$OUTDIR/net/connections_now.txt" netstat -antu
else echo 'MISSING: ss/netstat' >"$OUTDIR/net/listen.txt"; echo 'MISSING: ss/netstat' >"$OUTDIR/net/connections_now.txt"; fi
cap_sh "$OUTDIR/net/arp.txt" 'command -v ip >/dev/null 2>&1 && ip neigh || (command -v arp >/dev/null 2>&1 && arp -an)'

# ---------- firewall & MAC ----------
cap_sh "$OUTDIR/net/nft.txt" 'command -v nft >/dev/null 2>&1 && nft list ruleset'
cap_sh "$OUTDIR/net/iptables.txt" 'command -v iptables >/dev/null 2>&1 && iptables -S; command -v ip6tables >/dev/null 2>&1 && ip6tables -S'
cap_sh "$OUTDIR/net/ufw.txt" 'command -v ufw >/dev/null 2>&1 && ufw status verbose'
cap_sh "$OUTDIR/net/firewalld.txt" 'command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --list-all-zones'
{
  if command -v getenforce >/dev/null 2>&1; then getenforce; fi
  if command -v sestatus   >/dev/null 2>&1; then sestatus; fi
} >"$OUTDIR/security/selinux.txt" 2>&1
{
  [ -r /sys/module/apparmor/parameters/enabled ] && cat /sys/module/apparmor/parameters/enabled
  command -v aa-status >/dev/null 2>&1 && aa-status
} >"$OUTDIR/security/apparmor.txt" 2>&1

# ---------- users, groups, sudoers, ssh ----------
cap "$OUTDIR/etc/passwd" cat /etc/passwd
if [ -r /etc/shadow ]; then cap "$OUTDIR/etc/shadow" cat /etc/shadow; else echo 'No access or missing /etc/shadow' >"$OUTDIR/etc/shadow"; fi
cap "$OUTDIR/etc/group" cat /etc/group
cap "$OUTDIR/etc/login.defs" cat /etc/login.defs
{
  [ -r /etc/sudoers ] && cat /etc/sudoers
  if [ -d /etc/sudoers.d ]; then
    echo; echo '# /etc/sudoers.d'
    for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo; echo "## $f"; cat "$f"; }; done
  fi
} >"$OUTDIR/etc/sudoers" 2>&1
{
  for f in /etc/ssh/sshd_config /etc/ssh/ssh_config; do [ -r "$f" ] && { echo "## $f"; cat "$f"; echo; }; done
} >"$OUTDIR/etc/ssh_config.txt" 2>&1
# per-user SSH assets
AUTHDIR="$OUTDIR/ssh"; mkdir -p "$AUTHDIR"
awk -F: '{print $1":"$6}' /etc/passwd | while IFS=: read -r u h; do
  [ -n "$h" ] || continue
  for ak in "$h"/.ssh/authorized_keys "$h"/.ssh/authorized_keys2; do [ -r "$ak" ] && { mkdir -p "$AUTHDIR/$u"; cp -p "$ak" "$AUTHDIR/$u/" 2>/dev/null; }; done
  for cf in "$h"/.ssh/config; do [ -r "$cf" ] && { mkdir -p "$AUTHDIR/$u"; cp -p "$cf" "$AUTHDIR/$u/" 2>/dev/null; }; done
  for pub in "$h"/.ssh/*.pub; do [ -f "$pub" ] && { mkdir -p "$AUTHDIR/$u"; cp -p "$pub" "$AUTHDIR/$u/" 2>/dev/null; }; done
  for key in "$h"/.ssh/id_*; do [ -f "$key" ] || continue; case "$key" in *.pub) continue;; esac; mkdir -p "$AUTHDIR/$u"; cp -p "$key" "$AUTHDIR/$u/" 2>/dev/null || :; done
done

# ---------- software inventory ----------
SWDIR="$OUTDIR/software"; mkdir -p "$SWDIR"
cap_sh "$SWDIR/dpkg.txt" 'command -v dpkg >/dev/null 2>&1 && dpkg -l'
cap_sh "$SWDIR/apt.txt"  'command -v apt >/dev/null 2>&1 && apt list --installed 2>/dev/null || (command -v apt-get >/dev/null 2>&1 && apt-get -qq --just-print upgrade 2>/dev/null)'
cap_sh "$SWDIR/rpm.txt"  'command -v rpm >/dev/null 2>&1 && rpm -qa'
cap_sh "$SWDIR/yum.txt"  'command -v yum >/dev/null 2>&1 && yum list installed'
cap_sh "$SWDIR/dnf.txt"  'command -v dnf >/dev/null 2>&1 && dnf list installed'
cap_sh "$SWDIR/zypper.txt" 'command -v zypper >/dev/null 2>&1 && zypper se -i'
cap_sh "$SWDIR/pacman.txt" 'command -v pacman >/dev/null 2>&1 && pacman -Q'
cap_sh "$SWDIR/snap.txt" 'command -v snap >/dev/null 2>&1 && snap list'
cap_sh "$SWDIR/flatpak.txt" 'command -v flatpak >/dev/null 2>&1 && flatpak list --app --columns=app,version,branch,origin,installation'
cap_sh "$SWDIR/pip.txt" 'command -v pip >/dev/null 2>&1 && pip list || (command -v pip3 >/dev/null 2>&1 && pip3 list)'
cap_sh "$SWDIR/gem.txt" 'command -v gem >/dev/null 2>&1 && gem list --local'
cap_sh "$SWDIR/npm.txt" 'command -v npm >/dev/null 2>&1 && npm -g ls --depth=0'
{
  for d in /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin /opt /srv; do
    [ -d "$d" ] && { echo "# $d"; find "$d" -maxdepth 2 -type f -perm -u+x -printf '%p\n' 2>/dev/null; echo; }
  done
} >"$SWDIR/local_bins.txt" 2>&1

# ---------- sensitive perms & certs ----------
MOUNTS=$(df -lP 2>/dev/null | awk 'NR>1 {print $6}')
SUIDF="$OUTDIR/find/suid_sgid.txt"; : >"$SUIDF"
WWDIR="$OUTDIR/find/world_writable_dirs.txt"; : >"$WWDIR"
CERTS="$OUTDIR/find/certificates.txt"; : >"$CERTS"
for m in $MOUNTS; do
  [ -d "$m" ] || continue
  case "$m" in /proc|/sys|/dev) continue;; esac
  log "[+] Scanning perms on $m (this may take a while)"
  find "$m" -xdev \( -type f -perm -4000 -o -perm -2000 \) -printf '%m %u %g %p\n' 2>/dev/null >>"$SUIDF"
  find "$m" -xdev -type d -perm -0002 -printf '%m %u %g %p\n' 2>/dev/null >>"$WWDIR"
  find "$m" -xdev -type f \( -name '*.crt' -o -name '*.pem' -o -name '*.cer' -o -name '*.der' \) 2>/dev/null |
  while IFS= read -r f; do
    if command -v openssl >/dev/null 2>&1; then
      case "$f" in *.der) FM='-inform DER';; *) FM='';; esac
      END=$(openssl x509 $FM -noout -enddate -in "$f" 2>/dev/null | sed 's/notAfter=//')
      SUBJ=$(openssl x509 $FM -noout -subject -in "$f" 2>/dev/null | sed 's/subject= //')
      ISSR=$(openssl x509 $FM -noout -issuer  -in "$f" 2>/dev/null | sed 's/issuer= //')
      printf '%s\t%s\t%s\t%s\n' "$f" "${END:-unknown}" "${SUBJ:-}" "${ISSR:-}" >>"$CERTS"
    else
      printf '%s\t(no openssl to read expiry)\n' "$f" >>"$CERTS"
    fi
  done
done

# ---------- cron / timers / logrotate ----------
{
  [ -r /etc/crontab ] && cat /etc/crontab
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do [ -d "$d" ] && { echo; echo "# $d"; ls -l "$d"; }; done
} >"$OUTDIR/cron/system_crontab.txt" 2>&1
{
  if command -v crontab >/dev/null 2>&1; then
    awk -F: '{print $1}' /etc/passwd | while read u; do crontab -l -u "$u" 2>/dev/null | sed "1i## user:$u"; done
  fi
  [ -d /var/spool/cron ] && { echo; echo "# /var/spool/cron"; ls -l /var/spool/cron; }
  [ -d /var/spool/cron/crontabs ] && { echo; echo "# /var/spool/cron/crontabs"; ls -l /var/spool/cron/crontabs; }
} >"$OUTDIR/cron/user_crons.txt" 2>&1
cap_sh "$OUTDIR/systemd/services.txt" 'command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service --all --no-pager'
cap_sh "$OUTDIR/systemd/timers.txt"   'command -v systemctl >/dev/null 2>&1 && systemctl list-timers --all --no-pager'
cap_sh "$OUTDIR/logrotate.txt" ' [ -r /etc/logrotate.conf ] && cat /etc/logrotate.conf; [ -d /etc/logrotate.d ] && { echo; echo "# /etc/logrotate.d"; for f in /etc/logrotate.d/*; do [ -f "$f" ] && { echo; echo "## $f"; cat "$f"; }; done; }'

# ---------- identify common servers & runtimes ----------
cap_sh "$OUTDIR/services/servers_processes.txt" 'ps auxww | egrep -i "nginx|apache2|httpd|lighttpd|mysqld|mariadbd|postgres|mongod|redis-server|rabbitmq|dockerd|containerd|crio|podman|kubelet" | grep -v egrep'
if command -v ss >/dev/null 2>&1; then cap "$OUTDIR/services/listeners_brief.txt" ss -tunlp; elif command -v netstat >/dev/null 2>&1; then cap "$OUTDIR/services/listeners_brief.txt" netstat -tulnp; fi

# ---------- monitoring / backup / log agents ----------
AG="$OUTDIR/agents/agents.txt"; : >"$AG"
for d in \
  /etc/datadog-agent /opt/datadog-agent \
  /etc/zabbix /var/lib/zabbix \
  /etc/telegraf /var/lib/telegraf \
  /etc/filebeat /etc/metricbeat /etc/elastic-agent \
  /etc/rsyslog.conf /etc/rsyslog.d \
  /etc/syslog-ng /etc/syslog-ng.conf \
  /etc/vector /var/lib/vector \
  /opt/splunkforwarder /opt/splunk \
  /etc/veeam /var/log/veeam \
  /etc/borgmatic /etc/bacula /etc/duplicity /root/.config/rclone /etc/restic \
  /etc/prometheus /var/lib/node_exporter /etc/node_exporter \
  /etc/td-agent /etc/fluent* /etc/td-agent-bit /etc/fluent-bit \
  ; do [ -e "$d" ] && printf '[FOUND] %s\n' "$d" >>"$AG"; done

# ---------- cloud footprints ----------
CF="$OUTDIR/cloud_footprints.txt"; : >"$CF"
for p in /root /home/*; do
  [ -d "$p" ] || continue
  for d in \
    .aws .azure .config/gcloud .oci .alibabacloud .docker .kube .terraform.d .config/gh .azure-devops .config/rclone .gnupg .config/sops .vault .k9s .minikube; do
    [ -e "$p/$d" ] && echo "$p/$d" >>"$CF"
  done
  for f in .env .envrc .docker/config.json .config/gcloud/application_default_credentials.json .aws/credentials .aws/config; do
    [ -e "$p/$f" ] && echo "$p/$f" >>"$CF"
  done
done

# ---------- network sampler (top talkers) ----------
SAMPLES_CSV="$OUTDIR/csv/netconn_samples.csv"; : >"$SAMPLES_CSV"
TOP_CSV="$OUTDIR/csv/net_top_talkers.csv"; : >"$TOP_CSV"
SVC_FROM_PORT() { p="$1"; if [ -z "$p" ]; then echo ""; return; fi; if command -v getent >/dev/null 2>&1; then getent services "$p"/tcp 2>/dev/null | awk '{print $1}' | head -n1; else echo ""; fi; }
REV_DNS() { ip="$1"; if [ "$DNS_LOOKUP" = "1" ] && command -v getent >/dev/null 2>&1; then getent hosts "$ip" 2>/dev/null | awk '{print $2}' | head -n1; else echo ""; fi; }

SAMP_END=$(( $(date +%s 2>/dev/null || echo 0) + DURATION ))
while :; do
  NOWU=$(now_iso)
  if command -v ss >/dev/null 2>&1; then
    ss -ntu 2>/dev/null | awk 'NR>1 {print $5}' |
    while read rp; do rem=${rp##*,}; rem=$(echo "$rem" | sed 's/^\[//; s/\]$//'); r_ip=${rem%:*}; r_port=${rem##*:}; printf '%s,%s,%s\n' "$NOWU" "$r_ip" "$r_port" >>"$SAMPLES_CSV"; done
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ntu 2>/dev/null | awk 'NR>2 {print $5}' |
    while read rem; do r_ip=${rem%:*}; r_port=${rem##*:}; printf '%s,%s,%s\n' "$NOWU" "$r_ip" "$r_port" >>"$SAMPLES_CSV"; done
  else break; fi
  now_s=$(date +%s 2>/dev/null || echo 0); [ "$now_s" -ge "$SAMP_END" ] && break; sleep "$INTERVAL" 2>/dev/null || break
done

# aggregate safely
if command -v awk >/dev/null 2>&1; then
  awk -F, 'NF==3 {k=$2","$3; c[k]++} END {print "remote_ip,remote_port,count"; for (k in c) print k "," c[k]}' "$SAMPLES_CSV" >"$TOP_CSV.tmp"
  {
    echo "remote_ip,remote_port,count,service,reverse_dns"
    IFS=','
    while read ip port count; do
      [ "$ip" = "remote_ip" ] && continue
      svc=$(SVC_FROM_PORT "$port"); rdns=$(REV_DNS "$ip")
      printf '%s,%s,%s,%s,%s\n' "$ip" "$port" "$count" "$svc" "$rdns"
    done <"$TOP_CSV.tmp"
  } >"$TOP_CSV"
  rm -f "$TOP_CSV.tmp"
fi

# ---------- login activity (14 days) ----------
LOGDIR="$OUTDIR/login"
ACCEPTS="$LOGDIR/login_raw_accepts.csv"; : >"$ACCEPTS"
FAILS="$LOGDIR/login_raw_fails.csv"; : >"$FAILS"
SUM_SUCC="$LOGDIR/summary_success_by_user_source.csv"
SUM_FAIL_SRC="$LOGDIR/summary_failed_by_source.csv"

collect_auth() {
  if command -v journalctl >/dev/null 2>&1; then journalctl --since "14 days ago" -o short-iso 2>/dev/null | grep -E 'sshd\[' 2>/dev/null; else [ -f /var/log/auth.log ] && cat /var/log/auth.log; [ -f /var/log/secure ] && cat /var/log/secure; fi
}
collect_auth |
while IFS= read -r line; do
  ts="$(echo "$line" | awk '{print $1" "$2}')"
  echo "$line" | grep -q 'Accepted ' && { user=$(echo "$line" | sed -n 's/.*Accepted [^ ]* for \([^ ]*\) from .*/\1/p'); ip=$(echo "$line" | sed -n 's/.* from \([^ ]*\) port .*/\1/p'); meth=$(echo "$line" | sed -n 's/.*Accepted \([^ ]*\) .*/\1/p'); [ -n "$user" ] && printf '%s,%s,%s,%s\n' "$ts" "$user" "$ip" "$meth" >>"$ACCEPTS"; continue; }
  echo "$line" | grep -q 'Failed ' && { user=$(echo "$line" | sed -n 's/.*Failed [^ ]* for \(invalid user \)*\([^ ]*\) from .*/\2/p'); ip=$(echo "$line" | sed -n 's/.* from \([^ ]*\) port .*/\1/p'); meth=$(echo "$line" | sed -n 's/.*Failed \([^ ]*\) .*/\1/p'); [ -n "$ip" ] && printf '%s,%s,%s,%s\n' "$ts" "${user:-unknown}" "$ip" "$meth" >>"$FAILS"; continue; }
done
[ -s "$ACCEPTS" ] && sed -i '1i timestamp,user,source_ip,method' "$ACCEPTS" || echo 'timestamp,user,source_ip,method' >"$ACCEPTS"
[ -s "$FAILS" ] && sed -i '1i timestamp,user,source_ip,method' "$FAILS" || echo 'timestamp,user,source_ip,method' >"$FAILS"
if command -v awk >/dev/null 2>&1; then
  awk -F, 'NR>1 {k=$2","$3; c[k]++} END {print "user,source_ip,count"; for (k in c) print k "," c[k]}' "$ACCEPTS" >"$SUM_SUCC"
  awk -F, 'NR>1 {c[$3]++} END {print "source_ip,failed_count"; for (k in c) print k "," c[k]}' "$FAILS" >"$SUM_FAIL_SRC"
fi
cap "$LOGDIR/last.txt" last
cap "$LOGDIR/lastb.txt" lastb

# ---------- quick SUMMARY.txt ----------
SUM="$OUTDIR/SUMMARY.txt"
{
  echo "Host: $HOST"; echo "When: $(now_iso)"; echo
  printf 'OS: '; if [ -r /etc/os-release ]; then . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}"; else uname -a; fi
  printf 'Kernel: '; uname -r 2>/dev/null || echo unknown
  printf 'Uptime: '; awk '{print $1" seconds"}' /proc/uptime 2>/dev/null || uptime
  printf 'CPU(s): '; (command -v lscpu >/dev/null 2>&1 && lscpu | awk -F: '/^CPU\(s\)/{gsub(/ /,""); print $2}') || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "?"
  printf 'MemTotal: '; awk '/MemTotal/ {print $2" "$3}' /proc/meminfo 2>/dev/null || echo "?"; echo
  echo "Default routes:"; (command -v ip >/dev/null 2>&1 && ip route show default) || (command -v route >/dev/null 2>&1 && route -n | awk '$1=="0.0.0.0"') || echo none; echo
  echo "DNS:"; awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null || echo unknown; echo
  echo "Top talkers (sampled ${DURATION}s @ ${INTERVAL}s):"; if [ -s "$TOP_CSV" ]; then sort -t, -k3 -nr "$TOP_CSV" | head -n 10; else echo "N/A"; fi; echo
  echo "Successful SSH logins (14d) by user,source:"; if [ -s "$SUM_SUCC" ]; then (command -v column >/dev/null 2>&1 && column -s, -t "$SUM_SUCC") || cat "$SUM_SUCC"; else echo none; fi; echo
  echo "Listening ports:"; if command -v ss >/dev/null 2>&1; then ss -tulpen; elif command -v netstat >/dev/null 2>&1; then netstat -tulpen; else echo "No ss/netstat"; fi
} >"$SUM" 2>&1

# ---------- HTML report ----------
HTML="$OUTDIR/report.html"
add_pre() { t="$1"; f="$2"; echo "<section><h2>$(echo "$t" | html_escape)</h2><pre>" >>"$HTML"; [ -r "$f" ] && cat "$f" | html_escape >>"$HTML" || echo "(missing)" >>"$HTML"; echo "</pre></section>" >>"$HTML"; }
{
cat <<'EOF'
<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<title>Takeover Report</title>
<style>
  body{font:14px/1.4 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111;padding:24px;}
  header{margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #eee}
  h1{font-size:22px;margin:0}
  h2{font-size:18px;margin-top:24px;border-left:4px solid #444;padding-left:8px}
  pre{background:#f9f9f9;border:1px solid #e5e5e5;border-radius:6px;padding:10px;overflow:auto}
  .small{color:#666;font-size:12px}
</style>
</head><body>
EOF
  echo "<header><h1>System Takeover Report</h1>"
  echo "<div class=small>Host: $(echo "$HOST" | html_escape) — Generated: $(now_iso)</div></header>"
  echo "<section><h2>Summary</h2><pre>"; cat "$SUM" | html_escape; echo "</pre></section>"
} >"$HTML"

add_pre "OS Release" "$OUTDIR/os-release.txt"
add_pre "Kernel" "$OUTDIR/uname.txt"
add_pre "CPU" "$OUTDIR/cpuinfo.txt"
add_pre "Memory" "$OUTDIR/meminfo.txt"
add_pre "Disks (lsblk)" "$OUTDIR/lsblk.txt"
add_pre "Filesystems (df)" "$OUTDIR/df.txt"
add_pre "Mounts" "$OUTDIR/mount.txt"
add_pre "Networking (addresses)" "$OUTDIR/net/ip_addr.txt"
add_pre "Routes IPv4" "$OUTDIR/net/routes_v4.txt"
add_pre "Routes IPv6" "$OUTDIR/net/routes_v6.txt"
add_pre "Listening Ports" "$OUTDIR/net/listen.txt"
add_pre "Firewall nftables" "$OUTDIR/net/nft.txt"
add_pre "Firewall iptables" "$OUTDIR/net/iptables.txt"
add_pre "SELinux" "$OUTDIR/security/selinux.txt"
add_pre "AppArmor" "$OUTDIR/security/apparmor.txt"
add_pre "Users (/etc/passwd)" "$OUTDIR/etc/passwd"
add_pre "Groups (/etc/group)" "$OUTDIR/etc/group"
add_pre "Sudoers" "$OUTDIR/etc/sudoers"
add_pre "SSH server/client configs" "$OUTDIR/etc/ssh_config.txt"
add_pre "Software (dpkg)" "$SWDIR/dpkg.txt"
add_pre "Software (RPM)" "$SWDIR/rpm.txt"
add_pre "Software (YUM)" "$SWDIR/yum.txt"
add_pre "Software (DNF)" "$SWDIR/dnf.txt"
add_pre "Software (Zypper)" "$SWDIR/zypper.txt"
add_pre "Software (Pacman)" "$SWDIR/pacman.txt"
add_pre "Software (Snap)" "$SWDIR/snap.txt"
add_pre "Software (Flatpak)" "$SWDIR/flatpak.txt"
add_pre "Pip" "$SWDIR/pip.txt"
add_pre "Gem" "$SWDIR/gem.txt"
add_pre "NPM global" "$SWDIR/npm.txt"
add_pre "Local executables" "$SWDIR/local_bins.txt"
add_pre "SUID/SGID files" "$SUIDF"
add_pre "World-writable dirs" "$WWDIR"
add_pre "Certificates (expiry)" "$CERTS"
add_pre "Cron" "$OUTDIR/cron/system_crontab.txt"
add_pre "User crons" "$OUTDIR/cron/user_crons.txt"
add_pre "Systemd services" "$OUTDIR/systemd/services.txt"
add_pre "Systemd timers" "$OUTDIR/systemd/timers.txt"
add_pre "Detected servers/runtimes" "$OUTDIR/services/servers_processes.txt"
add_pre "Agents/Monitors/Backups" "$OUTDIR/agents/agents.txt"
add_pre "Cloud footprints" "$OUTDIR/cloud_footprints.txt"
add_pre "Current connections" "$OUTDIR/net/connections_now.txt"
add_pre "Top talkers (CSV)" "$TOP_CSV"
add_pre "Raw samples (CSV)" "$SAMPLES_CSV"
add_pre "SSH accepts (CSV)" "$ACCEPTS"
add_pre "SSH failures (CSV)" "$FAILS"
add_pre "Success by user+source (CSV)" "$SUM_SUCC"
add_pre "Failed by source (CSV)" "$SUM_FAIL_SRC"
printf '</body></html>\n' >>"$HTML"

# ---------- optional PDF ----------
PDF="${HTML%.*}.pdf"
if [ "${NO_PDF:-0}" != "1" ]; then
  if command -v wkhtmltopdf >/dev/null 2>&1; then wkhtmltopdf "$HTML" "$PDF" >/dev/null 2>&1 || :
  elif command -v pandoc >/dev/null 2>&1; then pandoc -o "$PDF" "$HTML" >/dev/null 2>&1 || :
  elif command -v libreoffice >/dev/null 2>&1; then libreoffice --headless --convert-to pdf --outdir "$OUTDIR" "$HTML" >/dev/null 2>&1 || :
  fi
fi

# ---------- bundle & optional encryption ----------
cd "$(dirname "$OUTDIR")" 2>/dev/null || :
BASE="$(basename "$OUTDIR")"
TAR="$BASE.tgz"
command -v tar >/dev/null 2>&1 && tar -czf "$TAR" "$BASE" 2>/dev/null || :
if [ "${ENCRYPT:-0}" = "1" ] && [ -f "$TAR" ]; then
  if command -v openssl >/dev/null 2>&1; then
    if [ -z "${PASS:-}" ] && [ -t 0 ]; then printf 'Enter encryption passphrase: ' >&2; stty -echo 2>/dev/null; read -r PASS; stty echo 2>/dev/null; printf '\n' >&2; fi
    [ -n "${PASS:-}" ] && openssl enc -aes-256-cbc -pbkdf2 -salt -in "$TAR" -out "$TAR.enc" -pass pass:"$PASS" 2>/dev/null && rm -f "$TAR" || :
  else
    log "[!] openssl not available; skipping encryption"
  fi
fi
log "[+] Done. See $OUTDIR/ (and $TAR or $TAR.enc if created)."
