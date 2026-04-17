#!/usr/bin/env bash
# Configure SSH, rsyslog, and cron file monitoring on EWS. Auth events go to
# ./shared_logs/ews/auth.log for Filebeat → Elasticsearch → detection.
#
# Kernel audit (auditd) is often unavailable inside Docker (auditctl EPERM even when
# privileged). Cron persistence visibility uses inotify on standard paths instead.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Setting up SSH + rsyslog + cron FIM (inotify) on EWS ==="
docker exec -u root ews bash -c "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server rsyslog curl iputils-ping iproute2 cron inotify-tools
mkdir -p /var/run/sshd
sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
for p in \$(pgrep -x rsyslogd 2>/dev/null || true); do kill -9 \"\$p\" 2>/dev/null || true; done
rm -f /run/rsyslogd.pid /dev/log
# Prefer mkdir over install -d: bind-mounted /var/log/audit can make install -d fail with set -e.
mkdir -p /var/log/audit 2>/dev/null || true
chmod 750 /var/log/audit 2>/dev/null || true
"
docker cp "${SCRIPT_DIR}/scripts/ews-ics-cron-fim.sh" ews:/usr/local/sbin/ics-cron-fim.sh
docker exec -u root ews chmod 755 /usr/local/sbin/ics-cron-fim.sh

# Foreground rsyslog (-n) keeps imuxsock working under docker exec; -d avoids blocking the host script.
docker exec -d ews /usr/sbin/rsyslogd -n
sleep 2
if ! docker exec -u root ews test -S /dev/log; then
  echo "ERROR: rsyslog did not create /dev/log on EWS" >&2
  exit 1
fi
docker exec -u root ews logger -p authpriv.notice "ICS lab: rsyslog ready (ews)"

echo "=== Starting cron FIM daemon on EWS (inotify) ==="
docker exec -u root ews /bin/sh -c '
# Do NOT pkill by script path: this same sh -c block contains /usr/local/sbin/ics-cron-fim.sh in argv,
# so pkill -f would match and kill the parent shell (exit 143). Only tear down prior inotifywait.
pkill -f "[i]notifywait -m -r" 2>/dev/null || true
sleep 1
chmod 755 /usr/local/sbin/ics-cron-fim.sh 2>/dev/null || true
if [ ! -f /usr/local/sbin/ics-cron-fim.sh ]; then
  echo "WARN: /usr/local/sbin/ics-cron-fim.sh missing after docker cp" >&2
else
  setsid /bin/bash /usr/local/sbin/ics-cron-fim.sh </dev/null >>/tmp/ics-cron-fim.stdout 2>&1 &
fi
exit 0
'

sleep 2
if docker exec -u root ews pgrep -f inotifywait >/dev/null 2>&1; then
  echo "ics-cron-fim (inotifywait) is running on EWS."
else
  echo "WARNING: inotify cron monitor does not appear to be running on EWS." >&2
fi

# Restart sshd so it uses the live syslog socket
docker exec -u root ews service ssh restart 2>/dev/null || docker exec -u root ews service ssh start

echo "=== Setting up SSH + sshpass on Kali ==="
docker exec -u root kali bash -c "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server sshpass iputils-ping || true
mkdir -p /var/run/sshd
"
docker exec -u root kali service ssh restart 2>/dev/null || docker exec -u root kali service ssh start

echo "=== Fixing the Routing between EWS and Caldera ==="
docker exec -u root ews ip route del 192.168.90.0/24 via 192.168.95.200 dev eth1 2>/dev/null || true
docker exec ews ip route get 192.168.90.250

echo "=== Verifying rsyslog on EWS ==="
docker exec -u root ews ps aux | grep '[r]syslogd' || true
docker exec -u root ews ls -la /dev/log

echo "=== Done ✅ ==="
