#!/usr/bin/env bash
# Configure SSH and rsyslog on lab containers. EWS auth events are exported via
# ./shared_logs/ews/auth.log (see docker-compose) for Filebeat → Elasticsearch → detection.
set -euo pipefail

echo "=== Setting up SSH + rsyslog on EWS ==="
docker exec -u root ews bash -c "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server rsyslog curl iputils-ping iproute2 cron
mkdir -p /var/run/sshd
# Kernel log module breaks or spins in Docker; disable before starting rsyslog
sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
# Clear stale state from prior crashed/killed rsyslog (otherwise new daemons fail silently)
for p in \$(pgrep -x rsyslogd 2>/dev/null || true); do kill -9 \"\$p\" 2>/dev/null || true; done
rm -f /run/rsyslogd.pid /dev/log
"
# Foreground rsyslog (-n) keeps imuxsock working under docker exec; -d avoids blocking the host script.
docker exec -d ews /usr/sbin/rsyslogd -n
sleep 2
if ! docker exec -u root ews test -S /dev/log; then
  echo "ERROR: rsyslog did not create /dev/log on EWS" >&2
  exit 1
fi
docker exec -u root ews logger -p authpriv.notice "ICS lab: rsyslog ready (ews)"
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
