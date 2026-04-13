#!/usr/bin/env bash
set -e

echo "=== Setting up SSH on EWS ==="
docker exec -u root ews bash -c "
apt update &&
apt install -y openssh-server rsyslog curl &&
mkdir -p /var/run/sshd &&
/usr/sbin/sshd
"

echo "=== Setting up SSH + sshpass on Kali ==="
docker exec -u root kali bash -c "
apt update &&
apt install -y openssh-server sshpass &&
mkdir -p /var/run/sshd &&
/usr/sbin/sshd
"

echo "=== Starting SSH services ==="
docker exec -u root ews service ssh start
docker exec -u root kali service ssh start

echo "=== Disabling imklog in rsyslog ==="
docker exec -u root ews sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

echo "=== Verifying rsyslog process ==="
docker exec -u root ews ps aux | grep rsyslog || true

echo "=== Done ✅ ==="
