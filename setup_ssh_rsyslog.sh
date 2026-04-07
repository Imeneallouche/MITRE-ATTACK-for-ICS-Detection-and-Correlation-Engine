#!/bin/bash

echo "=== Setting up SSH on EWS ==="
docker exec -it ews bash -c "apt update && apt install -y openssh-server && mkdir -p /var/run/sshd && /usr/sbin/sshd"

echo "=== Setting up SSH on Kali ==="
docker exec -it kali bash -c "apt update && apt install -y openssh-server && mkdir -p /var/run/sshd && /usr/sbin/sshd"

echo "=== Starting SSH services ==="
docker exec -u root ews service ssh start
docker exec -u root kali service ssh start

echo "=== Installing rsyslog on EWS ==="
docker exec -it -u root ews bash -c "apt update && apt install -y rsyslog && rsyslogd"

echo "=== Disabling imklog in rsyslog ==="
docker exec -u root ews sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

echo "=== Verifying rsyslog process ==="
docker exec -u root ews ps aux | grep rsyslog

echo "=== Done ✅ ==="
