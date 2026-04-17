#!/bin/bash
# Userspace FIM for cron persistence (MITRE DC0001/DC0005) when kernel audit is unavailable in Docker.
set -uo pipefail
LOG=/var/log/ics-cron-fim.log
echo "$(date -Iseconds) ics-cron-fim starting (inotify)" >>"$LOG"
inotifywait -m -r \
  -e modify,create,delete,move,close_write,moved_to,moved_from \
  --format 'ICS_CRON_FIM %w%f %e' \
  /etc/crontab \
  /etc/cron.d \
  /etc/cron.daily \
  /etc/cron.hourly \
  /etc/cron.weekly \
  /etc/cron.monthly \
  /var/spool/cron \
  2>>"$LOG" | while IFS= read -r line; do
  out="$(date -Iseconds) $line"
  echo "$out" >>"$LOG"
  logger -t ics-cron-fim -- "$out"
done
