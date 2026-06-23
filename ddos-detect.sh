#!/bin/bash
LOG="/var/log/apache2/access.log"
THRESHOLD=150
STATE_FILE="/var/ossec/active-response/bin/.ddos-detect-state"

if [ ! -f "$LOG" ]; then exit 0; fi

CURRENT_LINES=$(wc -l < "$LOG" 2>/dev/null || echo 0)
LAST_LINES=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
echo "$CURRENT_LINES" > "$STATE_FILE"

[ "$CURRENT_LINES" -lt "$LAST_LINES" ] && LAST_LINES=0
NEW_LINES=$((CURRENT_LINES - LAST_LINES))
[ "$NEW_LINES" -le 0 ] && exit 0

tail -n "$NEW_LINES" "$LOG" 2>/dev/null | awk '{print $1}' | \
    grep -v "^127\." | grep -v "^10\." | grep -v "^172\.1[6-9]\." | \
    grep -v "^172\.2[0-9]\." | grep -v "^172\.3[0-1]\." | grep -v "^192\.168\." | \
    sort | uniq -c | sort -rn | \
while read -r count ip; do
    if [ "$count" -ge "$THRESHOLD" ]; then
        echo "DDOS_DETECTED SRC_IP=$ip REQUESTS=$count"
    fi
done
