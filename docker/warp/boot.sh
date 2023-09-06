#!/bin/bash

set -m

if [ -z "$LOG_LEVEL" ]; then
    export LOG_LEVEL=OFF
fi

warp-svc | grep "$LOG_LEVEL" &

sleep 1

warp-cli --accept-tos set-mode proxy

if [ -z "$TEAMS_ENROLL_TOKEN" ]; then
    warp-cli --accept-tos register
    warp-cli --accept-tos connect
else
    warp-cli --accept-tos teams-enroll-token $TEAMS_ENROLL_TOKEN
fi

warp-cli --accept-tos enable-always-on

sleep 3

# This I guess is because they don't want warp-cli to be used for a sharing proxy
tcpfw -l 0.0.0.0:10000 -t 127.0.0.1:40000 &

IP=$(curl -s --retry 20 --retry-delay 5 --proxy socks5://127.0.0.1:10000 ifconfig.me)
echo "Cloudflare-Warp IP: $IP"

if [ -z "$TEAMS_ENROLL_TOKEN" ]; then
    while true; do
        if [[ $(warp-cli --accept-tos warp-stats | awk 'NR==3') == *GB ]]; then
            warp-cli --accept-tos delete
            warp-cli --accept-tos register
            warp-cli --accept-tos set-mode proxy
            warp-cli --accept-tos connect
            warp-cli --accept-tos enable-always-on
        fi

        sleep 300
    done
fi

fg %1