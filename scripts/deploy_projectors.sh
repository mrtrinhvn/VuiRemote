#!/bin/bash
set -e

BIN="/tmp/tx3_webremote/tx3_remote_bin"
if [ ! -f "$BIN" ]; then
    echo "Binary $BIN not found! Rebuilding..."
    CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o "$BIN" /tmp/tx3_webremote/main.go
fi

echo "============================================="
echo "   VuiRemote Projectors Auto-Deploy Script   "
echo "============================================="

# 1. KAW A70 Projector (192.168.1.138)
echo "[1/2] Checking KAW A70 (192.168.1.138)..."
if ping -c 1 -W 1 192.168.1.138 >/dev/null 2>&1; then
    echo " -> KAW is online! Connecting ADB..."
    adb connect 192.168.1.138:5555 || true
    adb -s 192.168.1.138:5555 push "$BIN" /data/local/tmp/kaw_remote_new
    adb -s 192.168.1.138:5555 shell "/system/xbin/rjsu 0 sh -c 'rm -f /data/local/tmp/kaw_remote && cp /data/local/tmp/kaw_remote_new /data/local/tmp/kaw_remote && chmod 755 /data/local/tmp/kaw_remote && chmod 666 /dev/uinput /dev/input/event* && killall -9 kaw_remote 2>/dev/null; nohup /data/local/tmp/kaw_remote >/data/local/tmp/remote.log 2>&1 &'" || \
    adb -s 192.168.1.138:5555 shell "su 0 sh -c 'rm -f /data/local/tmp/kaw_remote && cp /data/local/tmp/kaw_remote_new /data/local/tmp/kaw_remote && chmod 755 /data/local/tmp/kaw_remote && chmod 666 /dev/uinput /dev/input/event* && killall -9 kaw_remote 2>/dev/null; nohup /data/local/tmp/kaw_remote >/data/local/tmp/remote.log 2>&1 &'"
    echo " -> KAW updated and restarted successfully!"
else
    echo " -> KAW (192.168.1.138) is currently OFFLINE / STANDBY."
fi

# 2. Hyundai Projector (192.168.1.135)
echo "[2/2] Checking Hyundai Projector (192.168.1.135)..."
if ping -c 1 -W 1 192.168.1.135 >/dev/null 2>&1; then
    echo " -> Hyundai is online! Connecting ADB..."
    adb connect 192.168.1.135:5555 || true
    adb -s 192.168.1.135:5555 push "$BIN" /data/local/tmp/hyundai_remote_new
    adb -s 192.168.1.135:5555 shell "/system/xbin/zu 0 sh -c 'rm -f /data/local/tmp/hyundai_remote && cp /data/local/tmp/hyundai_remote_new /data/local/tmp/hyundai_remote && chmod 755 /data/local/tmp/hyundai_remote && chmod 666 /dev/uinput /dev/input/event* && killall -9 hyundai_remote 2>/dev/null; nohup /data/local/tmp/hyundai_remote >/data/local/tmp/remote.log 2>&1 &'"
    echo " -> Hyundai updated and restarted successfully!"
else
    echo " -> Hyundai (192.168.1.135) is currently OFFLINE / STANDBY."
fi

echo "Deploy check complete."
