#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$ROOT_DIR/bin/vuiremote_armv7"

if [ ! -f "$BIN" ]; then
    echo "Binary $BIN not found! Rebuilding..."
    "$SCRIPT_DIR/build.sh"
fi

echo "============================================="
echo "   VuiRemote Projectors Auto-Deploy Script   "
echo "============================================="

# 1. KAW A70 Projector (auto-detect via MAC a8:77:e5:da:c7:c5 or 192.168.1.153 / 192.168.1.138)
KAW_IP=""
KAW_ARP_IP=$(awk 'tolower($4)=="a8:77:e5:da:c7:c5" && $3=="0x2" {print $1; exit}' /proc/net/arp 2>/dev/null || true)
for cand in $KAW_ARP_IP 192.168.1.153 192.168.1.138; do
    if [ -n "$cand" ] && ping -c 1 -W 1 "$cand" >/dev/null 2>&1; then
        if timeout 2 adb connect "$cand:5555" 2>&1 | grep -qE "connected to|already connected"; then
            KAW_IP="$cand"
            break
        fi
    fi
done

echo "[1/2] Checking KAW A70 (${KAW_IP:-192.168.1.153})..."
if [ -n "$KAW_IP" ]; then
    echo " -> KAW is online at $KAW_IP! Pushing latest binary..."
    adb -s "$KAW_IP:5555" push "$BIN" /data/local/tmp/kaw_remote_new
    adb -s "$KAW_IP:5555" shell "/system/xbin/rjsu 0 sh -c 'setprop vendor.mstar.desk-display-mode 0; rm -f /data/local/tmp/kaw_remote && cp /data/local/tmp/kaw_remote_new /data/local/tmp/kaw_remote && chmod 755 /data/local/tmp/kaw_remote && chmod 666 /dev/uinput /dev/input/event* && ps -A | grep \"[k]aw_remote\" | while read u pid rest; do kill -9 \$pid 2>/dev/null; done; nohup /data/local/tmp/kaw_remote >/data/local/tmp/remote.log 2>&1 </dev/null &'"
    echo " -> KAW ($KAW_IP) updated and restarted successfully!"
else
    echo " -> KAW Projector is currently OFFLINE / STANDBY."
fi

# 2. Hyundai Projector (auto-detect via MAC 8c:bd:37:79:65:cc or 192.168.1.136 / 192.168.1.135)
HYUNDAI_IP=""
ARP_IP=$(awk 'tolower($4)=="8c:bd:37:79:65:cc" && $3=="0x2" {print $1; exit}' /proc/net/arp 2>/dev/null || true)
for cand in $ARP_IP 192.168.1.136 192.168.1.135; do
    if [ -n "$cand" ] && ping -c 1 -W 1 "$cand" >/dev/null 2>&1; then
        if timeout 2 adb connect "$cand:5555" 2>&1 | grep -qE "connected to|already connected"; then
            HYUNDAI_IP="$cand"
            break
        fi
    fi
done

echo "[2/2] Checking Hyundai Projector (${HYUNDAI_IP:-192.168.1.136})..."
if [ -n "$HYUNDAI_IP" ]; then
    echo " -> Hyundai is online at $HYUNDAI_IP! Pushing latest binary..."
    adb -s "$HYUNDAI_IP:5555" push "$BIN" /data/local/tmp/hyundai_remote_new
    adb -s "$HYUNDAI_IP:5555" shell "/system/xbin/zu 0 sh -c 'rm -f /data/local/tmp/hyundai_remote && cp /data/local/tmp/hyundai_remote_new /data/local/tmp/hyundai_remote && chmod 755 /data/local/tmp/hyundai_remote && chmod 666 /dev/uinput /dev/input/event* && ps | grep \"[h]yundai_remote\" | while read u pid rest; do kill -9 \$pid 2>/dev/null; done; nohup /data/local/tmp/hyundai_remote >/data/local/tmp/remote.log 2>&1 </dev/null &'"
    echo " -> Hyundai ($HYUNDAI_IP) updated and restarted successfully!"
else
    echo " -> Hyundai Projector is currently OFFLINE / STANDBY."
fi

echo "Deploy check complete."
