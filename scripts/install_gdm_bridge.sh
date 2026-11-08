#!/bin/sh
set -e

# 1. Đảm bảo quyền /dev/uinput 0666 ngay từ lúc boot để VuiKeyboard luôn hoạt động ở màn hình đăng nhập
cat << 'EOF' > /etc/udev/rules.d/99-vuiremote-uinput.rules
KERNEL=="uinput", MODE="0666", OPTIONS+="static_node=uinput"
EOF
chmod 0666 /dev/uinput 2>/dev/null || true

# 2. Tạo script đồng bộ Xauthority của màn hình đăng nhập GDM3 (:0) sang /dev/shm/vui_gdm_Xauthority
cat << 'EOF' > /usr/local/bin/vuiremote-gdm-auth-sync.sh
#!/bin/sh
while true; do
    chmod 0666 /dev/uinput 2>/dev/null || true
    FOUND=""
    for f in /run/user/*/gdm/Xauthority /var/run/gdm3/auth-for-gdm-*/database /run/gdm3/auth-for-gdm-*/database; do
        if [ -f "$f" ]; then
            case "$f" in
                /run/user/1000/*) continue ;;
            esac
            FOUND="$f"
            break
        fi
    done
    if [ -n "$FOUND" ]; then
        cp -f "$FOUND" /dev/shm/vui_gdm_Xauthority.tmp 2>/dev/null && \
        chmod 0644 /dev/shm/vui_gdm_Xauthority.tmp 2>/dev/null && \
        mv -f /dev/shm/vui_gdm_Xauthority.tmp /dev/shm/vui_gdm_Xauthority 2>/dev/null
    fi
    sleep 2
done
EOF
chmod 0755 /usr/local/bin/vuiremote-gdm-auth-sync.sh

# 3. Tạo systemd service chạy tự động ngay khi bật máy (trước khi đăng nhập)
cat << 'EOF' > /etc/systemd/system/vuiremote-gdm-auth.service
[Unit]
Description=VuiRemote GDM3 Pre-Login Screen & Input Bridge
After=systemd-user-sessions.service gdm.service gdm3.service

[Service]
Type=simple
ExecStart=/usr/local/bin/vuiremote-gdm-auth-sync.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vuiremote-gdm-auth.service
echo "[OK] Đã kích hoạt VuiRemote GDM3 Pre-Login Bridge thành công!"
