#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$DIR/bin"
mkdir -p "$DIST"

echo "============================================="
echo "       Building VuiRemote Binaries           "
echo "============================================="

# 1. ARMv7 (32-bit) - Most Android TV Boxes & Projectors (Tanix TX3, KAW A70, Hyundai, etc.)
echo "[1/4] Building for Linux ARMv7 (armhf)..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o "$DIST/vuiremote_armv7" "$DIR/cmd/vuiremote"
echo " -> Output: $DIST/vuiremote_armv7 ($(ls -lh "$DIST/vuiremote_armv7" | awk '{print $5}'))"

# 2. ARM64 (64-bit) - Modern Android TV & Boxes (Chromecast with Google TV, Shield TV, etc.)
echo "[2/4] Building for Linux ARM64 (aarch64)..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "$DIST/vuiremote_arm64" "$DIR/cmd/vuiremote"
echo " -> Output: $DIST/vuiremote_arm64 ($(ls -lh "$DIST/vuiremote_arm64" | awk '{print $5}'))"

# 3. x86_64 - Local Linux development & server testing
echo "[3/4] Building for Linux x86_64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$DIST/vuiremote_amd64" "$DIR/cmd/vuiremote"
echo " -> Output: $DIST/vuiremote_amd64 ($(ls -lh "$DIST/vuiremote_amd64" | awk '{print $5}'))"

# 4. Windows 11 x86_64
echo "[4/4] Building for Windows 11 x86_64..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o "$DIST/vuiremote_windows_amd64.exe" "$DIR/cmd/vuiremote"
echo " -> Output: $DIST/vuiremote_windows_amd64.exe ($(ls -lh "$DIST/vuiremote_windows_amd64.exe" | awk '{print $5}'))"

echo "Build complete! All binaries ready in $DIST/"
