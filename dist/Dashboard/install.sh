#!/usr/bin/env bash
# Creates a desktop shortcut for Advanced Antivirus Suite on Linux

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
EXE="$APP_DIR/Dashboard"
ICO="$APP_DIR/DrDan.ico"

if [ ! -f "$EXE" ]; then
    echo "[ERROR] Dashboard not found in $APP_DIR"
    echo "        Make sure you run install.sh from inside the Dashboard folder."
    exit 1
fi

chmod +x "$EXE"

DESKTOP_FILE="$HOME/Desktop/Advanced Antivirus Suite.desktop"

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Advanced Antivirus Suite
Exec=$EXE
Path=$APP_DIR
Icon=$ICO
Comment=Advanced Antivirus Suite
Terminal=false
StartupNotify=true
EOF

chmod +x "$DESKTOP_FILE"

# Some desktop environments require this to trust the launcher
if command -v gio &> /dev/null; then
    gio set "$DESKTOP_FILE" metadata::trusted true 2>/dev/null
fi

echo "Shortcut created: $DESKTOP_FILE"
