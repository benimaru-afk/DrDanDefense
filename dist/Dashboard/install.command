#!/usr/bin/env bash
# Creates a desktop launcher for Advanced Antivirus Suite on macOS
# Double-click this file in Finder to run it.

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
EXE="$APP_DIR/Dashboard"
ICN="$APP_DIR/DrDan.icns"

if [ ! -f "$EXE" ]; then
    echo "[ERROR] Dashboard not found in $APP_DIR"
    echo "        Make sure you run install.command from inside the Dashboard folder."
    read -rp "Press Enter to close..."
    exit 1
fi

chmod +x "$EXE"

DESKTOP="$HOME/Desktop"
LAUNCHER="$DESKTOP/Advanced Antivirus Suite.command"

cat > "$LAUNCHER" << EOF
#!/usr/bin/env bash
cd "$APP_DIR"
"$EXE"
EOF

chmod +x "$LAUNCHER"

# Apply the .icns icon to the launcher file if available
if [ -f "$ICN" ]; then
    osascript << APPLESCRIPT
use framework "AppKit"
set iconImage to current application's NSImage's alloc()'s initWithContentsOfFile:"$ICN"
current application's NSWorkspace's sharedWorkspace()'s setIcon:iconImage forFile:"$LAUNCHER" options:0
APPLESCRIPT
fi

echo "Shortcut created: $LAUNCHER"
echo ""

# Keep terminal open so the user can read the output
read -rp "Press Enter to close..."
