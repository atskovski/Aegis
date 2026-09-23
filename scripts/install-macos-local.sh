#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h:h}"
cd "$ROOT"

zsh "$ROOT/scripts/package-macos-local.sh"

APP=""
for candidate in   "$ROOT/dist/mac-arm64/Aegis Privacy Browser.app"   "$ROOT/dist/mac-x64/Aegis Privacy Browser.app"   "$ROOT/dist/mac/Aegis Privacy Browser.app"; do
  if [[ -d "$candidate" ]]; then APP="$candidate"; break; fi
done
[[ -n "$APP" ]] || { echo "Could not locate the packaged Aegis app."; exit 1; }

DEST_ROOT="$HOME/Applications"
DEST="$DEST_ROOT/Aegis Privacy Browser.app"
mkdir -p "$DEST_ROOT"
rm -rf "$DEST"
/usr/bin/ditto "$APP" "$DEST"

# A locally created build should not carry quarantine. Remove an inherited
# quarantine attribute only from this newly built local app bundle.
xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true

codesign --verify --deep --strict --verbose=2 "$DEST"

echo ""
echo "Installed Aegis Privacy Browser to:"
echo "$DEST"
echo ""
echo "Opening Aegis..."
open "$DEST"
