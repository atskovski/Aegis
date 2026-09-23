#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h:h}"
cd "$ROOT"

[[ "$(uname -s)" == "Darwin" ]] || { echo "Aegis macOS packaging must run on a Mac."; exit 1; }

case "$(uname -m)" in
  arm64) ARCH_FLAG="--arm64"; OUT_DIR="dist/mac-arm64" ;;
  x86_64) ARCH_FLAG="--x64"; OUT_DIR="dist/mac" ;;
  *) echo "Unsupported Mac architecture: $(uname -m)"; exit 1 ;;
esac

if [[ ! -x node_modules/.bin/electron-builder ]]; then
  echo "Installing build dependencies..."
  npm install
fi

npm run prepare:mac-icon

echo "Building local Aegis Privacy Browser.app..."
CSC_IDENTITY_AUTO_DISCOVERY=false node_modules/.bin/electron-builder   --mac dir "$ARCH_FLAG"   -c.mac.identity=-   -c.mac.hardenedRuntime=false   -c.mac.notarize=false

APP="$ROOT/$OUT_DIR/Aegis Privacy Browser.app"
if [[ ! -d "$APP" && -d "$ROOT/dist/mac-arm64/Aegis Privacy Browser.app" ]]; then APP="$ROOT/dist/mac-arm64/Aegis Privacy Browser.app"; fi
if [[ ! -d "$APP" && -d "$ROOT/dist/mac-x64/Aegis Privacy Browser.app" ]]; then APP="$ROOT/dist/mac-x64/Aegis Privacy Browser.app"; fi
[[ -d "$APP" ]] || { echo "Build finished but Aegis Privacy Browser.app was not found."; exit 1; }

codesign --verify --deep --strict --verbose=2 "$APP"
echo ""
echo "Built native app:"
echo "$APP"
echo ""
echo "This local build is an app bundle with its own icon and does not need Run-Aegis.command."
