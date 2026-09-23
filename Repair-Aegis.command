#!/bin/zsh
set -euo pipefail
APP_NAME="Aegis Privacy Browser"
VERSION="0.9.0"
ELECTRON_VERSION="44.4.3"
RUNTIME_ROOT="$HOME/Library/Application Support/$APP_NAME"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64) ELECTRON_ARCH="arm64" ;;
  x86_64) ELECTRON_ARCH="x64" ;;
  *) ELECTRON_ARCH="unknown" ;;
esac
ENGINE_DIR="$RUNTIME_ROOT/engines/electron-v$ELECTRON_VERSION-darwin-$ELECTRON_ARCH"
CACHE_DIR="$RUNTIME_ROOT/cache"
TRUST_FILE="$RUNTIME_ROOT/engines/electron-v$ELECTRON_VERSION.trust"

echo ""
echo "Aegis Privacy Browser — Repair"
echo "──────────────────────────────"
echo "This removes Aegis's downloaded Electron engine, cached Electron ZIP, and trust marker."
echo "Your Aegis settings and local launch logs are preserved."
echo ""
echo "Engine: $ENGINE_DIR"
read "?Repair Aegis now? [y/N] " answer
case "$answer" in
  y|Y) ;;
  *) exit 0 ;;
esac

rm -rf "$ENGINE_DIR"
rm -f "$TRUST_FILE"
if [[ "$ELECTRON_ARCH" != "unknown" ]]; then
  rm -f "$CACHE_DIR/electron-v$ELECTRON_VERSION-darwin-$ELECTRON_ARCH.zip" \
        "$CACHE_DIR/electron-v$ELECTRON_VERSION-darwin-$ELECTRON_ARCH.zip.part"
fi

echo "Repair reset complete. Double-click Run-Aegis.command to download a fresh hash-pinned official engine."
read "?Press Return to close..." || true
