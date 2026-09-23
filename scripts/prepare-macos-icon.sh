#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h:h}"
SOURCE="$ROOT/assets/brand/aegis-mark.svg"
BUILD="$ROOT/build"
ICONSET="$BUILD/icon.iconset"
MASTER_DIR="$(mktemp -d)"
trap 'rm -rf "$MASTER_DIR"' EXIT

[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS is required to generate icon.icns"; exit 1; }
[[ -f "$SOURCE" ]] || { echo "Missing Aegis brand mark: $SOURCE"; exit 1; }

mkdir -p "$BUILD"
rm -rf "$ICONSET"
mkdir -p "$ICONSET"

# Quick Look renders the repository SVG with transparency at a high enough
# resolution to produce every macOS icon slot without adding a build dependency.
qlmanage -t -s 1024 -o "$MASTER_DIR" "$SOURCE" >/dev/null 2>&1
MASTER="$MASTER_DIR/${SOURCE:t}.png"
[[ -f "$MASTER" ]] || { echo "Could not render $SOURCE to PNG with Quick Look."; exit 1; }

make_icon() {
  local pixels="$1"
  local name="$2"
  sips -z "$pixels" "$pixels" "$MASTER" --out "$ICONSET/$name" >/dev/null
}

make_icon 16   icon_16x16.png
make_icon 32   icon_16x16@2x.png
make_icon 32   icon_32x32.png
make_icon 64   icon_32x32@2x.png
make_icon 128  icon_128x128.png
make_icon 256  icon_128x128@2x.png
make_icon 256  icon_256x256.png
make_icon 512  icon_256x256@2x.png
make_icon 512  icon_512x512.png
make_icon 1024 icon_512x512@2x.png

iconutil -c icns "$ICONSET" -o "$BUILD/icon.icns"
rm -rf "$ICONSET"

echo "Created $BUILD/icon.icns"
