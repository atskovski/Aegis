#!/bin/zsh
set -u
APP_NAME="Aegis Privacy Browser"
VERSION="0.9.0"
ELECTRON_VERSION="44.4.3"
RUNTIME_ROOT="$HOME/Library/Application Support/$APP_NAME"
RUNTIME_DIR="$RUNTIME_ROOT/runtime-v$VERSION"
LOG_FILE="$RUNTIME_ROOT/logs/launch.log"
CODESIGN_LOG="$RUNTIME_ROOT/logs/codesign.log"
TRUST_FILE="$RUNTIME_ROOT/engines/electron-v$ELECTRON_VERSION.trust"
SOURCE_DIR="${0:A:h}"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
case "$ARCH" in
  arm64)
    ELECTRON_ARCH="arm64"
    EXPECTED_SHA="6b728f5dcfae74f3f936f2bca5b3cd9b9659ffea464f67939f004acb55425a85"
    ;;
  x86_64)
    ELECTRON_ARCH="x64"
    EXPECTED_SHA="015b52631d92187b552ff4e047255f596a7af4707e388a5890951f0b2645764e"
    ;;
  *) ELECTRON_ARCH="unknown"; EXPECTED_SHA="unknown" ;;
esac
ENGINE_DIR="$RUNTIME_ROOT/engines/electron-v$ELECTRON_VERSION-darwin-$ELECTRON_ARCH"
ELECTRON_APP="$ENGINE_DIR/Electron.app"
ELECTRON_BIN="$ELECTRON_APP/Contents/MacOS/Electron"
ZIP_PATH="$RUNTIME_ROOT/cache/electron-v$ELECTRON_VERSION-darwin-$ELECTRON_ARCH.zip"

print_line() { printf '%-32s %s\n' "$1" "$2"; }

archive_sha="missing"
if [[ -f "$ZIP_PATH" ]]; then archive_sha="$(/usr/bin/shasum -a 256 "$ZIP_PATH" 2>/dev/null | /usr/bin/awk '{print $1}' || echo error)"; fi

echo ""
echo "Aegis Privacy Browser — Local Diagnostics"
echo "─────────────────────────────────────────"
print_line "Source" "$SOURCE_DIR"
print_line "Runtime" "$RUNTIME_DIR"
print_line "Engine" "$ENGINE_DIR"
print_line "macOS" "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
print_line "Architecture" "$ARCH / Electron $ELECTRON_ARCH"
print_line "Host Node" "$(node --version 2>/dev/null || echo not required)"
print_line "Pinned Electron SHA" "$EXPECTED_SHA"
print_line "Cached archive SHA" "$archive_sha"
if [[ "$archive_sha" == "$EXPECTED_SHA" ]]; then
  print_line "Archive integrity" "PASS — exact pinned official asset"
elif [[ "$archive_sha" == "missing" ]]; then
  print_line "Archive integrity" "not downloaded yet"
else
  print_line "Archive integrity" "FAIL"
fi

if [[ -x "$ELECTRON_BIN" ]]; then
  EV="$(ELECTRON_RUN_AS_NODE=1 "$ELECTRON_BIN" -e 'process.stdout.write(process.versions.electron || "unknown")' 2>/dev/null || echo unknown)"
  CV="$(ELECTRON_RUN_AS_NODE=1 "$ELECTRON_BIN" -e 'process.stdout.write(process.versions.chrome || "unknown")' 2>/dev/null || echo unknown)"
  print_line "Electron executable" "present"
  print_line "Electron runtime" "$EV"
  print_line "Chromium runtime" "$CV"
else
  print_line "Electron executable" "MISSING"
fi

case "$SOURCE_DIR" in
  "$HOME/Downloads"/*|"$HOME/Desktop"/*|"$HOME/Documents"/*)
    print_line "Protected source folder" "yes — safe; engine/runtime execute from Application Support"
    ;;
  *) print_line "Protected source folder" "no" ;;
esac

if [[ -d "$ELECTRON_APP" ]]; then
  if /usr/bin/codesign --verify --deep --verbose=2 "$ELECTRON_APP" >/dev/null 2>&1; then
    print_line "Code signature (deep)" "PASS"
  else
    print_line "Code signature (deep)" "non-zero; see codesign.log"
  fi
  if /usr/bin/codesign --verify --deep --strict --verbose=2 "$ELECTRON_APP" >/dev/null 2>&1; then
    print_line "Code signature (strict)" "PASS"
  else
    print_line "Code signature (strict)" "advisory check returned non-zero"
  fi
  if /usr/sbin/spctl --assess --type execute --verbose=2 "$ELECTRON_APP" >/dev/null 2>&1; then
    print_line "Gatekeeper assessment" "accepted"
  else
    print_line "Gatekeeper assessment" "not accepted / unavailable (diagnostic only)"
  fi
fi

if [[ -f "$TRUST_FILE" ]]; then
  TRUST_SUMMARY="$(/usr/bin/awk -F= '/^trust=/{sub(/^trust=/,"");print}' "$TRUST_FILE" 2>/dev/null || true)"
  print_line "Last engine trust mode" "${TRUST_SUMMARY:-unknown}"
fi

if [[ -d "$ELECTRON_APP" ]] && command -v xattr >/dev/null 2>&1; then
  QA="$(xattr -p com.apple.quarantine "$ELECTRON_APP" 2>/dev/null || true)"
  print_line "Electron quarantine" "${QA:-none on Electron.app}"
fi

PIDS="$(pgrep -f "$ELECTRON_BIN" 2>/dev/null | tr '\n' ' ' || true)"
print_line "v$VERSION process" "${PIDS:-not running}"

if [[ -f "$LOG_FILE" ]]; then
  if grep -Fq '[Aegis startup] Browser window opened successfully.' "$LOG_FILE"; then
    print_line "Window-open marker" "present in launch log"
  else
    print_line "Window-open marker" "not found"
  fi
  if grep -Fq '[Aegis startup] First private tab initialized.' "$LOG_FILE"; then
    print_line "Private-tab marker" "present in launch log"
  else
    print_line "Private-tab marker" "not found"
  fi
  if grep -Fq '[Aegis startup] External website smoke test passed:' "$LOG_FILE"; then
    print_line "External-web marker" "PASS — real HTTPS page completed in an isolated tab"
  else
    print_line "External-web marker" "not recorded — run Smoke-Test-Aegis.command"
  fi

  echo ""
  echo "Last 80 launch-log lines"
  echo "────────────────────────"
  tail -80 "$LOG_FILE"
else
  echo ""
  echo "No launch log exists yet."
fi

if [[ -f "$CODESIGN_LOG" ]]; then
  echo ""
  echo "Last 60 code-sign verification lines"
  echo "────────────────────────────────────"
  tail -60 "$CODESIGN_LOG"
fi

echo ""
echo "Use Smoke-Test-Aegis.command for an automated browser → isolated tab → real HTTPS load → clean-exit check."
read "?Press Return to close..." || true
