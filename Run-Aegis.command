#!/bin/zsh
set -euo pipefail

SOURCE_DIR="${0:A:h}"
APP_NAME="Aegis Privacy Browser"
VERSION="1.1.1"
ELECTRON_VERSION="44.4.3"
RUNTIME_ROOT="$HOME/Library/Application Support/$APP_NAME"
RUNTIME_DIR="$RUNTIME_ROOT/runtime-v$VERSION"
ENGINE_ROOT="$RUNTIME_ROOT/engines"
CACHE_DIR="$RUNTIME_ROOT/cache"
LOG_DIR="$RUNTIME_ROOT/logs"
LOG_FILE="$LOG_DIR/launch.log"
CODESIGN_LOG="$LOG_DIR/codesign.log"
TRUST_FILE="$ENGINE_ROOT/electron-v$ELECTRON_VERSION.trust"

mkdir -p "$RUNTIME_DIR" "$ENGINE_ROOT" "$CACHE_DIR" "$LOG_DIR"
chmod 700 "$RUNTIME_ROOT" "$RUNTIME_DIR" "$ENGINE_ROOT" "$CACHE_DIR" "$LOG_DIR" 2>/dev/null || true

exec > >(tee -a "$LOG_FILE") 2>&1

stamp() { /bin/date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(stamp)] $*"; }

pause_close() {
  if [[ -t 0 ]]; then read "?Press Return to close..." || true; fi
}

fatal() {
  echo ""
  echo "ERROR: $1"
  echo "Launch log: $LOG_FILE"
  pause_close
  exit 1
}

echo ""
echo "Aegis Privacy Browser v$VERSION"
echo "────────────────────────────────────────"

[[ "$(uname -s)" == "Darwin" ]] || fatal "This launcher is intended for macOS."

MACOS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo 0)"
MACOS_MAJOR="${MACOS_VERSION%%.*}"
if ! [[ "$MACOS_MAJOR" =~ ^[0-9]+$ ]] || (( MACOS_MAJOR < 13 )); then
  fatal "Aegis v$VERSION requires macOS 13 Ventura or newer. Detected macOS: $MACOS_VERSION"
fi

ARCH="$(uname -m)"
case "$ARCH" in
  arm64)
    ELECTRON_ARCH="arm64"
    ELECTRON_SHA256="6b728f5dcfae74f3f936f2bca5b3cd9b9659ffea464f67939f004acb55425a85"
    ;;
  x86_64)
    ELECTRON_ARCH="x64"
    ELECTRON_SHA256="015b52631d92187b552ff4e047255f596a7af4707e388a5890951f0b2645764e"
    ;;
  *) fatal "Unsupported Mac architecture: $ARCH" ;;
esac

ENGINE_DIR="$ENGINE_ROOT/electron-v$ELECTRON_VERSION-darwin-$ELECTRON_ARCH"
ELECTRON_APP="$ENGINE_DIR/Electron.app"
ELECTRON_BIN="$ELECTRON_APP/Contents/MacOS/Electron"
ZIP_NAME="electron-v$ELECTRON_VERSION-darwin-$ELECTRON_ARCH.zip"
ZIP_PATH="$CACHE_DIR/$ZIP_NAME"
ELECTRON_BASE_URL="${AEGIS_ELECTRON_MIRROR:-https://github.com/electron/electron/releases/download}"
ELECTRON_URL="$ELECTRON_BASE_URL/v$ELECTRON_VERSION/$ZIP_NAME"

sha256_file() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

verify_cached_archive() {
  [[ -f "$ZIP_PATH" ]] || return 1
  local actual
  actual="$(sha256_file "$ZIP_PATH" 2>/dev/null || true)"
  [[ "$actual" == "$ELECTRON_SHA256" ]]
}

download_verified_archive() {
  if verify_cached_archive; then
    log "Pinned Electron archive SHA-256 verified from cache."
    return 0
  fi

  if [[ -f "$ZIP_PATH" ]]; then
    log "Cached Electron archive failed SHA-256 verification; deleting it."
    rm -f "$ZIP_PATH"
  fi

  echo "Downloading official Electron release..."
  local tmp="$ZIP_PATH.part"
  rm -f "$tmp"
  if ! /usr/bin/curl --fail --location --retry 3 --retry-delay 2 --connect-timeout 20 \
    --output "$tmp" "$ELECTRON_URL"; then
    rm -f "$tmp"
    fatal "Electron download failed. URL: $ELECTRON_URL"
  fi

  local actual
  actual="$(sha256_file "$tmp")"
  if [[ "$actual" != "$ELECTRON_SHA256" ]]; then
    rm -f "$tmp"
    echo "Expected: $ELECTRON_SHA256"
    echo "Actual:   $actual"
    fatal "SECURITY STOP: downloaded Electron archive failed pinned SHA-256 verification."
  fi

  mv "$tmp" "$ZIP_PATH"
  chmod 600 "$ZIP_PATH" 2>/dev/null || true
  log "Downloaded Electron archive matches the pinned official release SHA-256."
}

codesign_basic() {
  [[ -x "$ELECTRON_BIN" ]] || return 1
  /usr/bin/codesign --verify --deep --verbose=2 "$ELECTRON_APP" >"$CODESIGN_LOG" 2>&1
}

codesign_strict() {
  [[ -x "$ELECTRON_BIN" ]] || return 1
  /usr/bin/codesign --verify --deep --strict --verbose=2 "$ELECTRON_APP" >>"$CODESIGN_LOG" 2>&1
}

record_signature_metadata() {
  {
    echo ""
    echo "--- codesign metadata ---"
    /usr/bin/codesign -d --verbose=4 "$ELECTRON_APP" 2>&1 || true
    echo "--- end codesign metadata ---"
  } >>"$CODESIGN_LOG"
}

extract_verified_engine() {
  download_verified_archive
  rm -rf "$ENGINE_DIR"
  mkdir -p "$ENGINE_DIR"
  if ! /usr/bin/ditto -x -k "$ZIP_PATH" "$ENGINE_DIR"; then
    rm -rf "$ENGINE_DIR"
    fatal "Electron archive extraction failed."
  fi
  [[ -x "$ELECTRON_BIN" ]] || fatal "Electron archive extracted, but Electron.app/Contents/MacOS/Electron is missing."
}

verify_or_restore_engine() {
  local trust_mode=""

  # The archive's pinned SHA-256 is the primary supply-chain trust anchor. It is
  # the exact digest published for Electron 44.4.3's GitHub release asset.
  download_verified_archive

  if [[ ! -x "$ELECTRON_BIN" ]]; then
    echo "Installing verified Electron $ELECTRON_VERSION engine for $ELECTRON_ARCH..."
    extract_verified_engine
  fi

  : >"$CODESIGN_LOG"
  if codesign_basic; then
    trust_mode="pinned-sha256 + macOS-codesign"
    record_signature_metadata
    if codesign_strict; then
      log "Electron code signature verification passed (deep + strict)."
      trust_mode="$trust_mode + strict"
    else
      log "Strict code-signature validation returned non-zero; standard deep verification passed. Continuing safely."
      echo "Strict verification is diagnostic in v$VERSION; see $CODESIGN_LOG" >&2
    fi
  else
    # If macOS rejects the verification command, restore the app byte-for-byte
    # from the already hash-verified official archive. This prevents a modified
    # installed engine from being accepted merely because codesign is unavailable
    # or behaves differently on a given macOS release.
    log "macOS code-signature verification did not pass. Restoring Electron from the pinned archive before launch."
    extract_verified_engine
    : >"$CODESIGN_LOG"
    if codesign_basic; then
      trust_mode="pinned-sha256 + macOS-codesign-after-restore"
      record_signature_metadata
      if codesign_strict; then
        trust_mode="$trust_mode + strict"
      else
        log "Strict code-signature verification remains advisory on this Mac."
      fi
    else
      trust_mode="pinned-sha256 restored"
      record_signature_metadata
      log "macOS codesign still returned non-zero after a clean restore."
      log "Proceeding because the engine was freshly extracted from the exact SHA-256-pinned official Electron archive."
      log "Detailed codesign output: $CODESIGN_LOG"
    fi
  fi

  {
    echo "version=$ELECTRON_VERSION"
    echo "arch=$ELECTRON_ARCH"
    echo "sha256=$ELECTRON_SHA256"
    echo "trust=$trust_mode"
    echo "verified_at=$(stamp)"
  } >"$TRUST_FILE"
  chmod 600 "$TRUST_FILE" 2>/dev/null || true
  ENGINE_TRUST_MODE="$trust_mode"
}

# macOS protects Downloads/Desktop/Documents. Run the browser and its sandboxed
# helpers only from Aegis's private Application Support runtime.
echo "Preparing private runtime in Application Support..."
/usr/bin/rsync -a --delete \
  --exclude 'node_modules' \
  --exclude '.git' \
  --exclude 'dist' \
  --exclude '*.log' \
  "$SOURCE_DIR/" "$RUNTIME_DIR/"

verify_or_restore_engine

# Use Electron's embedded Node runtime for preflight; users do not need Node/npm installed.
echo "Running Aegis preflight security check..."
run_node() {
  ELECTRON_RUN_AS_NODE=1 "$ELECTRON_BIN" "$@"
}

if ! run_node --check "$RUNTIME_DIR/src/main.js" \
  || ! run_node --check "$RUNTIME_DIR/src/preload.js" \
  || ! run_node --check "$RUNTIME_DIR/src/ui/app.js" \
  || ! run_node --check "$RUNTIME_DIR/src/ui/start.js" \
  || ! run_node --check "$RUNTIME_DIR/src/ui/error.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/blocklist.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/filter-rules.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/fingerprint.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/navigation.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/network.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/privacy.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/safety.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/settings.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/sponsor.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/tracker-learning.js" \
  || ! run_node --check "$RUNTIME_DIR/src/core/url.js" \
  || ! run_node "$RUNTIME_DIR/scripts/self-check.js"; then
  fatal "Aegis source preflight failed; the browser engine was not started."
fi

export ELECTRON_ENABLE_SECURITY_WARNINGS=true
export AEGIS_RUNTIME_DIR="$RUNTIME_DIR"

# Keep user-data scoped to Aegis rather than Electron's generic default. The
# main process also uses app.getPath('userData') for local settings only.
export AEGIS_ENGINE_TRUST="$ENGINE_TRUST_MODE"

echo "Engine trust: $ENGINE_TRUST_MODE"
echo "Engine archive: Electron $ELECTRON_VERSION ($ELECTRON_ARCH), pinned SHA-256 verified."
echo "Starting Aegis from its private runtime..."
echo "The Terminal window stays open while Aegis is running."
echo "Watch for: [Aegis startup] Browser window opened successfully."
echo ""

STATUS=0
"$ELECTRON_BIN" "$RUNTIME_DIR" || STATUS=$?

if (( STATUS != 0 )); then
  echo ""
  echo "Aegis exited with status $STATUS."
  echo "Launch log: $LOG_FILE"
  echo "Code-sign log: $CODESIGN_LOG"
  echo "Run Diagnose-Aegis.command and send the final startup lines if needed."
  pause_close
else
  echo ""
  echo "Aegis closed normally."
fi
exit "$STATUS"
