#!/bin/zsh
set -euo pipefail
SOURCE_DIR="${0:A:h}"

echo ""
echo "Aegis Privacy Browser — Browser + Web Smoke Test"
echo "────────────────────────────────────────────────"
echo "Aegis will open, load https://duckduckgo.com through a real isolated tab,"
echo "verify the external navigation completes, then close itself."
echo ""

set +e
AEGIS_SMOKE_TEST=1 AEGIS_SMOKE_TEST_URL="https://duckduckgo.com/" "$SOURCE_DIR/Run-Aegis.command"
STATUS=$?
set -e

echo ""
if (( STATUS == 0 )); then
  echo "Browser + external website smoke test completed successfully."
else
  echo "Smoke test failed with status $STATUS."
  echo "Run Diagnose-Aegis.command and use Settings → Diagnostics for network details."
fi
read "?Press Return to close..." || true
exit "$STATUS"
