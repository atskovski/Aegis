#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is required to run verification."
  read "?Press Return to close..."
  exit 1
fi
echo "Running Aegis security and logic verification..."
set +e
npm run verify --if-present
STATUS=$?
set -e
if (( STATUS == 0 )); then
  echo ""
  echo "Aegis verification passed."
else
  echo ""
  echo "Aegis verification failed with status $STATUS."
fi
read "?Press Return to close..."
exit "$STATUS"
