#!/usr/bin/env bash
set -euo pipefail

ROOT="/opt/chal"

echo "BKISC{FLAG}" > "$ROOT/flag.txt"

exec python3 "$ROOT/server.py"
