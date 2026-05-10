#!/usr/bin/env bash
set -euo pipefail

echo "BKISC{testing}" > "/flag"

exec socat TCP-LISTEN:4058,reuseaddr,fork EXEC:"/opt/chal/powerful-dfs",stderr