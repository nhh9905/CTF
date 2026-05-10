#!/usr/bin/env bash
set -euo pipefail

echo "BKISC{fake_flag}" > "/opt/chal/flag.txt"
exec socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/opt/chal/chall,stderr