#!/usr/bin/env bash
# Import live sing-box client configs into a sb-render config root.
# One-off migration helper; the generated tree contains real UUIDs.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${here}/import_live.py" "$@"
