#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
# Convenience wrapper around install.sh: uninstall Runbound.
#   ./uninstall.sh            remove service + binary, KEEP /etc/runbound + /var/lib/runbound
#   ./uninstall.sh --purge    also remove config, data and the runbound user/group
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -x "$DIR/install.sh" ] || { echo "install.sh not found next to uninstall.sh" >&2; exit 1; }
case "${1:-}" in
  --purge)            exec "$DIR/install.sh" --purge ;;
  ""|--uninstall)     exec "$DIR/install.sh" --uninstall ;;
  -h|--help)          echo "Usage: $0 [--purge]"; exit 0 ;;
  *)                  echo "Unknown option: $1 (try --help)" >&2; exit 1 ;;
esac
