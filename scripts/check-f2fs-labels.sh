#!/usr/bin/env bash
# Audit label goto pada f2fs_fill_super (atau file C lain).
# Usage: bash scripts/check-f2fs-labels.sh fs/f2fs/super.c
set -euo pipefail

FILE="${1:-fs/f2fs/super.c}"
[ -f "$FILE" ] || { echo "File tidak ada: $FILE" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

grep -oE '\bgoto[[:space:]]+[A-Za-z_][A-Za-z0-9_]*' "$FILE" \
  | awk '{print $2}' | sort -u > "$TMP/gotos"

grep -oE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*:' "$FILE" \
  | sed -E 's/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*):.*/\1/' \
  | sort -u > "$TMP/labels"

echo "== goto tanpa label =="
comm -23 "$TMP/gotos" "$TMP/labels"

echo "== label tanpa goto (informasi) =="
comm -13 "$TMP/gotos" "$TMP/labels"
