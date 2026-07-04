#!/usr/bin/env bash
# check-registry.sh — valida public-registry.json antes de publicar.
# Corré esto (o agregalo a un pre-commit hook) tras editar el registro.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VALIDATOR="${VALIDATOR:-$HOME/osint/pubregistry-validate}"
if [ ! -x "$VALIDATOR" ]; then
  echo "check-registry: falta el binario en $VALIDATOR" >&2
  echo "  compilalo: (cd ~/osint && /usr/local/go/bin/go build -o pubregistry-validate ./cmd/pubregistry-validate/)" >&2
  exit 1
fi
"$VALIDATOR" "$HERE/public-registry.json"
