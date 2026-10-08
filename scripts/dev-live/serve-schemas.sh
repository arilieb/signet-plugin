#!/bin/bash
# Build the combined schema directory for the vLEI-server: the vital LESR-chain schemas plus the GLEIF schemas
# (whose SAIDs are identical to the ones the vLEI repo serves). Both dev-live chains work against it.
#
#   scripts/dev-live/serve-schemas.sh          # build generated/schemas and print the vLEI-server command
#   scripts/dev-live/serve-schemas.sh --run    # build it and run vLEI-server in the foreground
#
# Restart vLEI-server after the first run so it serves the new SAIDs (a stale server answers 200 with an empty body).
set -euo pipefail
source "$( dirname "${BASH_SOURCE[0]}" )/env.sh"

VITAL_SCHEMA_DIR="${VITAL_SCHEMA_DIR:-$HOME/healthkeri/vital/schema}"
VLEI_DIR="${VLEI_DIR:-$HOME/healthkeri/vLEI}"
SCHEMAS="${DEV_LIVE_OUT}/schemas"

[ -d "$VITAL_SCHEMA_DIR/GLEIF" ] || { echo "vital schema dir not found: $VITAL_SCHEMA_DIR (set VITAL_SCHEMA_DIR)"; exit 1; }

rm -rf "$SCHEMAS"
mkdir -p "$SCHEMAS"
for f in "$VITAL_SCHEMA_DIR"/*.json "$VITAL_SCHEMA_DIR"/GLEIF/*.json; do
  [ "$(basename "$f")" = "schema-map.json" ] || ln -s "$f" "$SCHEMAS/$(basename "$f")"
done

# Every SAID the dev chains use must be a $id of exactly one served schema
for said in "$SCHEMA_QVI" "$SCHEMA_LE" "$SCHEMA_ECR_AUTH" "$SCHEMA_ECR" "$SCHEMA_LE_SUBUNIT" "$SCHEMA_LESR_AUTH" "$SCHEMA_LESR"; do
  n=$(jq -r '."$id"' "$SCHEMAS"/*.json | grep -cx "$said" || true)
  [ "$n" = 1 ] || { echo "schema $said found $n times in $SCHEMAS (expected 1)"; exit 1; }
done
echo "built $SCHEMAS ($(ls "$SCHEMAS" | wc -l | tr -d ' ') schemas)"

CMD=(vLEI-server -s "$SCHEMAS" -c ./samples/acdc -o ./samples/oobis -p 7723)
if [ "${1:-}" = "--run" ]; then
  cd "$VLEI_DIR" && exec "${CMD[@]}"
fi
echo "run it with (restart any running vLEI-server):"
echo "  cd $VLEI_DIR && ${CMD[*]}"
