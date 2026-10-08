#!/bin/bash
# Issue the LESR credential chain with kli and deliver it to the Signet holder.
#
#   GLEIF External -> QVI -> LE (Practice) -> LE Subunit (Practice -> holder)
#     -> LESR Auth (Practice -> QVI AID, names the holder) -> LESR (QVI -> holder AID)
#   QVI also issues an LE credential to Provider, the echelon-server identity.
#
# Prerequisites: `kli witness demo` and vLEI-server on :7723 serving the combined schema dir (serve-schemas.sh).
# Run Locksmith with SIGNET_LIVE=1 first so the holder exists, then:
#
#   source scripts/dev-live/env.sh
#   scripts/dev-live/issue-chain-lesr.sh <HOLDER_AID> [--reset]
#
# Everything lives under the keri base "signet-dev-live"; --reset deletes only that base (and is required to switch
# between this chain and issue-chain-ecr.sh). Credentials are issued without --private: the LESR-chain `a` blocks forbid `u`.
set -euo pipefail
source "$( dirname "${BASH_SOURCE[0]}" )/env.sh"

HOLDER_AID="${1:-}"
[ -n "$HOLDER_AID" ] || { echo "usage: $0 <HOLDER_AID> [--reset]  (the signet-dev-holder AID Locksmith logs on vault open)"; exit 1; }

curl -s -m3 -o /dev/null http://127.0.0.1:5642/ || { echo "demo witnesses are not running (kli witness demo)"; exit 1; }
for s in "$SCHEMA_QVI" "$SCHEMA_LE" "$SCHEMA_LE_SUBUNIT" "$SCHEMA_LESR_AUTH" "$SCHEMA_LESR"; do
  curl -fsS -m3 "${SCHEMA_SERVER}/oobi/${s}" 2>/dev/null | grep -q "$s" \
    || { echo "vLEI-server does not serve schema ${s} on ${SCHEMA_SERVER}; run serve-schemas.sh and restart it with the combined dir"; exit 1; }
done

KERI_ROOT=/usr/local/var/keri
[ -d "$KERI_ROOT" ] || KERI_ROOT="$HOME/.keri"

if [ "${2:-}" = "--reset" ]; then
  for d in "$KERI_ROOT"/*/"${DEV_LIVE_BASE}"; do
    [ -d "$d" ] && { echo "removing $d"; rm -rf "$d"; }
  done
  # keep generated/schemas (serve-schemas.sh output; vLEI-server reads it)
  find "${DEV_LIVE_OUT}" -mindepth 1 -maxdepth 1 ! -name schemas -exec rm -rf {} +
elif kli aid --name External --base "${DEV_LIVE_BASE}" --alias External >/dev/null 2>&1; then
  echo "keystores already exist under base ${DEV_LIVE_BASE}; re-run with --reset"; exit 1
fi
mkdir -p "${DEV_LIVE_OUT}"

new_aid() {  # name salt
  kli init --name "$1" $KB --salt "0A$2" --nopasscode $KCF
  kli incept --name "$1" $KB --alias "$1" --file "${DEV_LIVE_DIR}/data/base-aid.json"
}
new_aid External CDEyMzQ1Njc4OWxtbm9dl1
new_aid QVI      CDEyMzQ1Njc4OWxtbm9dl2
new_aid Practice CDEyMzQ1Njc4OWxtbm9dl3
new_aid Provider CDEyMzQ1Njc4OWxtbm9dl4

# Registrar: non-transferable, serves over HTTP on :8080 (Registrar.json curls)
kli init --name Registrar $KB --salt 0ACDEyMzQ1Njc4OWxtbm9dl5 --nopasscode $KCF
kli incept --name Registrar $KB --alias Registrar --icount 1 --isith 1 --ncount 1 --nsith 1 --toad 0 --config "${DEV_LIVE_DIR}"

EXTERNAL_AID=$(kli aid --name External $KB --alias External)
QVI_AID=$(kli aid --name QVI $KB --alias QVI)
PRACTICE_AID=$(kli aid --name Practice $KB --alias Practice)
PROVIDER_AID=$(kli aid --name Provider $KB --alias Provider)

# Every keystore resolves every other issuer/holder identifier.
KEYSTORES=(External QVI Practice Provider Registrar)
oobi_of() { kli oobi generate --name "$1" $KB --alias "$1" --role witness | sed -n '2 p'; }
for src in External QVI Practice Provider; do
  OOBI=$(oobi_of "$src")
  for dst in "${KEYSTORES[@]}"; do
    [ "$src" = "$dst" ] || kli oobi resolve --name "$dst" $KB --oobi-alias "$src" --oobi "$OOBI"
  done
done

# The holder is witnessed by the demo witnesses; try each until its KEL resolves.
resolve_holder() {  # keystore
  for port in 5642 5643 5644; do
    if kli oobi resolve --name "$1" $KB --oobi-alias holder --oobi "http://127.0.0.1:${port}/oobi/${HOLDER_AID}" ; then return 0; fi
  done
  echo "could not resolve holder ${HOLDER_AID} from any witness; is Locksmith running with SIGNET_LIVE=1 and has it been receipted?"; return 1
}
for k in External QVI Practice; do resolve_holder "$k"; done

for k in External QVI Practice; do
  kli vc registry incept --name "$k" $KB --alias "$k" --registry-name "reg-$k"
done

# Local import helper: export from the issuer's keystore, import into another
share() {  # issuer-keystore said dest-keystore...
  local issuer=$1 said=$2; shift 2
  kli vc export --name "$issuer" $KB --alias "$issuer" --said "$said" --full > "${DEV_LIVE_OUT}/${said}.cesr"
  for dst in "$@"; do kli vc import --name "$dst" $KB --file "${DEV_LIVE_OUT}/${said}.cesr"; done
}
said_of() {  # keystore schema  (issued by this keystore; fails unless exactly one match)
  local out; out=$(kli vc list --name "$1" $KB --alias "$1" --issued --said --schema "$2")
  [ "$(echo "$out" | grep -c .)" = 1 ] || { echo "expected exactly one $2 credential issued by $1, got: ${out:-none}" >&2; return 1; }
  echo "$out"
}
edges_file() {  # out-file edge-name node-said schema-said [operator]  (SAIDified edge block)
  jq -n --arg k "$2" --arg n "$3" --arg s "$4" --arg o "${5:-}" \
    '{d: "", ($k): ({n: $n, s: $s} + (if $o == "" then {} else {o: $o} end))}' > "$1"
  kli saidify --file "$1"
}

# 1. GLEIF External -> QVI
kli vc create --name External $KB --alias External --registry-name reg-External --schema "$SCHEMA_QVI" \
  --recipient "$QVI_AID" --data @"${DEV_LIVE_DIR}/data/qvi-data.json"
QVI_CRED=$(said_of External "$SCHEMA_QVI")
share External "$QVI_CRED" QVI Practice Provider

# 2. QVI -> LE (Practice, the org the LESR is for) and QVI -> LE (Provider, the server identity)
issue_le() {  # recipient-name recipient-aid data-file
  edges_file "${DEV_LIVE_OUT}/le-edges-$1.json" qvi "$QVI_CRED" "$SCHEMA_QVI"
  kli vc create --name QVI $KB --alias QVI --registry-name reg-QVI --schema "$SCHEMA_LE" --recipient "$2" \
    --data @"${DEV_LIVE_DIR}/data/$3" --edges @"${DEV_LIVE_OUT}/le-edges-$1.json" --rules @"${DEV_LIVE_DIR}/data/rules.json"
}
issue_le Practice "$PRACTICE_AID" practice-le-data.json
PRACTICE_LE=$(kli vc list --name QVI $KB --alias QVI --issued --said --schema "$SCHEMA_LE" | head -n1)
issue_le Provider "$PROVIDER_AID" provider-le-data.json
PROVIDER_LE=$(kli vc list --name QVI $KB --alias QVI --issued --said --schema "$SCHEMA_LE" | grep -v "^${PRACTICE_LE}$" | head -n1)
share QVI "$PRACTICE_LE" Practice
share QVI "$PROVIDER_LE" Provider

# 3. LE (Practice) -> LE Subunit, issued to the holder (NI2I back to the LE credential)
edges_file "${DEV_LIVE_OUT}/lesr-subunit-edges.json" le "$PRACTICE_LE" "$SCHEMA_LE" NI2I
kli vc create --name Practice $KB --alias Practice --registry-name reg-Practice --schema "$SCHEMA_LE_SUBUNIT" \
  --recipient "$HOLDER_AID" --data @"${DEV_LIVE_DIR}/data/lesr-subunit-data.json" \
  --edges @"${DEV_LIVE_OUT}/lesr-subunit-edges.json" --rules @"${DEV_LIVE_DIR}/data/rules.json"
SUBUNIT=$(said_of Practice "$SCHEMA_LE_SUBUNIT")

# 4. LE (Practice) -> LESR Authorization, issued to the QVI AID, naming the holder AID (NI2I to the Subunit)
sed "s/__HOLDER_AID__/${HOLDER_AID}/" "${DEV_LIVE_DIR}/data/lesr-auth-data.json.tmpl" > "${DEV_LIVE_OUT}/lesr-auth-data.json"
edges_file "${DEV_LIVE_OUT}/lesr-auth-edges.json" subunit "$SUBUNIT" "$SCHEMA_LE_SUBUNIT" NI2I
kli vc create --name Practice $KB --alias Practice --registry-name reg-Practice --schema "$SCHEMA_LESR_AUTH" \
  --recipient "$QVI_AID" --data @"${DEV_LIVE_OUT}/lesr-auth-data.json" \
  --edges @"${DEV_LIVE_OUT}/lesr-auth-edges.json" --rules @"${DEV_LIVE_DIR}/data/rules.json"
LESR_AUTH=$(said_of Practice "$SCHEMA_LESR_AUTH")
share Practice "$LESR_AUTH" QVI   # --full carries the Subunit, LE and QVI credentials too

# 5. QVI -> LESR for the holder (I2I: LESR issuer QVI == LESR Auth issuee QVI)
edges_file "${DEV_LIVE_OUT}/lesr-edges.json" auth "$LESR_AUTH" "$SCHEMA_LESR_AUTH" I2I
kli vc create --name QVI $KB --alias QVI --registry-name reg-QVI --schema "$SCHEMA_LESR" --recipient "$HOLDER_AID" \
  --data @"${DEV_LIVE_DIR}/data/lesr-data.json" --edges @"${DEV_LIVE_OUT}/lesr-edges.json" \
  --rules @"${DEV_LIVE_DIR}/data/rules.json"
LESR=$(said_of QVI "$SCHEMA_LESR")

# 6. Registrar serves the whole chain (its PUT / cannot ingest a multi-issuer chain, so import directly)
share QVI "$LESR" Registrar

# 7. Deliver the chain to the holder over IPEX, issuers first (the holder admits them in any order, retrying)
kli ipex grant --name External $KB --alias External --said "$QVI_CRED" --recipient "$HOLDER_AID"
kli ipex grant --name QVI $KB --alias QVI --said "$PRACTICE_LE" --recipient "$HOLDER_AID"
kli ipex grant --name Practice $KB --alias Practice --said "$SUBUNIT" --recipient "$HOLDER_AID"
kli ipex grant --name Practice $KB --alias Practice --said "$LESR_AUTH" --recipient "$HOLDER_AID"
kli ipex grant --name QVI $KB --alias QVI --said "$LESR" --recipient "$HOLDER_AID"

# 8. Outputs for the other processes
SERVER_CONFIG="${DEV_LIVE_DIR}/server-lesr.config.yaml"
render() {  # whitelist-line output
  sed -e "s/__EXTERNAL_AID__/${EXTERNAL_AID}/g" -e "s/__QVI_AID__/${QVI_AID}/g" -e "s/__PRACTICE_AID__/${PRACTICE_AID}/g" \
      -e "s/__SCHEMA_QVI__/${SCHEMA_QVI}/g" -e "s/__SCHEMA_LE__/${SCHEMA_LE}/g" \
      -e "s/__SCHEMA_LE_SUBUNIT__/${SCHEMA_LE_SUBUNIT}/g" -e "s/__SCHEMA_LESR_AUTH__/${SCHEMA_LESR_AUTH}/g" \
      -e "s/__SCHEMA_LESR__/${SCHEMA_LESR}/g" \
      -e "s|__WHITELIST__|$1|" "${DEV_LIVE_DIR}/server-lesr.config.yaml.tmpl" > "$2"
}
render "[{qvi_aid: ${QVI_AID}}]" "${SERVER_CONFIG}"
render "[]" "${DEV_LIVE_DIR}/server-lesr.config.review.yaml"

# Schema OOBIs for the LESR-chain SAIDs ride along with the issuer OOBIs so Locksmith resolves them at startup
SCHEMA_OOBIS="${SCHEMA_SERVER}/oobi/${SCHEMA_LE_SUBUNIT},${SCHEMA_SERVER}/oobi/${SCHEMA_LESR_AUTH},${SCHEMA_SERVER}/oobi/${SCHEMA_LESR}"
SIGNET_DEV_OOBIS="$(oobi_of External),$(oobi_of QVI),$(oobi_of Practice),${SCHEMA_OOBIS}"
cat > "${DEV_LIVE_OUT}/env.out" <<OUT
export SIGNET_DEV_OOBIS='${SIGNET_DEV_OOBIS}'
export SIGNET_CREDENTIAL_SCHEMAS=${SCHEMA_LESR}
export HOLDER_AID=${HOLDER_AID}
export QVI_AID=${QVI_AID}
export LESR_SAID=${LESR}
OUT
cat <<DONE

Chain issued and granted to ${HOLDER_AID}.
  QVI ${QVI_AID}   Practice LE ${PRACTICE_AID}   Provider (server) ${PROVIDER_AID}
  LESR ${LESR}   LESR Auth ${LESR_AUTH}   LE Subunit ${SUBUNIT}

Next:
  registrar start --name Registrar --base ${DEV_LIVE_BASE} --alias Registrar --issuer ${QVI_AID}
  echelons serve --host 127.0.0.1 --port 8000 --name Provider --base ${DEV_LIVE_BASE} --alias Provider --config ${SERVER_CONFIG}
  Locksmith: source ${DEV_LIVE_OUT}/env.out (restart so it resolves the issuer/schema OOBIs and admits the grants)
DONE
