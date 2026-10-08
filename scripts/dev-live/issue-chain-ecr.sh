#!/bin/bash
# Issue the ECR Auth credential chain with kli and deliver it to the Signet holder.
#
#   GLEIF External -> QVI -> LE (Practice) -> ECR Auth (to the QVI AID) -> ECR (QVI -> holder AID)
#   QVI also issues an LE credential to Provider, the echelon-server identity.
#
# Prerequisites: `kli witness demo` and vLEI-server on :7723 (see README run order).
# Run Locksmith with SIGNET_LIVE=1 first so the holder exists, then:
#
#   source scripts/dev-live/env.sh
#   scripts/dev-live/issue-chain-ecr.sh <HOLDER_AID> [--reset]
#
# Everything lives under the keri base "signet-dev-live"; --reset deletes only that base (and is required to switch
# between this chain and issue-chain-lesr.sh).
set -euo pipefail
source "$( dirname "${BASH_SOURCE[0]}" )/env.sh"

HOLDER_AID="${1:-}"
[ -n "$HOLDER_AID" ] || { echo "usage: $0 <HOLDER_AID> [--reset]  (the signet-dev-holder AID Locksmith logs on vault open)"; exit 1; }

curl -s -m3 -o /dev/null http://127.0.0.1:5642/ || { echo "demo witnesses are not running (kli witness demo)"; exit 1; }
curl -fsS -m3 "${SCHEMA_SERVER}/oobi/${SCHEMA_ECR}" >/dev/null || { echo "vLEI-server is not serving schemas on ${SCHEMA_SERVER} (see serve-schemas.sh)"; exit 1; }

KERI_ROOT=/usr/local/var/keri
[ -d "$KERI_ROOT" ] || KERI_ROOT="$HOME/.keri"

if [ "${2:-}" = "--reset" ]; then
  for d in "$KERI_ROOT"/*/"${DEV_LIVE_BASE}"; do
    [ -d "$d" ] && { echo "removing $d"; rm -rf "$d"; }
  done
  # keep generated/schemas (serve-schemas.sh output; vLEI-server reads it)
  find "${DEV_LIVE_OUT}" -mindepth 1 -maxdepth 1 ! -name schemas -exec rm -rf {} + 2>/dev/null || true
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
said_of() {  # keystore schema  (issued by this keystore)
  kli vc list --name "$1" $KB --alias "$1" --issued --said --schema "$2"
}

# 1. GLEIF External -> QVI
kli vc create --name External $KB --alias External --registry-name reg-External --schema "$SCHEMA_QVI" \
  --recipient "$QVI_AID" --data @"${DEV_LIVE_DIR}/data/qvi-data.json"
QVI_CRED=$(said_of External "$SCHEMA_QVI")
share External "$QVI_CRED" QVI Practice Provider

# 2. QVI -> LE (Practice, the org the ECR is for) and QVI -> LE (Provider, the server identity)
issue_le() {  # recipient-name recipient-aid data-file
  echo "\"$QVI_CRED\"" | jq -f "${DEV_LIVE_DIR}/data/qvi-edges-filter.jq" > "${DEV_LIVE_OUT}/le-edges-$1.json"
  kli saidify --file "${DEV_LIVE_OUT}/le-edges-$1.json"
  kli vc create --name QVI $KB --alias QVI --registry-name reg-QVI --schema "$SCHEMA_LE" --recipient "$2" \
    --data @"${DEV_LIVE_DIR}/data/$3" --edges @"${DEV_LIVE_OUT}/le-edges-$1.json" --rules @"${DEV_LIVE_DIR}/data/rules.json"
}
issue_le Practice "$PRACTICE_AID" practice-le-data.json
PRACTICE_LE=$(kli vc list --name QVI $KB --alias QVI --issued --said --schema "$SCHEMA_LE" | head -n1)
issue_le Provider "$PROVIDER_AID" provider-le-data.json
PROVIDER_LE=$(kli vc list --name QVI $KB --alias QVI --issued --said --schema "$SCHEMA_LE" | grep -v "^${PRACTICE_LE}$" | head -n1)
share QVI "$PRACTICE_LE" Practice
share QVI "$PROVIDER_LE" Provider

# 3. LE (Practice) -> ECR Auth, issued to the QVI AID, naming the holder AID as the authorized person
sed "s/__HOLDER_AID__/${HOLDER_AID}/" "${DEV_LIVE_DIR}/data/ecr-auth-data.json.tmpl" > "${DEV_LIVE_OUT}/ecr-auth-data.json"
echo "\"$PRACTICE_LE\"" | jq -f "${DEV_LIVE_DIR}/data/ecr-auth-edges-filter.jq" > "${DEV_LIVE_OUT}/ecr-auth-edges.json"
kli saidify --file "${DEV_LIVE_OUT}/ecr-auth-edges.json"
kli vc create --name Practice $KB --alias Practice --registry-name reg-Practice --schema "$SCHEMA_ECR_AUTH" \
  --recipient "$QVI_AID" --data @"${DEV_LIVE_OUT}/ecr-auth-data.json" \
  --edges @"${DEV_LIVE_OUT}/ecr-auth-edges.json" --rules @"${DEV_LIVE_DIR}/data/ecr-auth-rules.json"
ECR_AUTH=$(said_of Practice "$SCHEMA_ECR_AUTH")
share Practice "$ECR_AUTH" QVI

# 4. QVI -> ECR for the holder (I2I: ECR issuer QVI == ECR Auth issuee QVI)
echo "\"$ECR_AUTH\"" | jq -f "${DEV_LIVE_DIR}/data/ecr-edges-filter.jq" > "${DEV_LIVE_OUT}/ecr-edges.json"
kli saidify --file "${DEV_LIVE_OUT}/ecr-edges.json"
kli vc create --name QVI $KB --alias QVI --registry-name reg-QVI --schema "$SCHEMA_ECR" --recipient "$HOLDER_AID" \
  --private --data @"${DEV_LIVE_DIR}/data/ecr-data.json" --edges @"${DEV_LIVE_OUT}/ecr-edges.json" \
  --rules @"${DEV_LIVE_DIR}/data/ecr-rules.json"
ECR=$(said_of QVI "$SCHEMA_ECR")

# 5. Registrar serves the whole chain (its PUT / cannot ingest a multi-issuer chain, so import directly)
share QVI "$ECR" Registrar
for s in "$QVI_CRED" "$PRACTICE_LE" "$ECR_AUTH"; do kli vc import --name Registrar $KB --file "${DEV_LIVE_OUT}/${s}.cesr" || true; done

# 6. Deliver the chain to the holder over IPEX, issuers first (the holder admits them in any order, retrying)
kli ipex grant --name External $KB --alias External --said "$QVI_CRED" --recipient "$HOLDER_AID"
kli ipex grant --name QVI $KB --alias QVI --said "$PRACTICE_LE" --recipient "$HOLDER_AID"
kli ipex grant --name Practice $KB --alias Practice --said "$ECR_AUTH" --recipient "$HOLDER_AID"
kli ipex grant --name QVI $KB --alias QVI --said "$ECR" --recipient "$HOLDER_AID"

# 7. Outputs for the other processes
SERVER_CONFIG="${DEV_LIVE_DIR}/server-ecr.config.yaml"
render() {  # whitelist-line output
  sed -e "s/__EXTERNAL_AID__/${EXTERNAL_AID}/g" -e "s/__QVI_AID__/${QVI_AID}/g" -e "s/__PRACTICE_AID__/${PRACTICE_AID}/g" \
      -e "s|__WHITELIST__|$1|" "${DEV_LIVE_DIR}/server-ecr.config.yaml.tmpl" > "$2"
}
render "[{qvi_aid: ${QVI_AID}}]" "${DEV_LIVE_DIR}/server-ecr.config.yaml"
render "[]" "${DEV_LIVE_DIR}/server-ecr.config.review.yaml"

SIGNET_DEV_OOBIS="$(oobi_of External),$(oobi_of QVI),$(oobi_of Practice)"
cat > "${DEV_LIVE_OUT}/env.out" <<OUT
export SIGNET_DEV_OOBIS='${SIGNET_DEV_OOBIS}'
export HOLDER_AID=${HOLDER_AID}
export QVI_AID=${QVI_AID}
export SIGNET_CREDENTIAL_SCHEMAS=${SCHEMA_ECR}
export ECR_SAID=${ECR}
OUT
cat <<DONE

Chain issued and granted to ${HOLDER_AID}.
  QVI ${QVI_AID}   Practice LE ${PRACTICE_AID}   Provider (server) ${PROVIDER_AID}
  ECR ${ECR}   ECR Auth ${ECR_AUTH}

Next:
  registrar start --name Registrar --base ${DEV_LIVE_BASE} --alias Registrar --issuer ${QVI_AID}
  echelons serve --host 127.0.0.1 --port 8000 --name Provider --base ${DEV_LIVE_BASE} --alias Provider --config ${SERVER_CONFIG}
  Locksmith: source ${DEV_LIVE_OUT}/env.out (restart so it resolves the issuer OOBIs and admits the grants)
DONE
