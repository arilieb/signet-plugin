#!/bin/bash
# Issue the simple LESR chain (no Legal Entity Subunit) with kli, in two phases around Locksmith.
#
#   GLEIF External -> QVI -> LE (the holder AID itself, no Practice)
#     -> LESR Auth (issued by the holder in Locksmith, to the QVI, `le` edge) -> LESR (QVI -> holder AID)
#   QVI also issues an LE credential to Provider, the echelon-server identity.
#
# The holder IS the Legal Entity AID: its keys live only in the Locksmith vault, so Locksmith (the live-dev
# bootstrap, SIGNET_DEV_LESR_AUTH_FILE) issues the LESR Auth and grants it to the QVI. This script therefore
# writes env.out first, then waits for that grant before it can issue the LESR.
#
# Prerequisites: `kli witness demo` and vLEI-server on :7723 serving the combined schema dir (serve-schemas.sh).
# Run Locksmith with SIGNET_LIVE=1 first so the holder exists, then:
#
#   source scripts/dev-live/env.sh
#   scripts/dev-live/issue-chain-lesr-simple.sh <HOLDER_AID> [--reset] [--timeout SECONDS]
#
# When it prints "waiting", restart Locksmith with `source generated/env.out`. Everything lives under the keri base
# "signet-dev-live"; --reset deletes only that base (and is required to switch between the chain scripts).
# Credentials are issued without --private: the LESR-chain `a` blocks forbid `u`.
set -euo pipefail
source "$( dirname "${BASH_SOURCE[0]}" )/env.sh"

HOLDER_AID=""; RESET=""; TIMEOUT=600
while [ $# -gt 0 ]; do
  case "$1" in
    --reset) RESET=1 ;;
    --timeout) shift; TIMEOUT="${1:?--timeout needs a number of seconds}" ;;
    -*) echo "unknown option $1"; exit 1 ;;
    *) HOLDER_AID="$1" ;;
  esac
  shift
done
[ -n "$HOLDER_AID" ] || { echo "usage: $0 <HOLDER_AID> [--reset] [--timeout SECONDS]  (the signet-dev-holder AID Locksmith logs on vault open)"; exit 1; }

curl -s -m3 -o /dev/null http://127.0.0.1:5642/ || { echo "demo witnesses are not running (kli witness demo)"; exit 1; }
for s in "$SCHEMA_QVI" "$SCHEMA_LE" "$SCHEMA_LESR_AUTH" "$SCHEMA_LESR"; do
  curl -fsS -m3 "${SCHEMA_SERVER}/oobi/${s}" 2>/dev/null | grep -q "$s" \
    || { echo "vLEI-server does not serve schema ${s} on ${SCHEMA_SERVER}; run serve-schemas.sh and restart it with the combined dir"; exit 1; }
done

KERI_ROOT=/usr/local/var/keri
[ -d "$KERI_ROOT" ] || KERI_ROOT="$HOME/.keri"

if [ -n "$RESET" ]; then
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
new_aid Provider CDEyMzQ1Njc4OWxtbm9dl4

# Registrar: non-transferable, serves over HTTP on :8080 (Registrar.json curls)
kli init --name Registrar $KB --salt 0ACDEyMzQ1Njc4OWxtbm9dl5 --nopasscode $KCF
kli incept --name Registrar $KB --alias Registrar --icount 1 --isith 1 --ncount 1 --nsith 1 --toad 0 --config "${DEV_LIVE_DIR}"

EXTERNAL_AID=$(kli aid --name External $KB --alias External)
QVI_AID=$(kli aid --name QVI $KB --alias QVI)
PROVIDER_AID=$(kli aid --name Provider $KB --alias Provider)

# Every keystore resolves every other issuer identifier.
KEYSTORES=(External QVI Provider Registrar)
oobi_of() { kli oobi generate --name "$1" $KB --alias "$1" --role witness | sed -n '2 p'; }
for src in External QVI Provider; do
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
for k in External QVI; do resolve_holder "$k"; done

for k in External QVI; do
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
share External "$QVI_CRED" QVI Provider

# 2. QVI -> LE issued to the holder (the Legal Entity AID) and QVI -> LE (Provider, the server identity)
issue_le() {  # recipient-name recipient-aid data-file
  edges_file "${DEV_LIVE_OUT}/le-edges-$1.json" qvi "$QVI_CRED" "$SCHEMA_QVI"
  kli vc create --name QVI $KB --alias QVI --registry-name reg-QVI --schema "$SCHEMA_LE" --recipient "$2" \
    --data @"${DEV_LIVE_DIR}/data/$3" --edges @"${DEV_LIVE_OUT}/le-edges-$1.json" --rules @"${DEV_LIVE_DIR}/data/rules.json"
}
issue_le Holder "$HOLDER_AID" practice-le-data.json
HOLDER_LE=$(kli vc list --name QVI $KB --alias QVI --issued --said --schema "$SCHEMA_LE" | head -n1)
issue_le Provider "$PROVIDER_AID" provider-le-data.json
PROVIDER_LE=$(kli vc list --name QVI $KB --alias QVI --issued --said --schema "$SCHEMA_LE" | grep -v "^${HOLDER_LE}$" | head -n1)
share QVI "$PROVIDER_LE" Provider

# 3. Deliver the QVI and LE credentials to the holder over IPEX (it admits them in any order, retrying)
kli ipex grant --name External $KB --alias External --said "$QVI_CRED" --recipient "$HOLDER_AID"
kli ipex grant --name QVI $KB --alias QVI --said "$HOLDER_LE" --recipient "$HOLDER_AID"

# 4. The LESR Auth is issued by the holder in Locksmith: hand it the attributes and rules, plus the OOBIs/env it needs
LESR_AUTH_FILE="${DEV_LIVE_OUT}/lesr-auth.json"
sed "s/__HOLDER_AID__/${HOLDER_AID}/" "${DEV_LIVE_DIR}/data/lesr-auth-data.json.tmpl" > "${DEV_LIVE_OUT}/lesr-auth-data.json"
jq -n --slurpfile a "${DEV_LIVE_OUT}/lesr-auth-data.json" --slurpfile r "${DEV_LIVE_DIR}/data/rules.json" \
  '{attributes: $a[0], rules: $r[0]}' > "${LESR_AUTH_FILE}"

SCHEMA_OOBIS="${SCHEMA_SERVER}/oobi/${SCHEMA_LESR_AUTH},${SCHEMA_SERVER}/oobi/${SCHEMA_LESR}"
SIGNET_DEV_OOBIS="$(oobi_of External),$(oobi_of QVI),${SCHEMA_OOBIS}"
cat > "${DEV_LIVE_OUT}/env.out" <<OUT
export SIGNET_DEV_OOBIS='${SIGNET_DEV_OOBIS}'
export SIGNET_CREDENTIAL_SCHEMAS=${SCHEMA_LESR}
export SIGNET_DEV_LESR_AUTH_FILE=${LESR_AUTH_FILE}
export HOLDER_AID=${HOLDER_AID}
export QVI_AID=${QVI_AID}
OUT

cat <<WAIT

QVI and LE credentials granted to ${HOLDER_AID}.
Restart Locksmith with the generated environment so the holder admits them and issues the LESR Auth:

  source ${DEV_LIVE_OUT}/env.out

Waiting up to ${TIMEOUT}s for the LESR Auth grant from the holder...
WAIT

# 5. Wait for the holder's LESR Auth grant in the QVI keystore (kli polls the mailboxes ~5s per call), then admit it
AUTH_TITLE=$(curl -fsS -m3 "${SCHEMA_SERVER}/oobi/${SCHEMA_LESR_AUTH}" | jq -r .title)
auth_grants() {  # SAIDs of received grants whose credential is a LESR Auth (the verbose output prints "GRANT - SAID:" then "Type:")
  kli ipex list --name QVI $KB --alias QVI --type grant --poll \
    | awk -v t="$AUTH_TITLE" '/GRANT - SAID:/ {said=$NF} /Type:/ && index($0, t) {print said}'
}
GRANT=""
deadline=$((SECONDS + TIMEOUT))
while [ -z "$GRANT" ]; do
  GRANT=$(auth_grants | head -n1 || true)
  [ -n "$GRANT" ] && break
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "timed out waiting for the LESR Auth grant from ${HOLDER_AID}. Check that Locksmith was restarted with env.out" \
         "(SIGNET_DEV_LESR_AUTH_FILE set), that it admitted the QVI and LE credentials, and that the witnesses receipted the holder."
    exit 1
  fi
done
kli ipex admit --name QVI $KB --alias QVI --said "$GRANT"
LESR_AUTH=$(kli vc list --name QVI $KB --alias QVI --said --schema "$SCHEMA_LESR_AUTH" | head -n1)
[ -n "$LESR_AUTH" ] || { echo "the LESR Auth grant ${GRANT} was admitted but no LESR Auth credential is in the QVI keystore"; exit 1; }

# 6. QVI -> LESR for the holder (I2I: LESR issuer QVI == LESR Auth issuee QVI)
edges_file "${DEV_LIVE_OUT}/lesr-edges.json" auth "$LESR_AUTH" "$SCHEMA_LESR_AUTH" I2I
kli vc create --name QVI $KB --alias QVI --registry-name reg-QVI --schema "$SCHEMA_LESR" --recipient "$HOLDER_AID" \
  --data @"${DEV_LIVE_DIR}/data/lesr-data.json" --edges @"${DEV_LIVE_OUT}/lesr-edges.json" \
  --rules @"${DEV_LIVE_DIR}/data/rules.json"
LESR=$(said_of QVI "$SCHEMA_LESR")

# 7. Registrar serves the whole chain (its PUT / cannot ingest a multi-issuer chain, so import directly)
share QVI "$LESR" Registrar
kli ipex grant --name QVI $KB --alias QVI --said "$LESR" --recipient "$HOLDER_AID"
echo "export LESR_SAID=${LESR}" >> "${DEV_LIVE_OUT}/env.out"

cat <<DONE

Chain issued and granted to ${HOLDER_AID}.
  QVI ${QVI_AID}   Legal Entity (holder) ${HOLDER_AID}   Provider (server) ${PROVIDER_AID}
  LESR ${LESR}   LESR Auth ${LESR_AUTH} (issued by the holder)

Next:
  registrar start --name Registrar --base ${DEV_LIVE_BASE} --alias Registrar --issuer ${QVI_AID}
  (no echelon-server config is rendered for this chain; point Signet at your own server)
  Locksmith: the holder admits the LESR on its next maintenance pass; env.out already has the OOBIs/env.
DONE
