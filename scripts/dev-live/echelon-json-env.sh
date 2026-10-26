#!/usr/bin/env bash
# Source this file (do not execute it) to run Locksmith's signet plugin against a local echelon-server
# started in json mode (onboarding.wire_format: json), i.e. with server-*.config.json.yaml.
#
# Order matters: start the server FIRST, then source this file. The server AID is read from the running
# server's /.well-known/udap, because the client takes it only from SIGNET_ONBOARDING_SERVER_AID and
# ignores any `aid` in the .well-known/keri document.
#
#   echelons serve ... --config scripts/dev-live/server-lesr.config.json.yaml     # 1. server
#   source scripts/dev-live/generated/env.out                                      # 2. chain env
#   source scripts/dev-live/echelon-json-env.sh                                    # 3. this file
#   cd ~/healthkeri/locksmith/src/locksmith && python main.py                      # 4. Locksmith
#
# Override ECHELON_URL / REGISTRAR_URL before sourcing if the server or registrar are elsewhere.
# Modelled on onyx-env.sh (the safhir run); unlike it, every endpoint comes from the discovery document.

ECHELON_URL="${ECHELON_URL:-http://127.0.0.1:8000}"
REGISTRAR_URL="${REGISTRAR_URL:-http://127.0.0.1:8080}"

_server_aid=$(curl -sf "${ECHELON_URL}/.well-known/udap" | python3 -c 'import json,sys; print(json.load(sys.stdin)["aid"])' 2>/dev/null)
if [ -z "${_server_aid}" ]; then
  echo "echelon-json-env.sh: no server AID from ${ECHELON_URL}/.well-known/udap; start echelon-server first" >&2
  unset _server_aid
  return 1 2>/dev/null || exit 1
fi

export LOCKSMITH_ENVIRONMENT=development
export SIGNET_LIVE=1
export SIGNET_PARTNER_URL="${ECHELON_URL}/.well-known/keri"
export SIGNET_ONBOARDING_FORMAT=json
export SIGNET_ONBOARDING_SERVER_AID="${_server_aid}"
export SIGNET_REGISTRAR_URL="${REGISTRAR_URL}"
unset _server_aid

# Negative test (matrix row 5): uncomment to send the packet without ipex_grant and expect a 400.
# export SIGNET_ONBOARDING_OMIT_GRANT=1

echo "signet json mode: ${SIGNET_PARTNER_URL} (server AID ${SIGNET_ONBOARDING_SERVER_AID})"
