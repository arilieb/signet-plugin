#!/bin/bash
# Source this file: environment shared by the dev-live scripts.
#
# All keystores live under the keri "base" below (e.g. /usr/local/var/keri/ks/signet-dev-live/QVI), so they
# never collide with, and `--reset` never touches, any other keystore.

DEV_LIVE_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export DEV_LIVE_DIR
export DEV_LIVE_BASE="signet-dev-live"
export DEV_LIVE_OUT="${DEV_LIVE_DIR}/generated"

# vLEI schema SAIDs
export SCHEMA_QVI="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
export SCHEMA_LE="ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
export SCHEMA_ECR_AUTH="EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g"
export SCHEMA_ECR="EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"

# kli --base shorthand; names have no spaces so $KB can be expanded unquoted
export KB="--base ${DEV_LIVE_BASE}"
export KCF="--config-dir ${DEV_LIVE_DIR} --config-file dev-live"
