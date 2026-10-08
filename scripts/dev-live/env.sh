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
# LESR chain (vital/schema; these may change on re-saidification, so they live only here)
export SCHEMA_LE_SUBUNIT="EP1jGIb7KXotuUZJf1NSu5wQ089epFfv93cpZECj-YBs"
export SCHEMA_LESR_AUTH="ECoqb1jxC9f9zwh664stMAy6gpnNduvP_3SCQlLvkPAR"
export SCHEMA_LESR="EHfJ563sbivepFRzk506fJenWIeVG2uXdAes8iJhHJan"

# vLEI-server serving the combined schema dir (see serve-schemas.sh)
export SCHEMA_SERVER="http://127.0.0.1:7723"

# kli --base shorthand; names have no spaces so $KB can be expanded unquoted
export KB="--base ${DEV_LIVE_BASE}"
export KCF="--config-dir ${DEV_LIVE_DIR} --config-file dev-live"
