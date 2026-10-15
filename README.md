# signet-plugin
Connection + FHIR API KIM plugin client

Locksmith plugin implementing "Keriguard Signet": a Connections CRUD that walks a user through
Onyx's asynchronous UDAP vLEI onboarding flow (submit an onboarding request, poll/refresh for
approval, then complete Dynamic Client Registration). A second menu item, FHIR APIs, opens a
table of FHIR endpoints: pick a registered connection, then a Group ID, to list that Group's
endpoints. Clicking a row first authenticates against the selected connection (reusing a
still-valid access token), then runs the (currently placeholder) downstream action. In mock mode
the Groups/endpoints are fixtures; outside mock mode the Group list is empty for now.

The FHIR APIs screen needs `TwoStageSelectionTableWidget` from a matching locksmith change
(locksmith branch `feat-non-sassy-witness`, not yet released). Deploy the two together: against an
older locksmith the FHIR APIs menu entry stays disabled and the rest of the plugin still loads.

This is UI/UX scaffolding: Onyx owns and will stand up the actual `/udap/onboarding*` servers, so
remoting hits the real endpoint shapes but short-circuits to canned responses when
`LOCKSMITH_ENVIRONMENT=development`, seeded with two dummy connections (Onyx, Cambia) so the flow
is demoable today.

## Setup

Copy the `src/signet` dir from this repo into the `src/locksmith/plugins` dir in the locksmith
repo.

Add the following line to the `[project.entry-points."locksmith.plugins"]` section in
`pyproject.toml` in the locksmith repo:

```toml
[project.entry-points."locksmith.plugins"]
signet = "locksmith.plugins.signet.plugin:SignetPlugin"
```

Copy the files from `assets/material-icons` in this repo into `assets/material-icons` in the
locksmith repo, then regenerate resources from the locksmith repo:

```
python ./scripts/generate_qrc.py && pyside6-rcc resources.qrc -o resources_rc.py && mv resources_rc.py ./src/locksmith
```

From the locksmith repo venv, run `pip install -e .`.

## Live local onboarding (development)

> **Status:** these scripts and steps were written but not yet run end to end. Treat every command as unverified until you have run it.

By default `LOCKSMITH_ENVIRONMENT=development` runs signet in mock mode (canned responses, fake seeded connections). Setting `SIGNET_LIVE=1` in development switches to the real single-IPEX-grant onboarding (the grant's exn signature is the only signature) against local infrastructure. Three credential chains are supported (pick one per run; see Troubleshooting for switching):

- **LESR subunit** (the main onboarding credential, `issue-chain-lesr-subunit.sh`): GLEIF External -> QVI -> LE (Practice) -> LE Subunit (Practice -> holder AID) -> LESR Auth (Practice -> QVI AID) -> LESR (QVI -> holder AID). The chain is linear: the LESR has a single `auth` edge.
- **LESR simple** (for orgs without subunits, `issue-chain-lesr-simple.sh`): GLEIF External -> QVI -> LE (issued to the holder AID, which *is* the Legal Entity AID) -> LESR Auth (holder -> QVI AID, `le` edge) -> LESR (QVI -> holder AID). The holder's keys live only in the Locksmith vault, so the live-dev bootstrap issues the LESR Auth in-process and grants it to the QVI (`SIGNET_DEV_LESR_AUTH_FILE`); the script waits for that grant before it issues the LESR. No echelon-server config is rendered for this chain.
- **ECR** (`issue-chain-ecr.sh`): GLEIF External -> QVI -> LE (Practice) -> ECR Auth (to the QVI AID) -> ECR (QVI -> holder AID).

### Environment variables

| Variable | Purpose |
|---|---|
| `SIGNET_LIVE=1` | Live dev mode (only honored when `LOCKSMITH_ENVIRONMENT=development`) |
| `SIGNET_REGISTRAR_URL` | Registrar hosting the credential chain, e.g. `http://127.0.0.1:8080` |
| `SIGNET_PARTNER_URL` | Local Echelon base URL (default `http://127.0.0.1:8000`), or the full URL of a partner's `.well-known/keri` document (see [Demo against a `.well-known/keri` server](#demo-against-a-well-knownkeri-server)) |
| `SIGNET_ONBOARDING_FORMAT` | `json` sends the JSON submission packet, whose `ipex_grant` is the full credential chain as one CESR stream ending in the grant exn; anything else (default `cesr`) sends the single CESR grant |
| `SIGNET_ONBOARDING_ENDPOINT` | Replaces the `onboarding_endpoint` advertised by a `.well-known/keri` document (ignored for `.well-known/udap` discovery) |
| `SIGNET_REGISTRATION_ENDPOINT` | With `SIGNET_ONBOARDING_FORMAT=json`: replaces the `registration_endpoint` advertised by a `.well-known/keri` document (ignored otherwise) |
| `SIGNET_TOKEN_ENDPOINT` | With `SIGNET_ONBOARDING_FORMAT=json`: replaces the advertised `token_endpoint` (ignored otherwise) |
| `SIGNET_DCR_OOBI` | With `SIGNET_ONBOARDING_FORMAT=json`: single OOBI URL sent as `oobi` in the registration request instead of the presenter's first witness OOBI |
| `SIGNET_ONBOARDING_OMIT_GRANT` | `1`/`true` sends the JSON packet without `ipex_grant` (the field is optional server-side while its grant verification is unfinished); the server AID is then not needed |
| `SIGNET_ONBOARDING_OOBI` | Comma-separated OOBI URLs that replace the witness-derived `legal_entity.oobi` in the JSON packet (e.g. when the witnesses are not reachable from the partner) |
| `SIGNET_ASSUME_PALANTIR_OOBIS` | `1`/`true` assumes every OOBI is hosted at `https://palantir.healthkeri.net/oobi/{aid}` and skips the keripy witness lookup (so an identifier without witnesses no longer errors). Applies to all OOBIs signet builds: the DCR `oobi`, the `oobis` array and the JSON packet's `legal_entity.oobi`. `SIGNET_DCR_OOBI` and `SIGNET_ONBOARDING_OOBI` still take precedence |
| `SIGNET_ONBOARDING_SERVER_AID` | AID the grant is addressed to when the discovery document advertises none (`.well-known/keri`) |
| `SIGNET_CREDENTIAL_SCHEMAS` | Comma-separated schema SAIDs of the credentials offered in Add Connection (default: the LESR schema); written by the issue scripts to `env.out` (the LESR SAID for `issue-chain-lesr-subunit.sh`) |
| `SIGNET_DEV_LESR_AUTH_FILE` | Live dev, LESR simple chain only: JSON file (`{"attributes": ..., "rules": ...}`) written by `issue-chain-lesr-simple.sh` to `env.out`. When set, once the holder has admitted an LE credential issued to it, the bootstrap issues a LESR Auth from the holder to that credential's issuer (the QVI) and IPEX-grants it. Unset, the other chains are untouched |
| `SIGNET_DEV_OOBIS` | Comma-separated extra OOBIs the bootstrap resolves (External, QVI, Practice, and the chain's schema OOBIs); written by `issue-chain-ecr.sh` / `issue-chain-lesr-subunit.sh` to `scripts/dev-live/generated/env.out` |
| `SIGNET_FHIR_BASE_URL` | Replaces the FHIR base URL otherwise derived from the connection's `base_url` (with `/.well-known/...` stripped), e.g. `https://api-dmdh-dev.safhir.io/v1/api/pvav2` |
| `SIGNET_EXPORT_STATUS_URL_PREFIX` | Replaces the `$davinci-data-export` status URL the server returns in `Content-Location`: signet polls this prefix with the export task id (the last path segment of the advertised URL) appended, e.g. `https://api-dmdh-dev.safhir.io/v1/api/pvav2/Group/davinci-data-export-status/` |
| `SIGNET_EXPORT_METHOD` | `GET` starts `$davinci-data-export` with a GET and no body; anything else (default) POSTs `{"exportType": "hl7.fhir.us.davinci-pdex#provider-snapshot"}` |

### Prerequisites

- keripy `kli`, echelon-server, Locksmith, the registrar and vLEI each in their own venv. Registrar pins `keri~=1.3.4`; the others use 1.3.6 (the local keripy checkout reports 1.3.5), so keep each tool in its own environment.
- Keystores are created under the keri base `signet-dev-live`; `--reset` deletes only that base. Never `rm -rf /usr/local/var/keri`.

### Run order

#### Clean up
```bash
rm -rf ~/.acdc/db/oauth2
rm -rf /usr/local/var/keri/*
```

#### 1 witnesses (keripy venv)
```bash
cd ~/healthkeri/keripy && kli witness demo
```
#### 2 schemas
Build the combined schema directory (vital's LESR-chain schemas plus the GLEIF ones, symlinked into `scripts/dev-live/generated/schemas`) and serve it. This replaces the default `-s ./schema/acdc` and is needed by both chains, because `dev-live.json` resolves the new schema OOBIs at `kli init`.
```bash
cd ~/healthkeri/signet-plugin && scripts/dev-live/serve-schemas.sh          # builds the dir, prints the command
cd ~/healthkeri/vLEI && vLEI-server -s ~/healthkeri/signet-plugin/scripts/dev-live/generated/schemas -c ./samples/acdc -o ./samples/oobis -p 7723
```
(`serve-schemas.sh --run` builds and launches it in one step.) Restart any vLEI-server that is already running. Check that each new schema OOBI returns the schema JSON, not an empty 200: `curl http://127.0.0.1:7723/oobi/<SAID>` (SAIDs are in `scripts/dev-live/env.sh`).

#### 3 Locksmith + signet in live dev; 
on vault open the holder "signet-dev-holder" is created and its AID logged. Leave it running (it must receive the grants).
```bash
cd ~/healthkeri/locksmith/src/locksmith && LOCKSMITH_ENVIRONMENT=development SIGNET_LIVE=1 \
  SIGNET_REGISTRAR_URL=http://127.0.0.1:8080 python main.py
```

#### 4 issue the chain and grant it to the holder
```bash
cd ~/healthkeri/signet-plugin && scripts/dev-live/issue-chain-lesr-subunit.sh EDqyx_rMkeZT63D41DjSstHUDwx_1W_0qtnKz30iGIJb --reset
# or, for the ECR chain: scripts/dev-live/issue-chain-ecr.sh <HOLDER_AID> --reset
```
Simple chain (no subunit): the script blocks half way, so the order differs:
```bash
scripts/dev-live/issue-chain-lesr-simple.sh <HOLDER_AID> --reset [--timeout 600]
# when it prints "Waiting ... for the LESR Auth grant": in another terminal, restart Locksmith with
source scripts/dev-live/generated/env.out   # then start Locksmith as in step 3
# Locksmith admits the QVI + LE credentials, issues the LESR Auth and grants it to the QVI; the script then issues the LESR
```
Step 6 (echelon-server) is not used for this chain. Afterwards the vault holds the LESR, LESR Auth, LE and QVI credentials.
Restart Locksmith with: 
```bash
source scripts/dev-live/generated/env.out
```
so the issuer OOBIs resolve and the pending grants are admitted

With `SIGNET_ONBOARDING_FORMAT=json` the vault must hold all chain credentials (five for the subunit chain, four for the simple chain) (and the issuer KELs) before Add, since the whole chain is sent. A `PresentingError` naming an incomplete chain means: wait for the grants to be admitted, or restart Locksmith.

#### 5 registrar 
(own venv; no passcode, matching the keystore)
```bash
registrar start --name Registrar --base signet-dev-live --alias Registrar --issuer <QVI_AID>
```

#### 6 echelon-server
```bash
cd ~/healthkeri/echelon-server && echelons serve --host 127.0.0.1 --port 8000 \
  --name Provider --base signet-dev-live --alias Provider \
  --config ~/healthkeri/signet-plugin/scripts/dev-live/server-lesr.config.yaml
```

The issue script prints the QVI AID and the exact commands for steps 5-6. For the ECR chain use `server-ecr.config.yaml` instead.

The server configs allow the `client_credentials` grant (used by Authenticate). A dev client registered before that change keeps its old grant types: regenerate the configs with `issue-chain-*.sh --reset`, restart the server and register again.

In the UI: Connections -> Add -> "Local Echelon" -> pick the LESR credential (the ECR for the ECR chain), enter the redirect URIs (one per line, e.g. `http://127.0.0.1:9000/cb`) -> submit; use Refresh to poll. The redirect URIs are approved with onboarding.

Onboarding sends one IPEX grant exn of the selected credential (the LESR) to `POST /udap/onboarding`; its `a.udap` carries the requested purposes, contacts, redirect URIs, correlation id and typed OOBIs. The credential's issuee must be the sending identifier, otherwise the server answers 403.

Once the connection is approved (green), the DCR gate offers "Proceed": signet builds an IPEX grant exn carrying `a.udap` (purpose, client_name, redirect_uris), POSTs it to `/register`, and shows the returned `client_id` (201; repeating it returns the same client). Failures show the RFC 7591 error and `correlation_id`.

### Demo against a `.well-known/keri` server

For a partner that publishes `.../.well-known/keri` (e.g. `https://api-dmdh-dev.safhir.io/slapv3/pdexv2/.well-known/keri`), onboarding POSTs the JSON packet described in `SUBMISSION_SHAPE.md`, with the full credential chain (issuer KELs, TELs, chained credentials, then the IPEX grant exn) as one CESR stream in `ipex_grant`. In a non-development Locksmith environment:

```bash
SIGNET_PARTNER_URL=https://api-dmdh-dev.safhir.io/slapv3/pdexv2/.well-known/keri \
SIGNET_ONBOARDING_FORMAT=json \
SIGNET_ONBOARDING_SERVER_AID=<server AID> \
SIGNET_ONBOARDING_ENDPOINT=https://api-dmdh-dev.safhir.io/slapv3/keri/udap/onboarding \
python main.py
```

Then Connections -> Add -> select the partner (listed by host) -> submit. The partner is offered whenever `SIGNET_PARTNER_URL` is set outside mock mode, independent of `SIGNET_LIVE`. The onboarding endpoint comes from the document's `onboarding_endpoint`, unless `SIGNET_ONBOARDING_ENDPOINT` overrides it. The dev document currently advertises the wrong host (`osfsdmdhdevslapapi.azurewebsites.net`, which answers 403 `Ip Forbidden` from non-allowlisted IPs), hence the override above (the status URL the server returns in `Content-Location` has the same wrong host, so it is moved onto the override's host, keeping its path). The document also advertises no server AID, hence `SIGNET_ONBOARDING_SERVER_AID`.

While the server's grant verification is under construction, set `SIGNET_ONBOARDING_OMIT_GRANT=1` to send the packet without `ipex_grant` (then `SIGNET_ONBOARDING_SERVER_AID` is not needed either).

Assumptions (adjust once tried against the real server):
- QVI LEI, purpose (`TREAT`), scopes and contacts are hardcoded demo values (`presenting.DEMO_*`; the LEI too when the credentials carry none), and `client_metadata` is `{}`; the redirect URIs from the dialog are ignored.
- `ipex_grant` ends in a plain grant exn (`a = {m, i}`, no `a.udap`), preceded by the chain artifacts. `submitter` carries only `role`; no `ecr_said`/`lesr_said`.
- `legal_entity` is the Legal Entity Subunit: `aid` and `lei` are the issuee and `LEI` of the chain's LE Subunit credential (the holder AID in the LESR chain). Without a subunit (the ECR chain) they come from the chain's Legal Entity credential, and without that from the holder AID and the demo LEI. `oobi` lists that AID's witness `/oobi/{aid}` URLs, unless `SIGNET_ONBOARDING_OOBI` overrides them.
- No HTTP signature headers; the response is assumed echelon-like (unauthenticated, 202/200 with `onboarding_id` (or `review_id`), `status`, `decision_due`, `Content-Location`). Polling needs a `Content-Location`.
- With `SIGNET_ONBOARDING_FORMAT=json`, Registration (DCR) POSTs to the document's `registration_endpoint` (or `SIGNET_REGISTRATION_ENDPOINT`; mind its trailing slash, Django may redirect a POST without one) the body `{ipex_grant, oobi, purpose, client_name, grant_types: ["client_credentials"]}`: `ipex_grant` is the same plain chain stream as onboarding (fresh `dt` per call, addressed to the server AID), `oobi` is the presenter's first witness OOBI (`SIGNET_DCR_OOBI` overrides), `purpose` is the requested purpose, and no `redirect_uris` are sent. `201` (first registration) and `200` (re-registration) both succeed and return `client_id` and a space-separated `scope`. A `400 unapproved_software_statement` shows its `failed_layer` and `review_endpoint`. The server may key approval by the presenter AID rather than the Legal Entity AID sent at onboarding; if DCR is refused with `aid_purpose`, check which AID the approval recorded.
- With the same format, Authenticate sends the registered `scope` along with the ACDC `client_assertion` to the advertised `token_endpoint` (or `SIGNET_TOKEN_ENDPOINT`). Known gap: the server has no `acdc_vlei` client authentication yet, so it answers `401 invalid_client`, which is shown as is. Without the json format, DCR and Authenticate are unchanged (`{base_url}/register`, `software_statement`, no `scope`).

### DaVinci data export (FHIR APIs)

The FHIR APIs page authenticates, then starts `POST {fhir_base}/Group/{groupId}/$davinci-data-export/` (note the trailing slash) with `Content-Type: application/fhir+json`, `Prefer: respond-async` and the body `{"exportType": "hl7.fhir.us.davinci-pdex#provider-snapshot"}`. A `202` carries the status URL to poll in `Content-Location`; when the export completes, each file in the manifest is a row to download into `~/signet-exports/<groupId>/`. Outside mock mode the Group dropdown is a static list (`grp-demo-export-1` to `-3`, `mock_data.STATIC_GROUP_IDS`), not the partner's `GET /Group`.

For the dev partner, point signet at its FHIR base and status URL prefix (the dev server advertises a `Content-Location` under `.../pvav2/blueshost/v2/Group/...`, which answers 404):

```bash
SIGNET_FHIR_BASE_URL=https://api-dmdh-dev.safhir.io/v1/api/pvav2 \
SIGNET_EXPORT_STATUS_URL_PREFIX=https://api-dmdh-dev.safhir.io/v1/api/pvav2/Group/davinci-data-export-status/ \
python main.py   # plus the onboarding variables above
```

Add both variables to the launch command in [Demo against a `.well-known/keri` server](#demo-against-a-well-knownkeri-server). Signet appends the export task id to the prefix itself (a trailing slash on the prefix is optional); the id is the last path segment of the advertised `Content-Location` (`.../davinci-data-export-status/<id>` gives `<id>`), and every other part of the advertised URL is ignored. Unset, the advertised URL is polled as returned.

### Authenticate

Registered connections get an "Authenticate" row action that obtains an access token (`grant_type=client_credentials`).

**Prerequisites:** the server policy must allow `client_credentials` (already in the `server-*.config.yaml.tmpl` files); a client registered before that change must be re-registered (see step 6). The token endpoint is re-discovered from `/.well-known/udap` each time.

**What it does:**
1. Looks up the `client_id` pinned at DCR for this connection's `(sending AID, credential SAID)`. Signet never assumes `client_id` equals the credential SAID; with no matching pin it asks you to register again. (Connections registered before pinning existed are pinned lazily from their own AID and credential, and only if they have no pins yet.)
2. Builds a fresh IPEX grant exn embedding the full credential (same recipe as DCR, with an empty `a.udap`) and POSTs it form-urlencoded to the token endpoint with `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:acdc-vlei` and `client_assertion`. No `scope` is sent, so the server applies its default scopes.
3. Stores the bearer token, scope and an expiry computed once at receipt on the connection. The dialog shows only the expiry, never the token; View shows "Authenticated: Until ...". The token is kept in plaintext in LMDB like the rest of the connection record.

Authenticate stays available while a token is valid (`client_credentials` returns no refresh token, so re-authenticate to renew). The connection status remains `registered`.

**Manual check:** the assertion is a fresh signed grant, so there is no hand-made curl for the first call. To replay one captured from the server log or a debugger:

```
curl -s -X POST http://127.0.0.1:8000/token \
  -d grant_type=client_credentials -d client_id=<CLIENT_ID_FROM_DCR> \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:acdc-vlei \
  --data-urlencode client_assertion=<CESR_GRANT>
# 200 {"access_token": ..., "token_type": "Bearer", "expires_in": 3600, "scope": ...}
# replaying the same assertion: 401 invalid_client; client registered without the grant: unauthorized_client
```

**Known echelon-server gaps** (not fixed here; none block the happy path):
- `/token` does not check the onboarding record (approved/purpose), and the form `client_id` is not bound to the client derived from the assertion (the client is found by the embedded credential SAID).
- Replay protection stores only the first `(SAID, dt)` per AID, and a failed first attempt still consumes it; signet always uses a fresh `dt`.
- The audience (`a.i`) is not checked against the server AID.
- A malformed assertion gives 500 `server_error` rather than 401 `invalid_client`.
- The acdc-vlei assertion path has no token-time tests, and the OIDC metadata advertises an unimplemented `client_secret_post`.
- `ONBOARDING.md` does not describe `client_credentials` token issuance.

### Manual checks

```
curl -s http://127.0.0.1:8000/.well-known/udap
curl -s http://127.0.0.1:8000/udap/onboarding/<onboarding_id>
# POST /udap/onboarding takes a raw CESR grant (Content-Type: application/cesr), built and signed by signet (with `SIGNET_ONBOARDING_FORMAT=json`: a JSON packet carrying the grant); there is no hand-made curl for it
# after DCR: 403 access_denied with no approved record (review config), 400 invalid_redirect_uri for a URI outside the approved set
curl -s -X POST http://127.0.0.1:8000/register -H 'content-type: application/json' -d '{"software_statement_type":"x","software_statement":"x","udap":"1"}'   # 400 invalid_software_statement
curl -s "http://127.0.0.1:8080/credential/<LESR_SAID>?chains=true&tel=true&registry=true" | head -c 300
# witness holds the holder KEL (key-state refresh path); header value is a witness AID
curl -H "CESR-DESTINATION: BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha" \
  "http://127.0.0.1:5642/log?pre=<HOLDER_AID>" | head -c 300
```

### Whitelist toggle demo

`server-lesr.config.yaml` whitelists the QVI AID, so onboarding returns 200 `approved`. Restart the server with `server-lesr.config.review.yaml` (empty whitelist) to get 202 `in-review`; the connection shows red until approved, then orange after Refresh. Both files are generated into `scripts/dev-live/` (git-ignored) by `issue-chain-lesr-subunit.sh` from `server-lesr.config.yaml.tmpl` (the ECR equivalents are `server-ecr.config*.yaml`).

### Troubleshooting

- **INDETERMINATE key state** in server logs: the witness lacks the holder KEL (inception not receipted) or the witness location is unknown to the server. Check the `/log?pre=` curl above.
- **Registrar 404 on `/credential/<said>?chains=true`**: the chain was not imported into the Registrar keystore; rerun the issue script with `--reset`.
- **Port conflicts**: witnesses use 5642-5644, vLEI-server 7723, echelon 8000, registrar 8080.
- **Grants not appearing in Locksmith**: grants are admitted by a background doer every ~2s once the issuer OOBIs (`SIGNET_DEV_OOBIS`) have resolved; also each time the Add Connection dialog loads.
- **No credential in the dropdown**: the credential must be admitted in the vault, which needs the earlier chain grants admitted first (LESR subunit: QVI, LE, LE Subunit and LESR Auth; LESR simple: QVI, LE and LESR Auth; ECR: QVI, LE and ECR Auth). Also check that `SIGNET_CREDENTIAL_SCHEMAS` (from `env.out`) names the chain you issued; unset, only the LESR is listed (set it to the ECR SAID for the ECR chain).
- **Switching between the ECR and LESR chains** (any two of the three): all share the keystore base `signet-dev-live` and `generated/`, so run the other issue script with `--reset` (and restart Locksmith with the new `env.out`). `--reset` keeps `generated/schemas`.
- **`issue-chain-lesr-simple.sh` times out waiting for the LESR Auth**: Locksmith must be restarted with `env.out` (`SIGNET_DEV_LESR_AUTH_FILE` set), must have admitted the QVI and LE credentials, and the holder must be receipted by its witnesses; look for `LESR Auth step failed (retrying)` in the Locksmith log. The step retries every 60s.
- **Schema OOBI returns 200 with an empty body**, or the issue script's preflight fails: the vLEI-server is not serving the combined schema dir; run `serve-schemas.sh` and restart it with `-s .../generated/schemas`.

With `server-lesr.config.review.yaml` (or `server-ecr.config.review.yaml`; empty whitelist) the gate is never offered while pending; a DCR sent without an approved record returns 403 `access_denied`.
