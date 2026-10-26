# signet-plugin
Connection + FHIR API KIM plugin client

Locksmith plugin implementing "Keriguard Signet": a Connections CRUD that walks a user through
Onyx's asynchronous UDAP vLEI onboarding flow (submit an onboarding request, poll/refresh for
approval, then complete Dynamic Client Registration). A second menu item, FHIR APIs, opens a
table of FHIR endpoints: pick a registered connection, then a Group ID, to list that Group's
endpoints. Clicking a row first authenticates against the selected connection (reusing a
still-valid access token), then runs the (currently placeholder) downstream action. In mock mode
the Groups/endpoints are fixtures; outside mock mode the Group list is empty for now.

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

The protocol and flow logic (discovery, onboarding, DCR, token, FHIR export, the IPEX request
builders) lives in the `acdc-auth-client` library (the `echelon-client` repo), which the plugin
calls through `core/remoting.py` and `core/presenting.py`. It is not released yet, so install it
into the same venv from a checkout (it needs keri `~=1.3.5`, as Locksmith does):

```
pip install -e ../echelon-client
```

(`uv sync` in this repo resolves it from the sibling `../echelon-client` checkout, see
`[tool.uv.sources]` in `pyproject.toml`.)

## Live local onboarding (development)

> **Status:** the dev-live scripts and steps were run end to end (the plugin on `acdc-auth-client`) against echelon-server in both wire formats. [Test with echelon-client](#test-with-echelon-client) lists what was exercised and what was not. The `kli` issue scripts for the LESR simple chain (`issue-chain-lesr-simple.sh`) were not part of that run.

By default `LOCKSMITH_ENVIRONMENT=development` runs signet in mock mode (canned responses, fake seeded connections). Setting `SIGNET_LIVE=1` in development switches to the real single-IPEX-grant onboarding (the grant's exn signature is the only signature) against local infrastructure. Schemas come from the healthKERI bucket, so no local schema server is needed. Three credential chains are supported (pick one per run; see Troubleshooting for switching):

- **LESR subunit** (the main onboarding credential, `issue-chain-lesr-subunit.sh`): GLEIF External -> QVI -> LE (Practice) -> LE Subunit (Practice -> holder AID) -> LESR Auth (Practice -> QVI AID) -> LESR (QVI -> holder AID). The chain is linear: the LESR has a single `auth` edge.
- **LESR simple** (for orgs without subunits, `issue-chain-lesr-simple.sh`): GLEIF External -> QVI -> LE (issued to the holder AID, which *is* the Legal Entity AID) -> LESR Auth (holder -> QVI AID, `le` edge) -> LESR (QVI -> holder AID). The holder's keys live only in the Locksmith vault, so the live-dev bootstrap issues the LESR Auth in-process and grants it to the QVI (`SIGNET_DEV_LESR_AUTH_FILE`); the script waits for that grant before it issues the LESR. It renders the `server-lesr*.config*.yaml` files (from the `server-lesr-simple.config*.yaml.tmpl` templates) with the holder AID pinned as the LESR Auth issuer.
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
| `SIGNET_ONBOARDING_OMIT_GRANT` | `1`/`true` sends the JSON packet without `ipex_grant`; the server AID is then not needed. Third-party servers may accept this while their grant verification is unfinished; echelon-server in json mode requires `ipex_grant` and answers `400 invalid_request` (the negative test of [Test with echelon-client](#test-with-echelon-client)) |
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

- keripy `kli`, echelon-server, Locksmith and the registrar each in their own venv. Registrar pins `keri~=1.3.4`; the others use 1.3.6 (the local keripy checkout reports 1.3.5), so keep each tool in its own environment.
- Keystores are created under the keri base `signet-dev-live`; `--reset` deletes only that base. Never `rm -rf /usr/local/var/keri`.

### Run order

#### Clean up
```bash
rm -rf ~/.acdc/db/oauth2
rm -rf /usr/local/var/keri/*
```
The second command deletes every Locksmith vault under that directory, not just the dev one.

#### 1 witnesses (keripy venv)
```bash
cd ~/healthkeri/keripy && kli witness demo
```
#### 2 schemas
Nothing to run. All schemas are fetched from the healthKERI bucket (`https://healthkeri-schema.sfo3.digitaloceanspaces.com/oobi/{SAID}`, `SCHEMA_SERVER` in `scripts/dev-live/env.sh`), and `dev-live.json` / `Registrar.json` resolve their OOBIs at `kli init`. The machine needs network access to it. Check one: `curl https://healthkeri-schema.sfo3.digitaloceanspaces.com/oobi/<SAID>` (SAIDs are in `scripts/dev-live/env.sh`). The issue scripts preflight all of them.

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
scripts/dev-live/issue-chain-lesr-simple.sh EDqyx_rMkeZT63D41DjSstHUDwx_1W_0qtnKz30iGIJb --reset            # optionally: --timeout 600 (seconds to wait for the LESR Auth grant; 600 is the default)
# when it prints "Waiting ... for the LESR Auth grant": in another terminal, restart Locksmith with
source scripts/dev-live/generated/env.out   # then start Locksmith as in step 3
# Locksmith admits the QVI + LE credentials, issues the LESR Auth and grants it to the QVI; the script then issues the LESR
```
Step 6 (echelon-server) applies as for the other chains (the script rendered `server-lesr.config.yaml`). Afterwards the vault holds the LESR, LESR Auth, LE and QVI credentials.
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
- With the same format, Authenticate sends the registered `scope` along with the ACDC `client_assertion` to the advertised `token_endpoint` (or `SIGNET_TOKEN_ENDPOINT`). echelon-server accepts it and issues a token. When this was last tried against the third-party safhir server it had no `acdc_vlei` client authentication yet and answered `401 invalid_client`, which is shown as is. Without the json format, DCR and Authenticate are unchanged (`{base_url}/register`, `software_statement`, no `scope`).

### Test with echelon-client

Everything above also applies to the migrated plugin. This section is what was run against a local echelon-server and what it showed, so you can repeat it.

**Requirements.** The protocol and flow logic lives in `acdc-auth-client` (the `echelon-client` repo, `pip install -e ../echelon-client`, keri 1.3.6), and the server must be an echelon-server that supports `onboarding.wire_format` and `fhir.enabled` (described below).

**Server.** echelon-server speaks two wire formats, chosen per run (restart to switch) with `onboarding.wire_format: cesr|json` (default `cesr`). `fhir.enabled: true` also serves a FHIR stub (`GET /Group`, `$davinci-data-export` and its downloads, all behind the token `/token` issues), independently of the format. The issue scripts render four configs per chain into `scripts/dev-live/` (git-ignored):

| File | Format | Whitelist |
|---|---|---|
| `server-<chain>.config.yaml` | cesr | QVI whitelisted, onboarding returns 200 |
| `server-<chain>.config.review.yaml` | cesr | empty, onboarding returns 202 in-review |
| `server-<chain>.config.json.yaml` | json | QVI whitelisted, 200 |
| `server-<chain>.config.json.review.yaml` | json | empty, 202 in-review |

`<chain>` is `lesr` (the LESR subunit chain) or `ecr`. The json configs also set `max_body_bytes` to 1 MiB, `fetch_allowlist: [127.0.0.1]` (json onboarding still fetches the `legal_entity.oobi` URLs from the witnesses, so the witness host must be listed), `purpose_policy.TREAT.scopes: [system/Group.read]` and the `client_credentials` grant.

**Run order.** Follow steps Clean up through 5 above, then step 6 with the config you want.
- cesr: start Locksmith as in step 3 (and again after `source scripts/dev-live/generated/env.out`).
- json: start the server first, then derive the server AID by sourcing the env file, then launch Locksmith. The client takes the server AID only from `SIGNET_ONBOARDING_SERVER_AID` and ignores any `aid` in the `.well-known/keri` document, so the order matters:

```bash
cd ~/healthkeri/echelon-server && echelons serve --host 127.0.0.1 --port 8000 \
  --name Provider --base signet-dev-live --alias Provider \
  --config ~/healthkeri/signet-plugin/scripts/dev-live/server-lesr.config.json.yaml   # or server-ecr.config.json.yaml
cd ~/healthkeri/signet-plugin
source scripts/dev-live/generated/env.out
source scripts/dev-live/echelon-json-env.sh       # fails with "start echelon-server first" if the server is down
cd ~/healthkeri/locksmith/src/locksmith && python main.py
```

`echelon-json-env.sh` exports `SIGNET_LIVE=1`, `SIGNET_PARTNER_URL=<server>/.well-known/keri`, `SIGNET_ONBOARDING_FORMAT=json`, `SIGNET_ONBOARDING_SERVER_AID` (read from `/.well-known/udap`) and `SIGNET_REGISTRAR_URL`. Override `ECHELON_URL` or `REGISTRAR_URL` before sourcing if they are elsewhere. For the negative test, `export SIGNET_ONBOARDING_OMIT_GRANT=1` and restart Locksmith (unset it afterwards).

Then in the UI: Connections -> Add -> pick the credential, submit, Refresh, DCR "Proceed", Authenticate, and the FHIR APIs page (pick a Group, wait for the file rows, click one to download). In json mode all chain credentials must be in the vault first.

**What each run exercised.**

| # | Server | Chain | Result |
|---|---|---|---|
| 1 | cesr | LESR subunit | Pass: add with whitelist approval (200), DCR gate, Authenticate, FHIR export and download. Reported by the person who ran it; no log excerpt kept. |
| 2 | cesr, review | LESR subunit | Pass: 202 in-review, Refresh polling, DCR gate not offered until approved. Same caveat. |
| 3 | json | LESR subunit | Pass: `.well-known/keri` discovery, onboarding with the full 5-credential chain (23,952 bytes) auto-approved by whitelist rule 0 (200), DCR 201, token 200, export kickoff 202 then status 202, 200. The chain used the real vLEI schemas and witnessed KELs. |
| 4 | json, review | LESR subunit | Pass: onboarding held at "needs approval". The transition from in-review to approved was not tried (nothing in the dev config approves a record). |
| 5 | json | LESR subunit | Omitted grant (`SIGNET_ONBOARDING_OMIT_GRANT=1`) gives `400 invalid_request`: verified live. A revoked or missing chain credential and an Authenticate replay were **not** tested live; the server's unit tests cover them. |
| 6 | json | ECR | Pass: the presenter AID (the ECR holder) is not the Legal Entity AID (Practice), and onboarding (4 credentials, 21,930 bytes), DCR 201, token 200 and export all worked. Approval is keyed by the presenter AID. |
| 7 | none | n/a | Pass: Locksmith in plain mock mode (no `SIGNET_LIVE`) works with no network. |

Not covered by any run: a slow or interrupted download, the DCR repeat (`200` with the same `client_id`) and the exported file contents were not separately observed in the UI. The safhir/Onyx instructions elsewhere in this README still describe the third-party run and were not re-run.

**Reading the server log** (json mode, a healthy run): `GET /.well-known/keri` 200, `json onboarding body: N bytes (limit 1048576)`, `auto-approved by whitelist rule 0`, `POST /udap/onboarding` 200, `POST /register` 201, `POST /token` 200, then the export `POST .../Group/<id>/%24davinci-data-export/` 202 and one or more status `GET`s ending in 200. A 202 from `/udap/onboarding` means in review (use a whitelisted config, or Refresh later).

### DaVinci data export (FHIR APIs)

The FHIR APIs page authenticates, then starts `POST {fhir_base}/Group/{groupId}/$davinci-data-export/` (note the trailing slash) with `Content-Type: application/fhir+json`, `Prefer: respond-async` and the body `{"exportType": "hl7.fhir.us.davinci-pdex#provider-snapshot"}`. A `202` carries the status URL to poll in `Content-Location`; when the export completes, each file in the manifest is a row; clicking a row asks where to save the file (the dialog starts in your home directory) and downloads it there. Outside mock mode the Group dropdown is a static list (`grp-demo-export-1` to `-3`, `mock_data.STATIC_GROUP_IDS`), not the partner's `GET /Group`.

For the dev partner, point signet at its FHIR base and status URL prefix (the dev server advertises a `Content-Location` under `.../pvav2/blueshost/v2/Group/...`, which answers 404):

```bash
SIGNET_FHIR_BASE_URL=https://api-dmdh-dev.safhir.io/v1/api/pvav2 \
SIGNET_EXPORT_STATUS_URL_PREFIX=https://api-dmdh-dev.safhir.io/v1/api/pvav2/Group/davinci-data-export-status/ \
python main.py   # plus the onboarding variables above
```

Add both variables to the launch command in [Demo against a `.well-known/keri` server](#demo-against-a-well-knownkeri-server). (Against echelon-server's FHIR stub neither is needed: the base URL is the server root and the advertised `Content-Location` is already correct.) Signet appends the export task id to the prefix itself (a trailing slash on the prefix is optional); the id is the last path segment of the advertised `Content-Location` (`.../davinci-data-export-status/<id>` gives `<id>`), and every other part of the advertised URL is ignored. Unset, the advertised URL is polled as returned.

### Authenticate

Registered connections get an "Authenticate" row action that obtains an access token (`grant_type=client_credentials`).

**Prerequisites:** the server policy must allow `client_credentials` (already in the `server-*.config.yaml.tmpl` files); a client registered before that change must be re-registered (see step 6). The token endpoint is re-discovered from `/.well-known/udap` each time.

**What it does:**
1. Looks up the `client_id` pinned at DCR for this connection's `(sending AID, credential SAID)`. Signet never assumes `client_id` equals the credential SAID; with no matching pin it asks you to register again. (Connections registered before pinning existed are pinned lazily from their own AID and credential, and only if they have no pins yet.)
2. Builds a fresh IPEX grant exn embedding the full credential (same recipe as DCR, with an empty `a.udap`) and POSTs it form-urlencoded to the token endpoint with `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:acdc-vlei` and `client_assertion`. In the default (cesr) format no `scope` is sent, so the server applies its default scopes; with `SIGNET_ONBOARDING_FORMAT=json` the scope registered at DCR is sent too.
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

**Known echelon-server gaps** (none block the happy path):
- `/token` does not check the onboarding record (approved/purpose).
- Replay protection stores only the first `(SAID, dt)` per AID, and a failed first attempt still consumes it; signet always uses a fresh `dt`. A live replay needs a captured assertion (see above), so it was not exercised live; it is covered by server unit tests only.
- The audience (`a.i`) is not checked against the server AID.
- The OIDC metadata advertises an unimplemented `client_secret_post`, and `scopes_supported` is the fixed `["read","write"]` even in json mode (it gates nothing; the registered scope does).
- `ONBOARDING.md` does not describe `client_credentials` token issuance.

echelon-server also requires the form `client_id` to match the client derived from the assertion (else 401 `invalid_client`), requires the assertion's grant to be accepted by the exchanger (a grant signed by an AID other than its sender is refused), and answers a malformed assertion with 401.

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
- **Port conflicts**: witnesses use 5642-5644, echelon 8000, registrar 8080.
- **Grants not appearing in Locksmith**: grants are admitted by a background doer every ~2s once the issuer OOBIs (`SIGNET_DEV_OOBIS`) have resolved; also each time the Add Connection dialog loads.
- **No credential in the dropdown**: the credential must be admitted in the vault, which needs the earlier chain grants admitted first (LESR subunit: QVI, LE, LE Subunit and LESR Auth; LESR simple: QVI, LE and LESR Auth; ECR: QVI, LE and ECR Auth). Also check that `SIGNET_CREDENTIAL_SCHEMAS` (from `env.out`) names the chain you issued; unset, only the LESR is listed (set it to the ECR SAID for the ECR chain).
- **Switching between the ECR and LESR chains** (any two of the three): all share the keystore base `signet-dev-live` and `generated/`, so run the other issue script with `--reset` (and restart Locksmith with the new `env.out`).
- **`issue-chain-lesr-simple.sh` times out waiting for the LESR Auth**: Locksmith must be restarted with `env.out` (`SIGNET_DEV_LESR_AUTH_FILE` set), must have admitted the QVI and LE credentials, and the holder must be receipted by its witnesses; look for `LESR Auth step failed (retrying)` in the Locksmith log. The step retries every 60s.
- **`Likely Duplicitous Event` lines in the echelon-server log** (`ipex_grant message was not accepted: Likely Duplicitous Event of type=vcp` / `type=iss`): expected, not an error. Onboarding logs a few, because the server's own `Provider` keystore already holds the QVI credential and its own Legal Entity credential (the issue scripts import them) and the chain repeats those events. `/register` logs one per registry and credential, because onboarding already ingested the same chain. keripy rejects a registry or credential event it already holds, the server logs it and carries on, and the chain verification is unaffected.
- **json onboarding answers `413`**: the `ipex_grant` chain stream exceeded `onboarding.max_body_bytes`. The measured chains are about 22-24 KB; the json templates allow 1 MiB and the server default is 256 KiB. The server logs `json onboarding body: N bytes (limit M)` for each request.
- **json onboarding fails fetching OOBIs**: the witness host must be in `onboarding.fetch_allowlist` even in json mode (the generated json configs list `127.0.0.1`).
- **The issue script's schema preflight fails**: the schema bucket is unreachable from this machine, or the SAID is not published there (`curl` the URL it prints).

With `server-lesr.config.review.yaml` (or `server-ecr.config.review.yaml`; empty whitelist) the gate is never offered while pending; a DCR sent without an approved record returns 403 `access_denied`.
