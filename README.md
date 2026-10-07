# signet-plugin
Connection + FHIR API KIM plugin client

Locksmith plugin implementing "Keriguard Signet": a Connections CRUD that walks a user through
Onyx's asynchronous UDAP vLEI onboarding flow (submit an onboarding request, poll/refresh for
approval, then complete Dynamic Client Registration). A second menu item, FHIR APIs, is stubbed
but inert (disabled, no page registered).

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

By default `LOCKSMITH_ENVIRONMENT=development` runs signet in mock mode (canned responses, fake seeded connections). Setting `SIGNET_LIVE=1` in development switches to the real single-IPEX-grant onboarding (the grant's exn signature is the only signature) against local infrastructure. The credential chain is GLEIF External -> QVI -> LE (Practice) -> ECR Auth (to the QVI AID) -> ECR (QVI -> holder AID).

### Environment variables

| Variable | Purpose |
|---|---|
| `SIGNET_LIVE=1` | Live dev mode (only honored when `LOCKSMITH_ENVIRONMENT=development`) |
| `SIGNET_REGISTRAR_URL` | Registrar hosting the credential chain, e.g. `http://127.0.0.1:8080` |
| `SIGNET_PARTNER_URL` | Local Echelon base URL (default `http://127.0.0.1:8000`) |
| `SIGNET_DEV_OOBIS` | Comma-separated extra OOBIs the bootstrap resolves (External, QVI, Practice); written by `issue-chain.sh` to `scripts/dev-live/generated/env.out` |

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
```bash
cd ~/healthkeri/vLEI && vLEI-server -s ./schema/acdc -c ./samples/acdc -o ./samples/oobis -p 7723
```

#### 3 Locksmith + signet in live dev; 
on vault open the holder "signet-dev-holder" is created and its AID logged. Leave it running (it must receive the grants).
```bash
cd ~/healthkeri/locksmith && LOCKSMITH_ENVIRONMENT=development SIGNET_LIVE=1 \
  SIGNET_REGISTRAR_URL=http://127.0.0.1:8080 python main.py
```

#### 4 issue the chain and grant it to the holder
```bash
cd ~/healthkeri/signet-plugin && scripts/dev-live/issue-chain.sh <HOLDER_AID> --reset
```
Restart Locksmith with: 
```bash
source scripts/dev-live/generated/env.out
```
so the issuer OOBIs resolve and the pending grants are admitted

#### 5 registrar 
(own venv; no passcode, matching the keystore)
```bash
registrar start --name Registrar --base signet-dev-live --alias Registrar --issuer <QVI_AID>
```

#### 6 echelon-server
```bash
cd ~/healthkeri/echelon-server && echelons serve --host 127.0.0.1 --port 8000 \
  --name Provider --base signet-dev-live --alias Provider \
  --config ~/healthkeri/signet-plugin/scripts/dev-live/server.config.yaml
```

`issue-chain.sh` prints the QVI AID and the exact commands for steps 5-6.

In the UI: Connections -> Add -> "Local Echelon" -> pick the ECR credential, enter the redirect URIs (one per line, e.g. `http://127.0.0.1:9000/cb`) -> submit; use Refresh to poll. The redirect URIs are approved with onboarding.

Onboarding sends one IPEX grant exn of the ECR credential to `POST /udap/onboarding`; its `a.udap` carries the requested purposes, contacts, redirect URIs, correlation id and typed OOBIs. The credential's issuee must be the sending identifier, otherwise the server answers 403.

Once the connection is approved (green), the DCR gate offers "Proceed": signet builds an IPEX grant exn carrying `a.udap` (purpose, client_name, redirect_uris), POSTs it to `/register`, and shows the returned `client_id` (201; repeating it returns the same client). Failures show the RFC 7591 error and `correlation_id`.

### Manual checks

```
curl -s http://127.0.0.1:8000/.well-known/udap
curl -s http://127.0.0.1:8000/udap/onboarding/<onboarding_id>
# POST /udap/onboarding takes a raw CESR grant (Content-Type: application/cesr), built and signed by signet; there is no hand-made curl for it
# after DCR: 403 access_denied with no approved record (review config), 400 invalid_redirect_uri for a URI outside the approved set
curl -s -X POST http://127.0.0.1:8000/register -H 'content-type: application/json' -d '{"software_statement_type":"x","software_statement":"x","udap":"1"}'   # 400 invalid_software_statement
curl -s "http://127.0.0.1:8080/credential/<ECR_SAID>?chains=true&tel=true&registry=true" | head -c 300
# witness holds the holder KEL (key-state refresh path); header value is a witness AID
curl -H "CESR-DESTINATION: BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha" \
  "http://127.0.0.1:5642/log?pre=<HOLDER_AID>" | head -c 300
```

### Whitelist toggle demo

`server.config.yaml` whitelists the QVI AID, so onboarding returns 200 `approved`. Restart the server with `server.config.review.yaml` (empty whitelist) to get 202 `in-review`; the connection shows red until approved, then orange after Refresh. Both files are generated by `issue-chain.sh` from `server.config.yaml.tmpl`.

### Troubleshooting

- **INDETERMINATE key state** in server logs: the witness lacks the holder KEL (inception not receipted) or the witness location is unknown to the server. Check the `/log?pre=` curl above.
- **Registrar 404 on `/credential/<said>?chains=true`**: the chain was not imported into the Registrar keystore; rerun `issue-chain.sh --reset`.
- **Port conflicts**: witnesses use 5642-5644, vLEI-server 7723, echelon 8000, registrar 8080.
- **Grants not appearing in Locksmith**: grants are admitted by a background doer every ~2s once the issuer OOBIs (`SIGNET_DEV_OOBIS`) have resolved; also each time the Add Connection dialog loads.
- **No credential in the dropdown**: the ECR must be admitted in the vault, which needs the QVI, LE and ECR Auth grants admitted first.

With `server.config.review.yaml` (empty whitelist) the gate is never offered while pending; a DCR sent without an approved record returns 403 `access_denied`.
