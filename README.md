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
