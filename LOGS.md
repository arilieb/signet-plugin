# Onboarding Failure — libsodium Missing

## Summary

| Field | Value |
|-------|-------|
| **Endpoint** | `POST /slapv3/keri/udap/onboarding` |
| **Status** | `500 Internal Server Error` |
| **Timestamp** | `2026-10-09 19:33:45 GMT` |
| **Correlation ID (request)** | `3826217fec04464e` |
| **Correlation ID (response)** | `6d6a226af2cb4c8f9159171fb03dfe99` |
| **Resolved URL** | `https://api-dmdh-dev.safhir.io/slapv3/keri/udap/onboarding` |
| **Advertised URL (overridden)** | `https://osfsdmdhdevslapapi.azurewebsites.net/slapv3/keri/udap/onboarding` |

## Root Cause

> `ValueError: Unable to find libsodium`

The server returns a `500` because importing `pysodium` fails — the native
`libsodium` library is missing from the deployment environment. The import is
triggered lazily while parsing the IPEX grant during serializer validation.

## Key Frames

| File | Line | Call |
|------|------|------|
| `apps/keri/views.py` | 194 | `serializer.is_valid()` |
| `apps/keri/serializers.py` | 670 | `parse_ipex_grant(ipex_grant_str.encode("utf-8"))` |
| `apps/keri/services/ipex.py` | 81 | `extract_signatures(cesr_bytes, event_size)` |
| `apps/keri/services/ipex.py` | 266 | `from keri.core import indexing` (lazy — requires libsodium) |
| `keri/core/coring.py` | 18 | `import pysodium` |
| `pysodium/__init__.py` | 35 | `raise ValueError('Unable to find libsodium')` |

## Environment

- **Django:** 5.2.16
- **Python:** 3.14.3
- Full error page saved to:
  `/var/folders/l6/0ft9tgzs66vb_b7ljs0np0_m0000gn/T/signet-onboarding-last-response.html`

## Suggested Fix

Install the native `libsodium` package in the server image before the app starts:

```text
# Debian / Ubuntu
apt-get install -y libsodium23

# Alpine
apk add libsodium
```

---

<details>
<summary>Request (click to expand)</summary>

```text
2026-10-09 12:33:44 [signet.core.remoting] INFO     Overriding advertised onboarding endpoint https://osfsdmdhdevslapapi.azurewebsites.net/slapv3/keri/udap/onboarding with https://api-dmdh-dev.safhir.io/slapv3/keri/udap/onboarding
2026-10-09 12:33:44 [signet.core.remoting] INFO     Onboarding request: POST https://api-dmdh-dev.safhir.io/slapv3/keri/udap/onboarding headers={'Content-Type': 'application/json'} body={"correlation_id": "3826217fec04464e", "legal_entity": {"lei": "549300QKBENKLBXQ8968", "aid": "EJirP7qS5rerfoxCc5GIbRg1n2ydtkOUKKz2bYNsfFor", "qvi_lei": "254900OPPU84GM83MG36", "oobi": ["http://127.0.0.1:5642/oobi/EJirP7qS5rerfoxCc5GIbRg1n2ydtkOUKKz2bYNsfFor"]}, "submitter": {"role": "Care Coordinator"}, "requested_purposes": [{"purpose": "TREAT", "scopes": ["system/Patient.rs", "system/Group.rs"]}], "client_metadata": {}, "contacts": {"technical": "interop-eng@healthkeri.com", "security": "security@healthkeri.com"}, "ipex_grant": "<3791 chars omitted>"}
```
</details>

<details>
<summary>Response headers (click to expand)</summary>

```text
2026-10-09 12:33:45 [signet.core.remoting] INFO     Onboarding response: 500 Internal Server Error url=https://api-dmdh-dev.safhir.io/slapv3/keri/udap/onboarding headers={'date': 'Fri, 09 Oct 2026 19:33:45 GMT', 'content-type': 'text/html; charset=utf-8', 'content-length': '263977', 'connection': 'keep-alive', 'set-cookie': 'correlation_id=6d6a226af2cb4c8f9159171fb03dfe99; Path=/', 'vary': 'origin,Cookie', 'access-control-expose-headers': 'Correlation-ID', 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload', 'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff', 'referrer-policy': 'same-origin', 'cross-origin-opener-policy': 'same-origin', 'correlation-id': '6d6a226af2cb4c8f9159171fb03dfe99'}
```
</details>

<details>
<summary>Full traceback (click to expand)</summary>

```text
Request Method: POST
Request URL: https://osfsdmdhdevslapapi.azurewebsites.net/slapv3/keri/udap/onboarding

Django Version: 5.2.16
Python Version: 3.14.3

Traceback (most recent call last):
  File "/usr/local/lib/python3.14/site-packages/django/core/handlers/exception.py", line ...
    response = get_response(request)
  File "/usr/local/lib/python3.14/site-packages/django/core/handlers/base.py", line 197, in _get_response
    response = wrapped_callback(request, *callback_args, **callback_kwargs)
  File "/usr/local/lib/python3.14/site-packages/django/views/decorators/csrf.py", line 6
    return view_func(request, *args, **kwargs)
  File "/usr/local/lib/python3.14/site-packages/django/views/generic/base.py", line 105, in view
    return self.dispatch(request, *args, **kwargs)
  File "/usr/local/lib/python3.14/site-packages/rest_framework/views.py", line 515, in dispatch
    response = self.handle_exception(exc)
  File "/usr/local/lib/python3.14/site-packages/rest_framework/views.py", line 475, in handle_exception
    self.raise_uncaught_exception(exc)
  File "/usr/local/lib/python3.14/site-packages/rest_framework/views.py", line 486, in raise_uncaught_exception
    raise exc
  File "/usr/local/lib/python3.14/site-packages/rest_framework/views.py", line 512, in dispatch
    response = handler(request, *args, **kwargs)
  File "/usr/local/lib/python3.14/site-packages/rest_framework/decorators.py", line 50, in handler
    return func(*args, **kwargs)
  File "/usr/local/bin/app/apps/keri/views.py", line 194, in keri_onboarding_submit
    is_valid = serializer.is_valid()
  File "/usr/local/lib/python3.14/site-packages/rest_framework/serializers.py", line 225, in is_valid
    self._validated_data = self.run_validation(self.initial_data)
  File "/usr/local/lib/python3.14/site-packages/rest_framework/serializers.py", line 447, in run_validation
    value = self.validate(value)
  File "/usr/local/bin/app/apps/keri/serializers.py", line 670, in validate
    grant = parse_ipex_grant(ipex_grant_str.encode("utf-8"))
  File "/usr/local/bin/app/apps/keri/services/ipex.py", line 81, in parse_ipex_grant
    signatures = extract_signatures(cesr_bytes, event_size)
  File "/usr/local/bin/app/apps/keri/services/ipex.py", line 266, in extract_signatures
    from keri.core import indexing  # lazy — requires libsodium
  File "/usr/local/lib/python3.14/site-packages/keri/core/__init__.py", line 8, in <module>
    from .coring import (Tiers, )
  File "/usr/local/lib/python3.14/site-packages/keri/core/coring.py", line 18, in <module>
    import pysodium
  File "/usr/local/lib/python3.14/site-packages/pysodium/__init__.py", line 35, in <module>
    raise ValueError('Unable to find libsodium')

Exception Type: ValueError at /slapv3/keri/udap/onboarding
Exception Value: Unable to find libsodium
```
</details>
```