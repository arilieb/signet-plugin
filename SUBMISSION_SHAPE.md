# Proposed Submission Shape
```json
{
  "correlation_id": "{{correlationId}}",
  "legal_entity": {
    "lei": "{{lei}}",
    "aid": "{{aid}}",
    "oobi": [
      "https://example.invalid/oobi/{{aid}}"
    ]
  },
  "submitter": {
    "role": "Postman smoke test",
    "ecr_said": "{{said}}"
  },
  "requested_purposes": [
    {
      "purpose": "{{purpose}}",
      "scopes": [
        "{{scope}}"
      ]
    }
  ],
  "contacts": {
    "technical": "{{technicalContact}}",
    "security": "{{securityContact}}"
  },
  "ipex_grant": "<CESR stream: chain KELs, TELs and credentials, ending in the IPEX grant exn>"
}
```
## Example 
```json
{
  "correlation_id": "req-2026-10-09-0001",
  "legal_entity": {
    "lei": "549300QKBENKLBXQ8968",
    "aid": "EKrM-fvAs-jS2pFTvfr643wFoAoHtidQBpDNSQQTwQHX",
    "qvi_lei": "254900OPPU84GM83MG36",
    "oobi": [
      "https://witness.example.org/oobi/EKrM-fvAs-jS2pFTvfr643wFoAoHtidQBpDNSQQTwQHX/witness"
    ]
  },
  "submitter": {
    "ecr_said": "EJ8s2...",
    "role": "Data Exchange Representative"
  },
  "requested_purposes": [
    {
      "purpose": "TREAT",
      "scopes": ["system/Group.read"]
    }
  ],
  "client_metadata": {},
  "contacts": {
    "technical": "interop-eng@healthkeri.com",
    "security": "security@healthkeri.com"
  },
  "ipex_grant": "<CESR stream: chain KELs, TELs and credentials, ending in the IPEX grant exn>"
}
```

# Dynamic Client Registration (after approval)
POST to the discovery document's `registration_endpoint` (SLAP: `{baseUrl}/slapv3/keri/register/`), `Content-Type: application/json`. `purpose`, `client_name` and `grant_types` are top level; the grant is plain (no `a.udap`). `ipex_grant` is built like the onboarding one, with a fresh `dt`, and `oobi` is the presenter's own witness OOBI.
```json
{
  "ipex_grant": "<CESR stream: chain KELs, TELs and credentials, ending in the IPEX grant exn>",
  "oobi": "https://witness.example.org/oobi/EKrM-fvAs-jS2pFTvfr643wFoAoHtidQBpDNSQQTwQHX",
  "purpose": "TREAT",
  "client_name": "Onyx",
  "grant_types": ["client_credentials"]
}
```
`201` on first registration, `200` on re-registration, both with `client_id` and a space-separated `scope`. `400 unapproved_software_statement` carries `failed_layer` and `review_endpoint`.
