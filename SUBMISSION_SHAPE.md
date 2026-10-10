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
  "ipex_grant": "<CESR-encoded IPEX grant>"
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
      "scopes": ["system/Patient.rs", "system/Group.rs"]
    }
  ],
  "client_metadata": {},
  "contacts": {
    "technical": "interop-eng@healthkeri.com",
    "security": "security@healthkeri.com"
  },
  "ipex_grant": "<CESR-encoded IPEX grant>"
}
```