# Gateway

Untrusted agent → Mandate Enforcement Gateway → trusted executor → registered route only.

POST /v1/intents { intent, execute }
POST /v1/approvals { approval, execute }
GET /v1/receipts/{id}
GET /health

Forbidden: target_url, destination_url, host, base_url, proxy_url, url.
