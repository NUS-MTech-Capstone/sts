# STS

Security Token Service. It validates well-formed access
requests and issues short-lived session tokens.

## Run

```bash
PORT=8082 \
JWT_SIGNING_KEY='replace-with-at-least-32-random-bytes' \
CHANGE_REQUEST_URL=http://localhost:8085 \
SERVER_INVENTORY_URL=http://localhost:8086 \
go run ./cmd/server
```

For local development without a server-inventory service, configure a trusted
static inventory:

```bash
SERVER_INVENTORY_STATIC_JSON='{
  "host-123": {
    "address": "server.example:22",
    "username": "ubuntu",
    "connectionType": "ssh",
    "credentialSecretId": "dendenmushi/host-123",
    "hostPublicKey": "ssh-ed25519 AAAA..."
  }
}'
```

`JWT_SIGNING_KEY` is required and must contain at least 32 bytes. All STS
instances and token-verifying services must use the same secret. Generate one
for local development with `openssl rand -base64 32`.

Optional token settings:

```bash
SESSION_TOKEN_TTL_SECONDS=300
AUTOMATION_TOKEN_TTL_SECONDS=600
JWT_ISSUER=dendenmushi-sts
JWT_AUDIENCE=dendenmushi-session
JWT_CLOCK_SKEW_SECONDS=5
```

The upstream URLs are optional while those services are not part of this
workspace. When configured, start validation performs these placeholder calls:

```http
GET /change-requests/{crId}
GET /servers/{hostId}
```

## Endpoints

```http
GET  /healthz
POST /validate
POST /tokens/session
POST /tokens/validate
POST /tokens/automation
POST /tokens/automation/validate
```

`/validate` accepts `start` requests scoped by `hostId` and `crId`, session
operations scoped by `sessionId`, and owner rejoin discovery requests scoped by
`hostId` and `crId`.

`/tokens/validate` is used by the proxy dataplane. A successful response returns
the verified claims. Tokens bind the session action (`start`, `rejoin`, or
`observe`), mode, host, change request, connection type, and trusted SSH target
metadata. Observer tokens cannot become writable owner connections.

Session tokens are RFC 7519 JWTs signed with JWS `HS256`. They include the
registered `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, and `jti` claims plus the
private session and SSH target claims. Verification only accepts `HS256` and
requires the configured issuer, audience, expiration, and issued-at values.

Automation capability tokens are a separate JWT type and cannot be used as
interactive session tokens. Issuance requires a projected Kubernetes
service-account token that passes TokenReview for the configured namespace,
service account, and audience. Capabilities bind the run, incident, host,
phase, operation allowlist, assigned pod instance, and remediation plan hash.

Trusted inventory entries may include:

```json
{
  "automation": {
    "serviceName": "myapp",
    "healthUrl": "http://127.0.0.1:8080/healthz",
    "helperPath": "/usr/local/sbin/ddm-ops",
    "allowedOperations": ["service_status", "health_check", "restart_service"]
  }
}
```
