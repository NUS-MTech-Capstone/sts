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

Optional lifecycle event publication:

```bash
EVENT_PUBLISHER_ENABLED=false
EVENTS_TOPIC_ARN=
AWS_REGION=ap-southeast-1
```

When enabled, `/validate` publishes sanitized `AccessAllowed` and
`AccessDenied` metadata events to SNS. Events never include session tokens,
automation capability tokens, secrets, command bodies, prompts, or terminal
streams. Publish failures are logged and do not change the authorization
response.

The upstream URLs are optional while those services are not part of this
workspace. When configured, start validation performs these placeholder calls:

```http
GET /change-requests/{crId}
GET /servers/{hostId}
```

When `CHANGE_REQUEST_URL` is configured, `/validate` requires the upstream
change request to be approved. If the response includes `hostIds`, the requested
gateway host ID must be present.

## Design Patterns

STS models access checks as policy strategies behind the `/validate` endpoint.
Common validation runs first, then the action-specific policy for `start`,
`rejoin`, `observe`, or `stop`. The `start` policy composes the optional
change-request and server-inventory clients without changing the public
request or response contract.

## Endpoints

```http
GET  /healthz
POST /validate
POST /tokens/session
POST /tokens/validate
POST /tokens/automation
POST /tokens/automation/validate
```

Business endpoints require `x-api-version: 1`. `GET /healthz` and
`GET /openapi.yaml` are exempt so probes and spec reads do not need custom
headers.

`/validate` accepts `start` requests scoped by `hostId` and `crId`, session
operations scoped by `sessionId`, and owner rejoin discovery requests scoped by
`hostId` and `crId`.

`/tokens/validate` is used by token-consuming services. A successful response
returns the verified claims. Callers may provide expected `userId`, `hostId`,
`crId`, `connectionType`, `action`, and `mode` values; STS rejects the request
if any provided expected value does not match the signed token. Tokens bind the
session action (`start`, `rejoin`, or `observe`), mode, host, change request,
connection type, and trusted SSH target metadata. Observer tokens cannot become
writable owner connections.

Session tokens are RFC 7519 JWTs signed with JWS `HS256`. They include the
registered `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, and `jti` claims plus the
private session and SSH target claims. Verification only accepts `HS256` and
requires the configured issuer, audience, expiration, and issued-at values.

Automation capability tokens are a separate JWT type and cannot be used as
interactive session tokens. Issuance requires a projected Kubernetes
service-account token that passes TokenReview for the configured namespace,
service account, and audience. `AUTOMATION_WORKLOAD_SERVICE_ACCOUNTS` may list
multiple comma-separated service accounts during rollout, for example
`incident-agent,agent-controlplane`; after migration it should be narrowed to
the runtime issuer. Capabilities bind the run, incident, host, phase, operation
allowlist, assigned pod instance, and remediation plan hash.

For Phase 2 AI-agent integrations, STS remains the authority boundary. Model
output never grants capability by itself; callers must present workload identity
for issuance and consumers must validate the signed run, incident, host,
operation allowlist, assigned pod instance, and plan hash before executing any
automation step.

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

## API Specification

The OpenAPI contract is checked in at `api/openapi.yaml` and is served
unauthenticated at:

```http
GET /openapi.yaml
```
