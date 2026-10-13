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
AUTOMATION_WORKLOAD_AUDIENCE=dendenmushi-incident-agent
AUTOMATION_WORKLOAD_NAMESPACE=dendenmushi-agentic
AUTOMATION_TOKEN_SERVICE_ACCOUNTS=agent-tool-gateway
WORKLOAD_IDENTITY_SERVICE_ACCOUNTS=incident-agent,agent-controlplane
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

## Trusted change-request authorization

`CHANGE_REQUEST_URL` is required for interactive access. STS fails closed when
it is absent or its lookup fails. In EKS it points to
`http://nest-backend.dendenmushi-webapp.svc.cluster.local:3000/sts`.
The trusted backend returns:

```http
GET /change-requests/{crId}
```

```json
{
  "crId": "cr-123",
  "status": "Approved",
  "hostIds": ["host-123"],
  "implementationStartAt": "2026-10-07T08:00:00.000Z",
  "implementationEndAt": "2026-10-07T10:00:00.000Z",
  "allowedRoles": ["Employee"]
}
```

Start, rejoin, observe, rejoin discovery, and `/tokens/session` issuance require:

- The returned CR ID matches the requested ID and its status is approved.
- Both timestamps are valid, start precedes end, and `start <= now < end`.
  CR windows have no clock-skew grace period.
- `hostIds` is explicitly present, non-empty, contains no blank entries, and
  includes the exact requested gateway host ID.
- `actorGroups` comes from Proxy Control Plane's cryptographically verified
  Cognito access token. Group names match `allowedRoles` case-insensitively,
  consistent with the web application's role mapping (for example, `admin`
  and `Admin`). Whitespace-padded role names remain invalid; host and CR IDs
  remain case-sensitive. `Admin` bypasses role matching only, including an
  explicitly empty role list.
  Missing/null/malformed role metadata is denied even for Admin.

The STS API is internal: caller assertions are trusted only within the existing
service/network boundary. Do not expose `/validate` or `/tokens/session` to
browsers or accept browser-supplied actor groups. Missing actor context, malformed
metadata, and unavailable upstreams deny access with sanitized errors. Role/group
checks refer to Cognito groups, not implementer-group OS usernames.

For rejoin and observe, Proxy Control Plane resolves `hostId` and `crId` from
Session Manager. Rejoin remains owner-only; observe remains read-only. A
`sessionId` alone is no longer sufficient for these STS policy checks.
Closing a session remains available after CR expiry. Existing attachments and
issued-token TTLs retain their lifecycle behavior; this policy does not terminate
an already attached terminal at the CR end time.

A configured inventory URL still uses `GET /servers/{hostId}`. EKS continues to
use trusted static SSH inventory. CR metadata never supplies SSH credentials.

Deploy the compatible Nest response first, then Proxy Control Plane actor-group
forwarding, then STS enforcement. Older callers missing the new fields fail
closed after STS rolls out. Roll back through immutable GitOps image promotions;
rolling back enforcing STS restores its earlier, weaker authorization behavior.

## Design Patterns

STS models access checks as policy strategies behind the `/validate` endpoint.
Common validation runs first, then the action-specific policy for `start`,
`rejoin`, `observe`, or `stop`. The `start` policy composes the trusted
change-request and optional server-inventory clients using the internal actor-group contract.

## Endpoints

```http
GET  /healthz
POST /validate
POST /tokens/session
POST /tokens/validate
POST /tokens/automation
POST /tokens/automation/validate
POST /workloads/validate
```

Business endpoints require `x-api-version: 1`. `GET /healthz` and
`GET /openapi.yaml` are exempt so probes and spec reads do not need custom
headers.
Successful probe request logs are suppressed; failed probe responses still emit
request logs.

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
audience, and `AUTOMATION_TOKEN_SERVICE_ACCOUNTS`; production narrows this to
`agent-tool-gateway`. Capabilities bind the run, incident, host, phase,
operation allowlist, assigned pod instance, and remediation plan hash.

`POST /workloads/validate` validates projected tokens against
`WORKLOAD_IDENTITY_SERVICE_ACCOUNTS` and returns only normalized `subject`,
`namespace`, and `serviceAccount` fields. A2A and MCP services use this endpoint
for authentication. It never returns or logs the submitted token. The existing
audience is intentionally retained so identity and capability callers can use
the same projected-token configuration while their service-account allowlists
remain separate.

The Kubernetes reviewer credential is read from its mounted service-account
token file for every TokenReview. Kubernetes rotates this file while the STS
pod is running; STS fails closed if the current credential is missing or empty
and never logs either the reviewer credential or submitted workload token.

For Phase 2 AI-agent integrations, STS remains the authority boundary. Model
output never grants capability by itself; callers must present workload identity
for issuance and consumers must validate the signed run, incident, host,
operation allowlist, assigned pod instance, and plan hash before executing any
automation step.

Trusted inventory entries may include:

```json
{
  "automation": {
    "catalogVersion": "v1",
    "serviceName": "myapp",
    "healthUrl": "http://127.0.0.1:8080/healthz",
    "helperPath": "/usr/local/sbin/ddm-ops",
    "allowedOperations": [
      "service_status",
      "health_check",
      "restart_service",
      "recover_demo_app",
      "reload_service"
    ]
  }
}
```

## API Specification

The OpenAPI contract is checked in at `api/openapi.yaml` and is served
unauthenticated at:

```http
GET /openapi.yaml
```

## API contract verification

`api/openapi.yaml` is the checked-in HTTP contract, served byte-for-byte at
`GET /openapi.yaml`. CI validates it with `openapi-spec-validator==0.9.0`.
Handler tests validate representative success and error responses against its
schemas, including missing and unsupported API versions. Business HTTP calls
require `x-api-version: 1`; the specification declares route exemptions and
any transport-specific alternatives. Run the repository test suite when
changing handlers or response models, and update the contract in the same PR.

The Image workflow runs only after successful CI for a push to `main`. It builds
the tested source SHA, retains that SHA as a traceability tag, and promotes the
build's `sha256` digest through a Kubernetes PR. Promotion requires the digest;
Argo CD deploys that immutable reference after the GitOps PR is merged.
