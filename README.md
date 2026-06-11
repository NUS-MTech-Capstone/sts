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

`JWT_SIGNING_KEY` is required and must contain at least 32 bytes. All STS
instances and token-verifying services must use the same secret. Generate one
for local development with `openssl rand -base64 32`.

Optional token settings:

```bash
SESSION_TOKEN_TTL_SECONDS=300
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
```

`/tokens/validate` is used by the proxy dataplane and DDM Agent. Validation may
include `userId` and `mode`; when supplied, STS requires them to match the JWT
claims. The DDM Agent requires `mode: "owner"` before command execution, so an
observer token cannot run commands.

Session tokens are RFC 7519 JWTs signed with JWS `HS256`. They include the
registered `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, and `jti` claims plus the
private `sessionId` and `mode` claims. Verification only accepts `HS256` and
requires the configured issuer, audience, expiration, and issued-at values.
