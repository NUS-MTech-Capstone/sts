# STS

Security Token Service. It validates well-formed access
requests and issues short-lived session tokens.

## Run

```bash
PORT=8082 \
CHANGE_REQUEST_URL=http://localhost:8085 \
SERVER_INVENTORY_URL=http://localhost:8086 \
go run ./cmd/server
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

`/tokens/validate` is included so the proxy dataplane can validate WebSocket
session tokens during the local MVP.
