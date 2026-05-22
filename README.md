# sts
# STS

Mock Security Token Service for the MVP. It validates well-formed access
requests and issues short-lived opaque session tokens.

## Run

```bash
PORT=8082 go run ./cmd/server
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
