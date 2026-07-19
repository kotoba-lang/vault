# vault-mcp-component

`etzhayyim-performer-sys-etzhayyim-app-vault-t33wiylr` の App 版コンポーネントです。

## Endpoints

- `GET /health`, `GET /healthz`, `GET /readyz`
- `GET|POST /api/v1/vault/items`
- `GET|PUT /api/v1/vault/items/{id}`
- `POST /api/mcp`, `POST /{nanoid}/api/mcp`

## MCP tools

- `vault.items_list`
- `vault.item_get`
- `vault.item_create`
- `vault.item_update`

## Persistence and providers

- `wasi:keyvalue/store` に `vault:state` を永続化
- `KV_BUCKET` default: `vault-state`
- provider link config をサポート:
  - `GRPC_LINK_NAME`
  - `MESSAGING_LINK_NAME`
  - `SQLDB_LINK_NAME`
  - `BLOBSTORE_LINK_NAME`
