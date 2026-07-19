# vault-extension-mcp-component

`etzhayyim-performer-sys-etzhayyim-app-vault-chrome-extension-awh4ueht` の App 版コンポーネントです。

## Endpoints

- `GET /health`, `GET /healthz`, `GET /readyz`
- `GET|PUT|POST /api/v1/extension/config`
- `GET|POST /api/v1/extension/events`
- `POST /api/mcp`, `POST /{nanoid}/api/mcp`

## MCP tools

- `vault_extension.get_config`
- `vault_extension.update_config`
- `vault_extension.record_event`
- `vault_extension.list_events`

## Persistence

- `wasi:keyvalue/store` に `vault-extension:state` を永続化
- `KV_BUCKET` default: `vault-extension-state`
