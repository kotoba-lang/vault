# etzhayyim-project-vault App migration

このディレクトリは `legacy-runtime` 実装を残したまま、App 版を段階移行するための配置先です。

## 対象 App services

- `etzhayyim-performer-sys-etzhayyim-app-vault-chrome-extension-awh4ueht` -> `vault-extension-mcp-component`
- `etzhayyim-performer-sys-etzhayyim-app-vault-t33wiylr` -> `vault-mcp-component`

## App 実装

- `vault-mcp-component`
  - vault item API と MCP endpoint を提供
  - `wasi:keyvalue/store` へ状態永続化
  - `grpc`, `messaging`, `sqldb`, `blobstore` link config 対応
- `vault-extension-mcp-component`
  - extension config/event API と MCP endpoint を提供
  - `wasi:keyvalue/store` へ状態永続化

## 補足

- 既存 App runtime は互換運用のため維持。
- Chrome extension と連携する OS 側(Tauri)実装はこの移行対象外。
