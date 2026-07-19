# vault.etzhayyim.com (etzhayyim-project-vault) Design Document

## 概要 (Overview)
`vault.etzhayyim.com` は、1Password のようなパスワードおよびシークレット管理を提供するアプリケーションです。
バックエンドのセキュアな保存先として HashiCorp Vault を利用し、Clerk によって提供される `user_id` と `org_id` に基づいてユーザーごとの「Personal Vault」と組織内の「Shared Vault」を分離・管理します。

## アーキテクチャ (Architecture)

1. **Frontend (SvelteKit UI)**
   - **デプロイ**: `vault-mcp-component` の static 配信 (`/...`) に統合
   - **UIライブラリ**: `@etzhayyim/appshellv2` を使用した 1Password 風の3ペインレイアウト (Sidebar, Item List, Item Detail)
   - **認証**: `@etzhayyim/appshellv2/auth` (Clerk) を使用。ログイン後に `org_id` と `user_id` を取得。
   - **通信**: バックエンドの `vault-mcp-component` に対して、HTTP Header (`X-etzhayyim-ORG-ID`, `X-etzhayyim-USER-ID`) を付与してリクエストを送信。

2. **Backend (App Component)**
   - **コンポーネント**: `vault-mcp-component` (Go)
   - **役割**: Frontend または MCP クライアントからのリクエストを受け取り、認可チェックを行った上で HashiCorp Vault と通信する仲介（BFF/Gateway）として動作します。
   - **Vault通信**: `wasi:http/outgoing-handler` を使用して HashiCorp Vault の REST API (KV Secrets Engine v2) を呼び出すか、Vault用Capability Providerを使用します。

3. **Storage (HashiCorp Vault)**
   - **エンジン**: KV Secrets Engine v2
   - `vault-mcp-component` が持つ権限（AppRole または Service Token）を利用してアクセス。エンドユーザーの `org_id` と `user_id` はパスによって論理的に分離されます。

## Vault のパス設計 (Secret Path Design)

Clerkの情報を基に、以下のパス階層でデータを分離します。

*   **Personal Vault (個人用)**
    `secret/data/orgs/{org_id}/users/{user_id}/items/{item_id}`
    *ユーザー自身のみがアクセス可能。*

*   **Shared Vault (組織共有用)**
    `secret/data/orgs/{org_id}/shared/items/{item_id}`
    *同じ `org_id` に属する全ユーザー（あるいは権限を持つユーザー）がアクセス可能。*

各アイテムのメタデータとペイロード構造例:
```json
{
  "data": {
    "title": "GitHub Login",
    "category": "login",
    "username": "etzhayyim-user",
    "password": "secure-password123",
    "url": "https://github.com",
    "notes": "Used for work",
    "tags": ["dev", "git"]
  }
}
```

*※ Vault KV v2 のメタデータ（`secret/metadata/...`）を利用して、アイテムの一覧取得（LIST）を高速に行う設計とします。*

## API および MCP ツール設計

`vault-mcp-component` は以下の REST API および MCP ツールを提供します。

### MCP Tools
*   `vault.items_list`: 指定された Vault (Personal or Shared) のアイテム一覧をメタデータのみで返す。
*   `vault.item_get`: 特定の `item_id` の詳細（パスワード含む）を返す。
*   `vault.item_create`: 新しいシークレットを作成する。
*   `vault.item_update`: 既存のシークレットを更新する。
*   `vault.item_delete`: シークレットを削除する。

### REST API (Frontend用)
*   `GET /api/v1/vault/items?scope=personal`
*   `GET /api/v1/vault/items?scope=shared`
*   `GET /api/v1/vault/items/{item_id}?scope=personal`
*   `POST /api/v1/vault/items`
*   `PUT /api/v1/vault/items/{item_id}`
*   `DELETE /api/v1/vault/items/{item_id}`

すべてのリクエストで Clerk Middleware が検証した `org_id` と `user_id` をコンテキストとして使用し、不正なパスへのアクセスを Component 側でブロックします。

## セキュリティと認可 (Security & Authorization)

1. **認証**: Frontend で Clerk Token を取得し、Component 呼び出し時に JWT として送信するか、Edge/Gateway レベルで検証された Header (`X-etzhayyim-USER-ID`, `X-etzhayyim-ORG-ID`) を信頼します。
2. **認可 (Component層)**:
   - Personal アイテムへのアクセス時: リクエストの `user_id` とパスの `{user_id}` が一致すること。
   - Shared アイテムへのアクセス時: リクエストの `org_id` とパスの `{org_id}` が一致すること。
3. **Vault アクセス**: Component は自身に付与された権限（環境変数の `VAULT_TOKEN` や WADM の secrets 経由）を使用して HashiCorp Vault へアクセスし、ユーザーには直接 Vault トークンを渡しません。

## 今後の実装ステップ

1. **Vault環境のセットアップ**:
   - HashiCorp Vault クラスターで KV v2 エンジンを有効化 (`vault secrets enable -path=secret kv-v2`)。
   - コンポーネント用のポリシーとトークン/AppRoleの発行。
2. **`vault-mcp-component` の改修**:
   - 既存の `wasi:keyvalue` 実装を、Vault REST API (`wasi:http/outgoing-handler`) 呼び出しに置き換える。
   - リクエストヘッダーからの `org_id`, `user_id` 抽出とパスベースの認可ロジック追加。
3. **SvelteKit UI の統合作業**:
   - Clerk によるログインと、左カラム（Personal / Shared メニュー）、中央カラム（リスト）、右カラム（詳細・編集ペイン）を `vault-mcp-component/static` 配信構成へ統合。
4. **WADM / Kubernetes 定義の更新**:
   - `VAULT_ADDR` および認証情報を Component に注入する設定の追加。
