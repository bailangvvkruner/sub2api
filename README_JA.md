# Sub2API

[English](README.md) | [简体中文](README_CN.md)

Sub2API はセルフホスト型 AI API ゲートウェイです。本番バックエンドは
Rust に完全移行し、必要な状態サービスは PostgreSQL のみです。

## ランタイム契約

- `backend-rust/` が唯一サポートされるバックエンド実装です。
- PostgreSQL 18 が業務データ、セッション、レート制限、ジョブ、複数
  インスタンス間の調整状態を保存します。Redis は使用しません。
- Vue フロントエンドは本番コンテナに組み込まれます。
- `backend/` の旧実装は移行時の挙動比較専用です。サポート対象のビルド、
  テスト、リリース、デプロイには含まれません。
- 環境変数が常に優先されます。移行に必要な旧 `config.yaml` の値は限定的に
  読み込み、未対応の認証・セキュリティ・プロキシ・ゲートウェイ設定が既定値
  から変更されている場合は、無視せず該当キーを示して起動を拒否します。
- Redis の旧 refresh session は PostgreSQL に移行されません。Go 版からの
  切り替え後、既存の refresh token を持つユーザーは再ログインが必要です。

## Docker デプロイ

```sh
mkdir sub2api-deploy
cd sub2api-deploy
curl -fsSL https://raw.githubusercontent.com/bailangvvkruner/sub2api/main/deploy/docker-deploy.sh | sh
DOCKER_BUILDKIT=1 docker compose up -d --build --remove-orphans
```

起動後 `http://localhost:8080` を開きます。

```sh
docker compose ps
docker compose logs -f sub2api
docker compose pull
docker compose up -d --build --remove-orphans
```

既定の構成は `./data` と `./postgres_data` を永続化します。バックアップ時は
PostgreSQL と `.env` の両方を保存してください。外部 PostgreSQL を利用する
場合は `deploy/docker-compose.standalone.yml` と `deploy/.env.example` の
`DATABASE_*` 設定を使用します。

## 開発

Rust 1.97、Node.js 20 以降、pnpm 9 が必要です。統合テストには
PostgreSQL 18 も必要です。

```sh
pnpm --dir frontend install --frozen-lockfile
make build
make test
```

詳細は [DEV_GUIDE.md](DEV_GUIDE.md) と
[deploy/README.md](deploy/README.md) を参照してください。

## ライセンス

[LICENSE](LICENSE) を参照してください。
