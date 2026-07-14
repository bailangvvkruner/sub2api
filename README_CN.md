# Sub2API

[English](README.md) | [日本語](README_JA.md)

Sub2API 是自托管的 AI API 网关。生产后端已全面迁移到 Rust，PostgreSQL
是唯一必需的状态服务。

## 运行时约定

- `backend-rust/` 是唯一受支持的后端实现。
- PostgreSQL 18 统一保存业务数据、会话、限流、任务和多实例协调状态；
  不使用也不依赖 Redis。
- Vue 前端会一并构建进生产容器。
- `backend/` 中的旧实现仅用于迁移考古和行为对照，不会进入任何受支持的
  构建、测试、发布或部署流程。
- 环境变量仍具有最高优先级；切换期间会有限兼容旧 `config.yaml`。无法兼容且
  偏离默认值的认证、安全、代理或网关配置会带具体键名拒绝启动，不会被静默忽略。
- Redis 中的旧 refresh session 不会导入 PostgreSQL。由 Go 版本切换后，旧
  refresh token 无法继续刷新，相关用户需要重新登录。

## Docker 部署

部署脚本会生成持久化密钥、检查 PostgreSQL 数据目录，并准备 Rust Compose：

```sh
mkdir sub2api-deploy
cd sub2api-deploy
curl -fsSL https://raw.githubusercontent.com/bailangvvkruner/sub2api/main/deploy/docker-deploy.sh | sh
DOCKER_BUILDKIT=1 docker compose up -d --build --remove-orphans
```

启动后访问 `http://localhost:8080`。常用命令：

```sh
docker compose ps
docker compose logs -f sub2api
docker compose pull
docker compose up -d --build --remove-orphans
```

默认部署持久化 `./data` 和 `./postgres_data`。备份时必须同时保存 PostgreSQL
数据和 `.env`，登录会话与加密数据依赖 `.env` 中的固定密钥。

如果使用外部托管 PostgreSQL，请使用 `deploy/docker-compose.standalone.yml`，
并按 `deploy/.env.example` 配置 `DATABASE_*` 环境变量。

## 本地开发

需要 Rust 1.97、Node.js 20+、pnpm 9；集成测试需要 PostgreSQL 18。

```sh
pnpm --dir frontend install --frozen-lockfile
make build
make test
```

PostgreSQL 集成测试需要 `TEST_DATABASE_URL`：

```sh
export TEST_DATABASE_URL='postgresql://sub2api:password@127.0.0.1:5432/sub2api_test?sslmode=disable'
make test-rust-integration
```

开发约定见 [DEV_GUIDE.md](DEV_GUIDE.md)，生产运维见
[deploy/README.md](deploy/README.md)。

## 许可证

见 [LICENSE](LICENSE)。
