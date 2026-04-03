# GitHub Actions 工作流说明

## Build, Release and Deploy

用于统一构建、测试、打包、发布 CyberMonitor。

当前 workflow 的关键设计点是：

- 仓库只提交源码，不提交 `admin-ui/dist/`、`internal/server/web/admin-app/`、`internal/server/web/admin-assets/`
- React 管理后台产物在 CI 内生成
- Server 的 `go:embed` 依赖这些前端产物，因此 Go 测试与 Server 构建前必须先恢复它们

## 触发方式

1. `Tag` 推送：推送以 `v` 开头的标签，例如 `v0.3.1`
2. 手动触发：在 Actions 页面运行 `Build, Release and Deploy`，可选填写版本号

规则：

- `push tags` 时，版本号来自 Git 标签
- `workflow_dispatch` 时，版本号来自输入值；如果留空，会生成 `0.0.0-<run_number>`

## 工作流顺序

### 1. `version`

负责计算：

- `version`
- `tag`
- `build_time`

这些值会传给后续二进制构建、Docker 镜像构建和 Release 创建步骤。

### 2. `build-admin`

负责构建 React 管理后台。

执行内容：

- 校验 `admin-ui/` 与 `internal/server/web/index.html` 是否存在且已被 Git 跟踪
- 校验 `go.mod` 与 `Dockerfile` 中声明的 Go 版本完全一致
- 使用 Node `22`
- 执行 `npm --prefix admin-ui ci`
- 执行 `npm --prefix admin-ui run lint`
- 执行 `npm --prefix admin-ui run build:admin`
- 将生成的 `internal/server/web/admin-app/` 与 `internal/server/web/admin-assets/` 打包为 `admin-web-sync.tar.gz`
- 上传为 artifact：`admin-web-sync`

这是后续 `verify-go`、`build-server`、`build-web`、`docker-server` 的前置依赖。

### 3. `verify-go`

负责执行 Go 测试。

执行内容：

- 下载 `admin-web-sync`
- 恢复 `internal/server/web/admin-app/` 与 `internal/server/web/admin-assets/`
- 执行 `go test ./...`

之所以依赖 `build-admin`，是因为 `./cmd/server` 和 `internal/server` 使用了 `go:embed`；在干净 checkout 中，如果没有先恢复这些前端产物，测试会因为缺少嵌入目录而失败。

### 4. `build-server`

负责构建多平台 Server 二进制。

依赖：

- `version`
- `build-admin`
- `verify-go`

执行内容：

- 下载并恢复 `admin-web-sync`
- 构建多平台 `./cmd/server`
- 注入：
  - `main.Version`
  - `main.Commit`
  - `main.BuildTime`

支持的平台：

| 平台 | 架构 |
|------|------|
| Linux | amd64, arm64, armv7 |
| macOS | amd64, arm64 |
| Windows | amd64 |
| FreeBSD | amd64, arm64 |

### 5. `build-agent`

负责构建多平台 Agent 二进制。

依赖：

- `version`
- `verify-go`

执行内容：

- 构建多平台 `./cmd/agent`
- 注入：
  - `main.Version`
  - `main.Commit`
  - `main.BuildTime`

支持的平台与 Server 一致。

### 6. `build-web`

负责打包 Web 静态资源归档。

依赖：

- `version`
- `build-admin`

执行内容：

- 下载并恢复 `admin-web-sync`
- 将 `internal/server/web/` 打包成：
  - `web-dist.tar.gz`
  - `web-dist.zip`

### 7. `docker-server`

负责构建并推送 Server 镜像。

依赖：

- `version`
- `build-admin`
- `verify-go`

执行内容：

- 使用 `Dockerfile` 的 `release-server` 目标
- 构建多架构镜像：`linux/amd64`、`linux/arm64`
- 推送到：
  - `ghcr.io/<owner>/<repo>-server:<version>`
  - `ghcr.io/<owner>/<repo>-server:latest`

### 8. `docker-agent`

负责构建并推送 Agent 镜像。

依赖：

- `version`
- `verify-go`

执行内容：

- 使用 `Dockerfile` 的 `release-agent` 目标
- 构建多架构镜像：`linux/amd64`、`linux/arm64`
- 推送到：
  - `ghcr.io/<owner>/<repo>-agent:<version>`
  - `ghcr.io/<owner>/<repo>-agent:latest`

### 9. `release`

负责创建 GitHub Release。

依赖：

- `version`
- `build-server`
- `build-agent`
- `build-web`
- `docker-server`
- `docker-agent`

执行内容：

- 下载全部 artifact
- 合并多平台二进制与 Web 静态资源包
- 生成 SHA256 校验和
- 创建或更新 GitHub Release

## 输出内容

最终输出包括：

- 多平台 Server 二进制
- 多平台 Agent 二进制
- Web 静态资源归档：
  - `web-dist.tar.gz`
  - `web-dist.zip`
- `SHA256SUMS`
- GHCR Docker 镜像：
  - `...-server`
  - `...-agent`

## 构建参数

- Go 版本：读取 `go.mod`
- Node 版本：`22`
- CGO：禁用
- 版本注入：
  - `main.Version`
  - `main.Commit`
  - `main.BuildTime`

## 对仓库的要求

要让这套 workflow 正常运行，以下源码必须同步到 GitHub：

- `admin-ui/`
- `scripts/docker-entrypoint.sh`
- `internal/server/web/index.html`
- `cmd/`
- `internal/`
- `Dockerfile`
- `.github/workflows/build-release.yml`

不需要同步到 GitHub 的内容：

- `admin-ui/node_modules/`
- `admin-ui/dist/`
- `internal/server/web/admin-app/`
- `internal/server/web/admin-assets/`
- 本地调试缓存与临时目录

## 手动发布示例

```bash
git tag v0.3.1
git push origin v0.3.1
```

或者直接在 GitHub Actions 页面手动运行 `Build, Release and Deploy`。
