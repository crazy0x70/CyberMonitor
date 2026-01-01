# GitHub Actions 工作流说明

## Build, Release and Deploy

用于统一构建、发布和部署 CyberMonitor（Go 驱动）。

### 触发方式

1. **Tag 推送**：推送以 `v` 开头的 tag（例如 `v0.1.0`）
   - 构建多平台 Server/Agent 二进制
   - 打包前端静态资源
   - 推送 Docker 镜像到 GHCR
   - 创建 GitHub Release

2. **手动触发**：在 GitHub Actions 页面手动运行并输入版本号

### 支持的平台

#### Server / Agent
| 平台 | 架构 |
|------|------|
| Linux | amd64, arm64, armv7 |
| macOS | amd64, arm64 |
| Windows | amd64 |
| FreeBSD | amd64, arm64 |

### 输出内容

- 二进制文件（Server 与 Agent 各一份）
- 前端静态资源归档（`web-dist.tar.gz` / `web-dist.zip`）
- SHA256 校验和
- Docker 镜像（GHCR）

### 构建参数

- Go 版本：1.22
- CGO：禁用（静态链接）
- 版本注入：`main.Version` / `main.Commit` / `main.BuildTime`
- 默认模式：通过 `main.DefaultMode` 区分 server/agent

### 使用示例

```bash
# 创建并推送 tag
git tag v0.1.0
git push origin v0.1.0
```

手动发布：在 Actions 页面运行 `Build, Release and Deploy`，输入版本号即可。
