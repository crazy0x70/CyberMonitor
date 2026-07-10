# CyberMonitor Evolution Log

## 2026-07-08 / Prefix guard hardening and Go 1.26.5 rebase

### 审视

- subagent 安全复核未发现 remote-update-v2 / webhook callback / public probe 高风险问题，但指出 callback URL 允许 userinfo 属于低风险配置卫生缺口。
- subagent admin runtime 复核未发现高风险断裂，但指出前端 `normalizeBasePath` 只解码 3 轮，和服务端 forwarded prefix 的 4 轮稳定解码策略不一致。
- 新一轮官方版本复核显示：
  - Node 官方 dist index 顶部版本仍为 `v26.4.0`。
  - Go 官方 `VERSION?m=text` 当前为 `go1.26.5`，覆盖前一阶段 `go1.26.4` 的结论。
- 当前正式 diff 为 73 个文件；`internal/netguard/netguard.go` 已是 `A` 状态，不再是 untracked 漏洞。

### 执行

- 将前端 `normalizeBasePath` 调整为最多 4 轮解码；4 轮后仍未稳定则拒绝，并在每轮解码后即时拒绝 query/hash/control char。
- 为 admin API path 合同补充深层编码回归：`/%2525252e%2525252e/admin`、`/%252525252e%252525252e/admin`、`/%25252563m` 均拒绝。
- 在 `validateHTTPCallbackURL` 中拒绝 `parsed.User != nil`，禁止 `https://user:pass@host/path` 这类误导性 callback 配置。
- 将 Go 版本源头从 `1.26.4` 升到 `1.26.5`：
  - `go.mod`
  - `Dockerfile` 的 `GO_IMAGE_VERSION`
  - README / README_zh-CN badge
- 重新生成 admin build 产物，确保 Go embed 读取的 dist 与源码一致。

### 验证

- `curl https://nodejs.org/dist/index.json`
  - 顶部版本为 `v26.4.0`。
- `curl https://go.dev/VERSION?m=text`
  - 输出 `go1.26.5`。
- `npm --prefix internal/server/web/admin outdated --json --cache /SourceCode/CyberMonitor/.cache/npm`
  - 返回 `{}`。
- `go list -m -u -f '{{if and .Update (not .Indirect)}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all`
  - 无输出，direct Go dependencies 无可用更新。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/server -run TestWebhookRejectsPrivateCallbackHosts -count=1`
  - 触发并使用 `go1.26.5` toolchain，通过。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp npm exec --yes --cache /SourceCode/CyberMonitor/.cache/npm --package=node@26.4.0 -- bash scripts/verify-local.sh`
  - 通过。
  - 覆盖 64 个 Node contract tests、`npm ci`、admin lint、admin build、`go vet ./...`、`go test ./...`。
- `go env GOVERSION`
  - 在项目内输出 `go1.26.5`。
- `go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - 通过。
- Runtime smoke:
  - 使用 `go1.26.5` 重新编译 `dist/cyber-monitor-server-local`。
  - `GET /admin/` 返回 200。
  - `GET /cm/admin/` 携带 `X-Forwarded-Prefix: /cm` 返回 200，boot payload `base_path` 为 `/cm`。
  - `POST /api/v1/login` 后携带 session cookie 请求 `/api/v1/admin/session`，返回 `{"authenticated":true}`。
  - Headless Chrome 打开 `/admin/` 后渲染登录页；页面上下文 `POST /api/v1/login` 成功；reload 后进入后台首页，导航包含 首页、节点管理、分组管理、探测设置、基础设置、通知告警、AI 服务商、退出登录。
- `git diff --check`
  - 通过。
- 正式源码/配置残留扫描：
  - `Dockerfile go.mod README.md README_zh-CN.md .github scripts cmd internal` 中无 `1.26.4` / `go1.26.4` 残留。

## 2026-07-08 / Active-goal recheck and Node 26 validation

### 审视

- 按当前 worktree 重新审计，不沿用上一轮完成结论。
- 当前正式变更仍为 71 个文件；新增文件以 `A` 出现在 diff 中，`git ls-files --others --exclude-standard` 无输出。
- `git diff --check` 通过，说明当前 patch 没有 whitespace/error marker 问题。
- 本机默认 `node` 仍为 25.x，但项目目标 Node 是 `26.4.0`；因此额外用 npm-provided `node@26.4.0` 跑 frontend typecheck/build，避免只用本机旧 Node 支撑结论。
- fresh latest 复核显示：
  - Go 官方当前版本为 `go1.26.4`。
  - Node 官方当前版本为 `v26.4.0`。
  - GitHub Releases API 返回的 workflow action latest tags 与当前 pins 一致。

### 执行

- 未修改产品代码。
- 追加本轮复核记录，保持长期任务的验证证据可追踪。
- 根据终审 reviewer 的低风险发现，将 `.codex/` 和 `.agents/` 补入 `.gitignore`，与 `.dockerignore` 的本地 agent 状态目录排除口径对齐。
- 继续保留当前新增文件的 diff 可见状态；提交前仍需要正常 `git add`，不能只依赖 intent-to-add。

### 验证

- `./scripts/verify-local.sh`
  - 通过。
  - 覆盖 shell syntax、64 个 Node contract tests、`npm ci`、admin lint、admin build、`go vet ./...`、`go test ./...`。
- `go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - 通过。
- `npm outdated --json`
  - 返回 `{}`。
- `go list -m -u -f '{{if and .Update (not .Indirect)}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all`
  - 无输出，direct Go dependencies 无可用更新。
- `npm exec --yes --cache /SourceCode/CyberMonitor/.cache/npm --package=node@26.4.0 -- node --version`
  - 输出 `v26.4.0`。
- `npm exec --yes --cache /SourceCode/CyberMonitor/.cache/npm --package=node@26.4.0 -- node ./node_modules/typescript/bin/tsc --noEmit`
  - 通过。
- `npm exec --yes --cache /SourceCode/CyberMonitor/.cache/npm --package=node@26.4.0 -- node ./node_modules/vite/bin/vite.js build`
  - 通过。
- Clean-checkout patch apply:
  - `git diff --binary HEAD` 导出的 patch 可在 clean clone 中 `git apply --check --index`。
  - `git apply --index` 后 `git diff --check` 通过。
  - clean clone 中 `git ls-files --others --exclude-standard` 无输出。
- Docker-managed update 语义复核：
  - `resolveDockerImageID(ctx, cli, targetImage)` 仍只用于拿 immutable image ID。
  - `buildReplacementSpec(inspect, targetImage, currentNodeID)` 仍保留可 retag 的目标镜像引用。
  - `verifyReplacementContainerImage(ctx, cli, created.ID, targetImageID)` 仍在替换前校验实际 image ID。
- `.gitignore` / `.dockerignore` 本地 agent 状态目录口径：
  - `.codex/` 和 `.agents/` 均被 `.gitignore` 忽略。
  - `.dockerignore` 也继续排除 `.codex` 和 `.agents`。

## 2026-07-07 / Vuln surface guard tightening and latest-version recheck

### 审视

- 当前 completion-gap 不只看测试是否通过，还要看新增正式交付文件是否能被 review/PR/clean-checkout 看到。
- `git ls-files --others --exclude-standard` 显示 29 个正式文件仍是 untracked，覆盖 `.node-version`、`scripts/verify-local.sh`、workflow 自测、Node 回归、Go 回归测试和本日志。
- 这些文件不是临时产物：workflow、`verify-local.sh`、`build-local.sh`、Go package tests 已经引用或依赖它们。
- Completion-gap reviewer 发现 Docker-managed replacement 在 image ID 绑定后仍存在一个连续更新语义缺口：
  - helper pull/inspect 出 `targetImageID` 后，把 `sha256:` ID 传给 `buildReplacementSpec`。
  - 替换容器的 `Config.Image` 会变成不可 retag 的 image ID。
  - 下一次产品进程通过 `NewDockerManagedUpdaterContext -> CurrentImage -> ResolveDockerTargetImage` 解析目标版本时会失败。
- 正确语义应是：替换容器保留可 retag 的目标镜像引用；不可变 image ID 只用于创建后 `inspect.Image` 校验。
- 上一轮 `go-vuln-surface` 已能约束 `github.com/docker/docker/...` 和 Prometheus TSDB-only 暴露面，但项目通过 `replace github.com/docker/docker => github.com/moby/moby` 使用 Moby module；未来如果生产代码直接 import `github.com/moby/moby/...`，原 guard 不会拦住。
- `admin-frontend-contract.test.mjs` 已检查 `verify-local.sh` 内的 admin/public Node 回归清单，但尚未把新增的 `go-vuln-surface.test.mjs` 纳入该本地入口合约。
- 版本事实重新复核：
  - Go 官方当前版本仍为 `go1.26.4`。
  - Node 官方当前版本仍为 `v26.4.0`。
  - release workflow 当前使用的 GitHub Actions pins 均匹配各自 GitHub latest release。
  - Admin npm dependencies 无 outdated 输出。

### 执行

- 对 29 个新增正式文件执行 `git add -N -- ...`：
  - 不提交、不暂存内容。
  - 将新增文件标记为 intent-to-add，让 `git diff`、review 和 patch 视图包含它们。
  - `git ls-files --others --exclude-standard` 清零，避免新增文件继续停留在 review 不可见状态。
- 修复 `RunDockerRecreateHelper`：
  - `buildReplacementSpec` 继续接收 `targetImage`，让 replacement `Config.Image` 保留 repo tag。
  - `targetImageID` 继续用于 `verifyReplacementContainerImage`，在停止旧容器前验证新容器实际镜像 ID。
- 新增 `TestBuildReplacementSpecKeepsRetaggableImageReference`：
  - 验证 replacement `Config.Image` 保留 repo tag。
  - 验证该 image ref 能继续被 `ResolveDockerTargetImage` 解析为下一次更新目标。
- 扩展 `internal/server/web/go-vuln-surface.test.mjs` 的 Docker import 扫描范围：
  - 同时扫描 `github.com/docker/docker/...` 和 `github.com/moby/moby/...`。
  - 仍只允许当前审视过的 Docker lifecycle client/types import。
  - 直接 `github.com/moby/moby/...` 生产 import 会被判为超出已审视暴露面。
- 将 `internal/server/web/go-vuln-surface.test.mjs` 加入 `admin-frontend-contract.test.mjs` 对 `scripts/verify-local.sh` 的清单断言，避免本地验证入口后续漏跑。

### 验证

- Clean-checkout simulation:
  - `git diff --check`
    - 通过。
  - `git ls-files --others --exclude-standard`
    - 无输出。
  - `git diff --name-status HEAD > /tmp/cm-source.names`
    - 生成源工作区变更清单。
  - `git diff --binary HEAD > /tmp/cm-current.diff`
    - 导出包含 29 个新增正式文件的完整 patch。
  - `git clone --no-hardlinks /SourceCode/CyberMonitor /tmp/cm-clean-index && git -C /tmp/cm-clean-index checkout --detach HEAD`
    - 创建干净 Git checkout。
  - `git -C /tmp/cm-clean-index apply --check --index /tmp/cm-current.diff && git -C /tmp/cm-clean-index apply --index /tmp/cm-current.diff`
    - patch 可在 clean checkout 上按 index 语义应用。
  - `git -C /tmp/cm-clean-index diff --cached --name-status HEAD > /tmp/cm-clean.names && diff -u /tmp/cm-source.names /tmp/cm-clean.names`
    - clean checkout 应用后的变更清单与源工作区一致。
  - `git -C /tmp/cm-clean-index diff --name-status`
    - 无输出。
  - `git -C /tmp/cm-clean-index ls-files --others --exclude-standard`
    - 无输出。
  - `node --test ... .github/workflows/build-release.test.mjs`
    - clean checkout 中 64 pass。
  - `npm --prefix internal/server/web/admin ci --cache /tmp/cm-clean-index/.cache/npm`
    - clean checkout 中通过，`found 0 vulnerabilities`。
  - `npm --prefix internal/server/web/admin run build:admin`
    - clean checkout 中通过。
  - `test -s internal/server/web/dist/admin/index.html && find internal/server/web/dist/admin/assets -type f | grep -q .`
    - clean checkout 中通过，确认 Go embed 所需 admin dist 已生成。
  - `go test ./internal/server -run TestServerServesStaticAssetsAndAdminBoot -count=1`
    - clean checkout 中通过。
  - `go test ./internal/server -count=1`
    - clean checkout 中通过。
  - `go test ./internal/updater -run 'Test(BuildReplacementSpecKeepsRetaggableImageReference|ResolveDockerTargetImage|ResolveDockerImageID|VerifyReplacementContainerImage)' -count=1`
    - clean checkout 中通过。
  - 说明：clean checkout 初次 Go 测试使用 `/tmp/cm-clean-index` 内部 cache 时触发 `no space left on device`；清理该临时 Go cache 后改用主工作区 Go cache/TMP 复跑通过。该失败为验证环境空间问题，不是源码或 patch 问题。
- `git ls-files --others --exclude-standard`
  - 无输出。
- `git diff --stat`
  - 新增正式文件已以 `A` 出现在 diff 中。
- `go test ./internal/updater -run 'Test(BuildReplacementSpecKeepsRetaggableImageReference|ResolveDockerTargetImage|ResolveDockerImageID|VerifyReplacementContainerImage)' -count=1`
  - 通过。
- `go test ./internal/updater -count=1`
  - 通过。
- `go vet ./...`
  - 通过。
- `go test ./...`
  - 通过。
- `go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - 通过。
- `git diff --check`
  - 通过。
- `node --test internal/server/web/go-vuln-surface.test.mjs internal/server/web/admin-frontend-contract.test.mjs`
  - 17 pass。
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/go-vuln-surface.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
  - 64 pass。
- `curl -sS https://go.dev/VERSION?m=text`
  - `go1.26.4`，`time 2026-05-29T15:26:39Z`。
- `curl -sS https://nodejs.org/dist/index.tab`
  - latest row `v26.4.0`，date `2026-06-24`。
- GitHub release API latest tags:
  - `actions/checkout v7.0.0`
  - `actions/setup-go v6.5.0`
  - `actions/setup-node v6.4.0`
  - `actions/cache v6.1.0`
  - `actions/upload-artifact v7.0.1`
  - `actions/download-artifact v8.0.1`
  - `docker/setup-qemu-action v4.2.0`
  - `docker/setup-buildx-action v4.2.0`
  - `docker/login-action v4.4.0`
  - `docker/build-push-action v7.3.0`
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
  - `{}`。
- `go list -m -u -f '{{if not .Indirect}}{{.Path}} {{.Version}}{{with .Update}} -> {{.Version}}{{end}}{{end}}' all`
  - direct dependencies 无 `->` 升级输出。

### 提升

- `go-vuln-surface` 仍是源码暴露面 guard，不是漏洞消除；`govulncheck` 的 no-fixed upstream findings 继续按暴露面和上游 fixed version 跟踪。
- 后续如果新增生产目录不在 `cmd` 或 `internal` 下，需要同步扩展该 guard 的扫描根目录。

## 2026-07-07 / Govulncheck source scan follow-up

### 审视

- 上一轮 `govulncheck` 通过 `/usr/bin/go` 运行时被 Go 1.24 wrapper / auto toolchain 影响，未形成有效漏洞扫描结论。
- 当前 `go version` 在项目内为 `go1.26.4`，实际 toolchain 位于 `.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.4.linux-amd64/bin/go`。
- `go list -m -u` 对 direct dependencies 无 `->` 升级输出。

### 执行

- 直接使用工作区 Go 1.26.4 toolchain 运行 `govulncheck`，避免 wrapper 降级。
- 不添加 `govulncheck` allowlist gate，不把 no-fixed 上游 findings 写成可忽略项；先以扫描证据和暴露面判断为准。
- 新增 `internal/server/web/go-vuln-surface.test.mjs`，把当前判断固化为代码回归约束：
  - 生产 Docker imports 仅允许已审视的 lifecycle client/API types。
  - 生产 Docker 调用禁止触达 archive、docker cp、plugin API。
  - 生产 Prometheus imports 仅允许 TSDB / labels / storage / chunkenc。
- 将该测试接入 `scripts/verify-local.sh`、release workflow 的 Node regression 清单和 `.github/workflows/build-release.test.mjs`。

### 验证

- `/SourceCode/CyberMonitor/.cache/go-mod/golang.org/toolchain@v0.0.1-go1.26.4.linux-amd64/bin/go version`
  - `go version go1.26.4 linux/amd64`。
- `govulncheck -scan=package ./...`
  - 发现 6 个 package-level findings：
    - `GO-2026-5746` / `GO-2026-5668` / `GO-2026-5617` / `GO-2026-4887` / `GO-2026-4883`，module `github.com/moby/moby@v28.5.2+incompatible`，`Fixed in: N/A`。
    - `GO-2026-5662`，module `github.com/prometheus/prometheus@v0.313.0`，`Fixed in: N/A`。
- `govulncheck -scan=symbol ./...`
  - 同样返回 6 个 findings；大量 traces 来自 Docker client/API import 和 Prometheus TSDB import。
- `node --test internal/server/web/go-vuln-surface.test.mjs`
  - 3 pass。
- `node --test .github/workflows/build-release.test.mjs`
  - 8 pass。
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/go-vuln-surface.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
  - 64 pass。

### 提升

- Moby findings 已按实际 Docker API 暴露面复核并加入回归测试；当前代码使用 container create/start/stop/rename/remove、image pull/inspect、network connect/disconnect，没有发现 `ContainerArchive` / docker cp 相关调用。
- Prometheus finding 指向 Prometheus web UI stored XSS；当前项目直接使用 TSDB / labels / storage / chunkenc，不运行 Prometheus web UI，且新增测试会阻止无意引入 Prometheus Web UI/API/template 面。后续如上游发布 fixed version，应优先通过 direct dependency bump 解决。
- `govulncheck` 现在应被视为“已运行且存在 no-fixed upstream findings”，不是“未运行”。

## 2026-07-07 / Docker consecutive replacement smoke and dependency completion wording

### 审视

- 上一轮已证明 detached helper 生产路径可完成单次 Docker replacement；剩余语义问题是连续两次 replacement 是否会被旧 `CM_CONTAINER_ID` 污染。
- 收口审计发现 `scripts/verify-local.sh` 已覆盖 `readme-docker-security`、`admin-frontend-contract`、`admin-i18n` 三类合约测试，但 release workflow 的 Node regression 清单仍缺这三项，存在本地与 CI 验证入口不一致。
- 前端 reviewer 发现节点保存/删除仍在 mutation 成功后 `await handleRefreshNodes()`；如果后续列表刷新失败，UI 会把已成功的保存/删除误报为失败。
- 后端 reviewer 发现 Docker-managed update 仍以 mutable tag 作为替换容器创建输入；虽然不是任意命令执行，但在 tag 被并发改写或 registry tag policy 弱时缺少本地不可变 image ID 绑定。
- 本地没有 Node 版本文件；Dockerfile / workflow 已固定官方 latest `26.4.0`，但当前 shell Node 仍是 `v25.9.0`，容易让开发验证与发布目标漂移。
- 两个 `gpt-5.5` / `xhigh` subagent 继续只读复核：
  - Docker 侧确认最小非冗余测试应放在 detached helper daemon smoke 层，不再扩展直接调用 `RunDockerRecreateHelper` 的路径。
  - Go 依赖侧确认 direct dependencies 无稳定升级提示；`github.com/gorilla/websocket` 当前是高于最新 tag `v1.5.3` 的 pseudo-version，不应在 indirect 批处理中处理。
- `go list -m -u all` 仍显示 indirect modules 有可更新项；这些主要来自 Prometheus、Docker/Moby、Kubernetes、OpenTelemetry、AWS/Cloud SDK 等上游传递依赖。没有 CVE、构建失败或 direct dependency bump 需求时，不强行 pin indirect。

### 执行

- 新增 `TestDockerLaunchSelfContainerUpdateDetachedHelperDaemonRunsTwiceWithoutStaleContainerID`：
  - 默认 skip，复用 `CM_RUN_DOCKER_DAEMON_TEST=1` 和 `CM_RUN_DOCKER_DETACHED_HELPER_TEST=1`。
  - 初始目标容器显式带入 `CM_CONTAINER_ID=stale-container-id`。
  - 第一次 replacement 后，检查真实 Docker inspect 的新容器 env 不再含 `CM_CONTAINER_ID`。
  - 第二次 replacement 使用第一次 replacement 的当前容器 ID，验证仍能完成替换。
- 提取 test helper：
  - `createDockerDaemonSmokeContainerWithEnv`
  - `launchDockerDaemonDetachedHelperReplacement`
  - `envContainsKey`
- 将 release workflow 的 Node regression 清单补齐到与 `scripts/verify-local.sh` 一致：
  - `scripts/readme-docker-security.test.mjs`
  - `internal/server/web/admin-frontend-contract.test.mjs`
  - `internal/server/web/admin-i18n.test.mjs`
- 同步 `.github/workflows/build-release.test.mjs`，让 workflow 自检能拦住关键合约测试清单再次缺失。
- 将 `handleSaveNode` / `handleDeleteNode` 改为复用 `refreshNodesAfterMutation` 的非阻塞刷新路径，mutation 成功先返回给页面，刷新失败只给 warning。
- 为节点保存/删除补 `admin-frontend-contract` 静态合约，禁止回退到 `await handleRefreshNodes()` 或直接 `await fetchNodes()`。
- Docker recreate helper 在 `ImagePull` 后立即 `ImageInspect` 目标 tag，解析本地 `sha256:` image ID；替换容器使用该 image ID 创建，并在停止旧容器前校验新容器 inspect 的 image ID 与期望一致。
- 补 `resolveDockerImageID` / `verifyReplacementContainerImage` 单元测试，覆盖无效 ID 和 image mismatch 失败路径。
- 增加根目录 `.node-version`，固定为 `26.4.0`，并在 workflow 自检中校验其与 Dockerfile Node 版本一致。
- Docker image ID 绑定和前端节点 mutation 刷新误报都已做产品代码修复；连续 replacement 的新增覆盖仍保持在 opt-in 集成测试层。

### 验证

- `node --test .github/workflows/build-release.test.mjs`
  - 8 pass。
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
  - 61 pass。
- `node --test internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-delete-node.test.mjs`
  - 15 pass。
- `CM_RUN_DOCKER_DAEMON_TEST=1 CM_RUN_DOCKER_DETACHED_HELPER_TEST=1 go test ./internal/updater -run '^TestDockerLaunchSelfContainerUpdateDetachedHelperDaemonRunsTwiceWithoutStaleContainerID$' -count=1 -v`
  - 通过，耗时约 118s。
- `CM_RUN_DOCKER_DAEMON_TEST=1 CM_RUN_DOCKER_DETACHED_HELPER_TEST=1 go test ./internal/updater -run '^TestDockerLaunchSelfContainerUpdateDetachedHelperDaemon(Smoke|RunsTwiceWithoutStaleContainerID)$' -count=1 -v`
  - 通过，耗时约 203s；覆盖 image ID 绑定后的真实 detached helper daemon 路径。
- `go test ./internal/updater -run '^TestDockerLaunchSelfContainerUpdateDetachedHelperDaemon(RunsTwiceWithoutStaleContainerID|Smoke)$' -count=1 -v`
  - 默认 skip 语义通过。
- `go test ./internal/updater -count=1`
  - 通过。
- `go test ./...`
  - 通过。
- `go vet ./...`
  - 通过。
- `npm --prefix internal/server/web/admin run lint`
  - 通过。
- `npm --prefix internal/server/web/admin run build:admin`
  - 通过。
- `go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - 通过。
- `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`
  - 早前通过 `/usr/bin/go` wrapper 未通过扫描启动：`go run` 自动切到 Go `1.25.11` 后无法加载本项目 Go `1.26` 包；强制 `GOTOOLCHAIN=local` 又暴露本地 toolchain base 为 Go `1.24.4`。该结论已被上方 “Govulncheck source scan follow-up” 的工作区 Go 1.26.4 直跑结果覆盖。
- `git diff --check`
  - 通过。
- Docker 资源清理复查说明：
  - opt-in smoke 自身包含 helper AutoRemove 和目标容器 cleanup 等待。
  - 额外 `docker ps` / `docker images` 只读复查在本轮收尾时被 approval reviewer 的 `503/429` 拦截，未绕过执行，因此不把该额外复查记为已验证。

### 提升

- 本地验证入口与 release workflow 的关键 Node 合约测试清单已经对齐；后续新增合约测试应同步放入 `scripts/verify-local.sh`、release workflow 和 workflow 自检。
- Docker-managed update 现在把目标 tag 收敛为本地不可变 image ID 后再创建替换容器；这能防止 pull/create 之间 tag 被重新解析。它仍不等价于 registry provenance/cosign 验证，后续若要更强供应链保证，应引入 digest/release metadata 或签名校验。
- 本地开发 Node 版本应切到 `.node-version` 的 `26.4.0`；当前 shell 仍是 `v25.9.0`，但源码/CI/Docker 目标已经固定。
- 已绕过 `/usr/bin/go` 的 Go 1.24 wrapper，直接使用工作区 Go 1.26.4 toolchain 跑通 `govulncheck`；当前剩余 findings 均为上游 no-fixed 结果，需要按暴露面跟踪，而不是误报为工具链失败。
- 连续 replacement smoke 证明：在 helper 已拿到当前目标容器 ID 的前提下，真实 daemon replacement 不会继承 stale `CM_CONTAINER_ID`，第二次 replacement 仍可继续。
- 该测试不夸大为“容器内产品进程自行触发第二次更新”。若后续要证明 replacement 后的 CyberMonitor 容器能自行通过 `/proc/self/mountinfo` / cgroup 解析当前容器 ID 并主动发起 update，应另做 test-only probe 或真实 server/agent update API smoke。
- Go completion audit 应表述为：direct requirements 无稳定升级提示；indirect updates 已识别但不强行升级，因为它们由上游 direct dependencies 和 MVS 共同约束。

## 2026-07-07 / Go dependency follow-up and Docker detached helper daemon smoke

### 审视

- 延续上一轮未闭环项：`go list -m -u all` 仍显示大量间接依赖可升级，Docker-managed update 还缺生产路径 daemon smoke。
- 两个 `gpt-5.5` / `xhigh` subagent 并行复核：
  - Go 依赖侧确认 direct dependencies 当前没有稳定可升项，不建议追 `grpc` dev 版本，也不应把 deprecated transitive 当成本项目直接替换目标。
  - Docker 侧确认现有 daemon tests 只直接调用 `RunDockerRecreateHelper`，缺少 `LaunchSelfContainerUpdate -> daemon detached helper container -> docker-entrypoint.sh -> docker-recreate-helper` 的生产链路验证。
- 本地 Docker daemon 可用，版本为 `29.6.0`，具备执行 opt-in smoke 的条件。
- 当前本地 shell Node 是 `v25.9.0`，低于官方最新 `v26.4.0`；源码侧 Docker Node base 已固定到 `26.4.0`，本地 Node 版本差异仅作为环境风险记录。

### 执行

- 执行 `go get -u ./...` 后再 `go mod tidy`，让 Go resolver 按当前 import graph 收敛依赖，而不是手写 replace 或硬 pin 一批高风险 transitive。
- 新增 `TestDockerLaunchSelfContainerUpdateDetachedHelperDaemonSmoke`：
  - 默认 skip，必须同时设置 `CM_RUN_DOCKER_DAEMON_TEST=1` 和 `CM_RUN_DOCKER_DETACHED_HELPER_TEST=1` 才会运行。
  - 测试临时构建最小 CyberMonitor helper 镜像，保留真实 `docker-entrypoint.sh` 和 `/app/cyber-monitor docker-recreate-helper` 入口。
  - 测试由 Docker daemon 启动 detached helper 容器，helper 通过 socket 替换目标容器，等待新容器运行、旧容器删除、helper `AutoRemove` 完成。
- 修正 smoke 建模：目标容器使用 `alpine:3.20`，helper 容器使用临时 CyberMonitor helper 镜像，避免把 helper image 的 entrypoint 继承给 alpine replacement。
- 清理 `/tmp` 中可再生 Go/Node cache 后恢复 sandbox；未删除源码或工作区变更。

### 验证

- `curl -sS https://go.dev/VERSION?m=text`
  - 官方当前 Go 为 `go1.26.4`。
- `curl -sS https://nodejs.org/dist/index.json`
  - 官方当前 Node latest 为 `v26.4.0`，发布时间 `2026-06-24`。
- `go list -m -u -f '{{if not .Indirect}}...{{end}}' all`
  - direct dependencies 无 `->` upgrade 输出。
- `CM_RUN_DOCKER_DAEMON_TEST=1 CM_RUN_DOCKER_DETACHED_HELPER_TEST=1 go test ./internal/updater -run '^TestDockerLaunchSelfContainerUpdateDetachedHelperDaemonSmoke$' -count=1 -v`
  - 通过，耗时约 83s。
- Docker 资源清理检查
  - `docker ps -a --filter label=cybermonitor.smoke ...` 无输出。
  - `docker images ... | grep '^cybermonitor-helper-smoke:'` 无输出。
- `go test ./internal/updater -count=1`
  - 通过。
- `go test ./internal/metrics ./internal/server/history ./internal/agentrpc ./internal/agent ./internal/server ./internal/updater -count=1`
  - 通过。
- `go test ./...`
  - 通过。
- `go vet ./...`
  - 通过。
- `go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - 通过。
- `npm --prefix internal/server/web/admin run lint`
  - 通过。
- `npm --prefix internal/server/web/admin run build:admin`
  - 通过。
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
  - 60 pass。
- `bash -n scripts/verify-local.sh scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh && sh -n scripts/docker-entrypoint.sh`
  - 通过。
- `git diff --check`
  - 通过。
- Admin 发布版样式守卫
  - 相对 `v0.6.3` 对 admin 页面和共享样式目录 grep `className` / `style` / Kumo 无输出。

### 提升

- Go direct dependencies 当前已无稳定升级提示；剩余 indirect upgrades 应按簇推进，不要一次性硬升：
  - 低风险 leaf/patch 簇。
  - gRPC/protobuf/`golang.org/x/*` 邻近簇。
  - Prometheus/OTel/collector 簇。
  - Kubernetes/OpenAPI/cloud provider 大簇。
- Docker-managed update 已补 detached helper 生产路径 smoke；后续可再补连续两次 replacement daemon smoke，验证旧 `CM_CONTAINER_ID` 过滤后第二次更新仍定位到当前容器。
- 本地开发环境应升级 Node 到 `26.4.0`，否则前端验证虽然通过，但和 Docker/release Node 版本不完全一致。

## 2026-07-07 / Toolchain refresh and second semantic hardening pass

### 审视

- 目标继续保持完整：代码简洁直接、依赖/toolchain 尽量跟进最新、以产品代码语义为主，不把范围缩成样式恢复。
- 官方 Go 当前版本复核为 `go1.26.4`；当前 `go.mod` 和 Docker Go base 已一致。
- 官方 Node 发布索引显示最新为 `v26.4.0`，本地 Docker Node base 仍停在 `26.3.0`。
- GitHub Action tag 抽检显示 `actions/checkout`、`actions/setup-go`、`actions/cache`、Docker build/login/setup action 已有新版本。
- 两个 `gpt-5.5` / `xhigh` subagent 分别审查 Go 执行面和 admin/public/scripts，合计提出 6 个可证实语义问题。

### 执行

- 将 Docker 构建 Node base 从 `26.3.0` 提升到 `26.4.0`，同步 workflow 静态测试期望；README Go badge 从 `1.26.2` 同步到 `1.26.4`。
- 同步 GitHub Action tag：`actions/checkout@v7.0.0`、`actions/setup-go@v6.5.0`、`actions/cache@v6.1.0`、`docker/setup-qemu-action@v4.2.0`、`docker/setup-buildx-action@v4.2.0`、`docker/login-action@v4.4.0`、`docker/build-push-action@v7.3.0`。
- `BasicSettings` 保存成功后统一用 canonical `SettingsView` 回填 draft，清空 `adminPass`，并用提交前密码值决定 toast，避免敏感输入残留和重复提交。
- `one-click.sh` 的管理员密码 fallback 改为有限 `/dev/urandom` 读取，避免 `pipefail` 下 `tr | head` 的 SIGPIPE 失败。
- `one-click.sh` 写入含 secret 的 `server.conf` 时使用 `0600` 权限；首次安装主控初始化完成后清理 `CM_ADMIN_PASS` 并立即 restart，清理或重启失败进入安装失败回滚路径。
- Agent config capability 由 `agentCapabilitiesForConfig` 统一生成，只有 `!DisableUpdate && HTTPS control plane` 时才在 HTTP/gRPC config request 中声明 `remote-update`。
- Docker replacement env 过滤 `CM_CONTAINER_ID`，避免新容器继承旧容器 ID 后下一次 Docker-managed update inspect 已删除容器。
- Feishu webhook 发送改用受控 HTTP client：禁用代理，发送前解析目标域名并拒绝解析到私网/loopback/link-local/multicast/unspecified IP，redirect 后重新校验 URL。

### 验证

- `curl -sS https://go.dev/VERSION?m=text`
  - `go1.26.4`。
- `curl -sS https://nodejs.org/dist/index.json`
  - 最新 Node 为 `v26.4.0`。
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
  - `{}`。
- `git ls-remote --tags --refs` 抽检官方 Action 仓库
  - 已同步到当前最新 tag：checkout `v7.0.0`、setup-go `v6.5.0`、setup-node `v6.4.0`、cache `v6.1.0`、upload-artifact `v7.0.1`、download-artifact `v8.0.1`、Docker actions `v4.2.0` / `v4.4.0` / `v7.3.0`。
- `node --test internal/server/web/admin-frontend-contract.test.mjs scripts/one-click.test.mjs`
  - 24 pass。
- `go test ./internal/agent ./internal/updater ./internal/server -run 'Test(AgentCapabilitiesForConfigOnlyAdvertisesRemoteUpdateWhenSafe|FetchRemoteConfigSendsConfiguredCapabilities|FetchRemoteConfigPreservesUpdateID|BuildReplacementSpecDropsStaleContainerIdentityEnv|WebhookRejectsDNSResolvedPrivateHosts|WebhookAllowsPublicResolvedHostAndDialsResolvedIP|WebhookRedirectsRevalidateCallbackURL|WebhookRejectsPrivateCallbackHosts)' -count=1`
  - 通过。
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
  - 60 pass。
- `bash -n scripts/verify-local.sh scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh`
  - 通过。
- `sh -n scripts/docker-entrypoint.sh`
  - 通过。
- `npm --prefix internal/server/web/admin run lint`
  - 通过。
- `npm --prefix internal/server/web/admin run build:admin`
  - 通过。
- `go vet ./...`
  - 通过。
- `go test ./...`
  - 通过。
- `go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - 通过。
- `git diff --check`
  - 通过。
- Admin 发布版样式守卫
  - 页面 `className` / `style` / Kumo grep 无输出，共享样式 token 和组件目录相对 `v0.6.3` 无 diff。

### 提升

- `go list -m -u all` 仍显示大量 indirect dependency 可升级；下一轮如果继续推进“全部组件最新”，应单独做 Go transitive dependency 批处理和回归验证，不要和本轮 semantic/security 修复混在一个变更里。
- Docker-managed update 仍建议补一次 opt-in Docker daemon 连续更新 smoke，验证过滤 `CM_CONTAINER_ID` 后两次 replacement 都能定位当前容器。
- Webhook SSRF 当前按默认安全策略拒绝 DNS 私网解析；如果产品未来需要内网 webhook，应增加显式 opt-in 配置，而不是绕过默认保护。

## 2026-07-07 / Admin release-style restore guard and semantic fix closeout

### 审视

- 用户要求关闭 demo，并把管理后台样式还原为 GitHub 已发布版本。
- GitHub latest release 复核为 `v0.6.3`，`target_commitish` 为 `475fe42cdd53ddf73364fa29c4d1c81e2af2fc06`，发布时间 `2026-06-01T08:52:24Z`。
- 宿主监听里没有 `CyberMonitor`、`cmd/server`、`vite` 或本仓库 admin demo 进程；`0.0.0.0:8010` / `0.0.0.0:9999` 是历史 Python 静态服务，不属于本仓库 demo，未误杀。
- 发布版样式恢复的关键风险是把行为修复和 UI 重构混在一起；本轮用 `v0.6.3` 做后台 `className` / `style` / Kumo 结构守卫。

### 执行

- `ServerManagement` 接入全局 unsaved-change guard，但复用发布版原有 footer 按钮位；dirty 时原“取消”按钮显示为“放弃修改”，不新增按钮样式结构。
- 后端 `normalizeAdminPath` 对齐前端 base path 规则：拒绝 scheme、`//`、多轮解码后的 dot segment、冒号、反斜杠、query/hash、控制字符和保留前缀。
- `ImportConfig` 对 `GroupTree` 按全量导入处理，允许导入空分组树清空旧持久化分组。
- Agent 注册收到服务端 issued token 后，即使 token file 持久化失败，也先更新内存 token，避免继续用 bootstrap token 重试。
- public-only 远程网络测试补拦 `64:ff9b::/96` NAT64 well-known prefix。
- one-click 首次安装主控时生成明确 bootstrap 密码，打印后从 `server.conf` 清理 `CM_ADMIN_PASS`，避免把 bcrypt hash 当初始密码输出，也避免明文长期留在配置文件。

### 验证

- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
  - 58 pass。
- `bash -n scripts/verify-local.sh scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh`
  - 通过。
- `sh -n scripts/docker-entrypoint.sh`
  - 通过。
- `npm --prefix internal/server/web/admin run lint`
  - 通过。
- `npm --prefix internal/server/web/admin run build:admin`
  - 通过。
- `go vet ./...`
  - 通过。
- `go test ./...`
  - 通过。
- `go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - 通过。
- `git diff --check`
  - 通过。
- `git diff v0.6.3 -- internal/server/web/admin/src/App.tsx internal/server/web/admin/src/pages/BasicSettings.tsx internal/server/web/admin/src/pages/ProbeSettings.tsx internal/server/web/admin/src/pages/NotificationAlert.tsx internal/server/web/admin/src/pages/AIProvider.tsx internal/server/web/admin/src/pages/GroupManagement.tsx internal/server/web/admin/src/pages/ServerManagement.tsx | grep -n "^[+-].*\\(className\\|style=\\|Kumo\\|admin-kumo\\|@kumo\\)" || true`
  - 无输出，确认后台样式结构相对发布版没有新增差异。
- `git diff v0.6.3 -- internal/server/web/admin/lib/admin-ui.ts internal/server/web/admin/src/index.css internal/server/web/admin/src/App.css internal/server/web/admin/components internal/server/web/admin/src/components`
  - 无输出，确认共享样式 token 和组件目录保持发布版状态。

### 提升

- 后续继续优化管理后台时，优先保持 `v0.6.3` 发布版视觉结构，行为修复通过 contract test 锁住，不再混入 Kumo 路线的视觉改造。
- 如果重新推进 Kumo 化，应作为独立分支或独立阶段处理，并补真实浏览器截图回归，而不是在当前发布版样式恢复线上继续叠加。

## 2026-07-06 / Agent update capability gate and admin behavior contract refresh

### 审视

- Agent remote update 之前只在 admin GET/POST 阶段按最后一次 stats 推断支持性，config 下发阶段没有校验本次请求是否声明 `remote-update` capability。
- 已排队的 pending update 可能被旧 Agent、降级 Agent 或未声明能力的 config client 拉到，协议边界不够明确。
- NodeView 中旧的 `AgentUpdateMessage` 可能遮住当前“不安全 HTTP 控制面”这类能力/安全原因。
- 恢复 GitHub 发布版后台样式后，admin 行为契约仍需补齐：反代 `base_path`、删除节点 partial success、WebSocket snapshot public settings、节点编辑 unsaved guard。

### 执行

- `metrics.NodeStats` 增加 `agent_update_insecure` 和 `agent_remote_update`，Agent 采样时按 `DisableUpdate` 与 HTTPS control plane 显式上报远程更新能力。
- Server 的 agent update 支持判断改为显式能力 gate：禁用更新、不安全控制面、未上报远程更新能力、Windows、Docker socket 缺失分别给出明确原因。
- HTTP config 读取 `X-CM-AGENT-CAPABILITIES`，gRPC `ConfigRequest` 增加 `Capabilities`；`DeliverAgentConfig(nodeID, remoteUpdateCapable)` 只有在本次请求声明 `remote-update` 且节点 stats 支持时才下发 update，并且未下发时不刷新 lease。
- `resolveAgentUpdateView` 在 unsupported 时优先展示当前 unsupported reason，避免旧任务消息遮住当前安全/能力原因。
- Admin API 增加 `normalizeBasePath`、`apiPath`、`adminSocketURL`、`adminAppPath`，fetch、login/logout、session、public snapshot、WebSocket 和 admin path rewrite 统一走 boot `base_path`。
- 删除节点前端契约补齐 `history_error`，partial success 只显示 warning，不再叠加 success toast。
- WebSocket snapshot 只合并 public settings，不覆盖 settings form；节点编辑页接入全局 unsaved-change guard。
- 移除前端 `SettingsView` 中已废弃的 `alert_all` / `alert_nodes` legacy 字段声明。

### 验证

- `go test ./internal/server ./internal/agent ./internal/agentrpc -run 'TestAgentUpdate|TestMaybeApplyRemoteUpdate|TestAnnotateAgentUpdateCapability|TestSystemUpdate|Test.*Settings' -count=1`
  - 通过。
- `node --test internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs`
  - 22 pass。
- `npm --prefix internal/server/web/admin run lint`
  - 通过。
- `go test ./internal/server ./internal/agent ./internal/agentrpc -count=1`
  - 通过。
- `npm --prefix internal/server/web/admin run build:admin`
  - 通过，Vite `8.0.8` 发布版依赖产物生成成功。
- `go test ./...`
  - 通过。
- `git diff --check`
  - 通过。

### 提升

- 当前 admin 保持发布版视觉体系，后续如果再次推进 Kumo 化，应作为单独 UI 路线处理，不和发布版行为契约修复混在一起。
- 下一阶段可继续收敛剩余 updater 版本比较、system update cancellation cache、public icon URL allowlist 等边界问题，再做一次全局 race/vet 验证。

## 2026-07-06 / System update refresh lock and message isolation

### 审视

- `systemUpdateManager.View` / `CheckLatest` 在状态锁内执行远程 release check，慢 GitHub 请求会阻塞 `Start` 和状态读取。
- `refreshLocked` 失败时会直接写 `message`，更新进行中的 UI 可能显示 release check 错误，而不是“正在下载/正在拉取”的更新进度。
- `POST /api/v1/admin/system/update` 之前先远程 `CheckLatest`，再调用 `Start`，已有更新任务运行时重复 POST 仍会先等待远程检查。
- refresh 失败原先会更新 `lastCheckedAt`，失败会被当成一次成功检查窗口缓存。

### 执行

- 将 release refresh 拆成状态锁外的 in-flight gate：并发 refresh 复用同一次 `CheckLatest` 结果，状态锁只负责判断、提交和快照。
- 增加 `lastAttemptAt` 与 `lastCheckError`，失败只记录尝试时间和错误，不写成功检查时间。
- `snapshotLocked` 在 updating 时优先展示更新进度，只有非 updating 且无 update message 时才展示 refresh error。
- 增加 `ReserveStart` / reservation start 流程，POST 更新先做本地占位；重复启动无需等待远程 release check 即可返回 in-progress。
- 补充 manager-level 测试覆盖慢 refresh 不阻塞 Start、refresh error 不覆盖 updating message、失败不写 `lastCheckedAt`、并发 refresh 合并、start reservation 快速拒绝。
- 更新静态测试，锁住 Docker-managed update 仍通过 `reservation.Start` 后才启动 detached helper，并锁住 POST 先 reserve 再 release check。

### 验证

- `go test ./internal/server -run 'TestSystemUpdateManager|TestSystemUpdateRefresh' -count=1`
  - 通过。
- `go test ./internal/server -run 'TestSystemUpdate|TestDockerManagedSystemUpdate|TestWebSocketUsesBalancedPublicAndAdminVariants' -count=1`
  - 通过。
- `go test -race ./internal/server -run 'TestSystemUpdateManager|TestSystemUpdateRefresh' -count=1`
  - 通过。
- `go test ./internal/server -count=1`
  - 通过。
- `go vet ./...`
  - 通过。
- `go test ./...`
  - 通过。
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/public-assets.test.mjs internal/server/update_assets.test.mjs .github/workflows/build-release.test.mjs`
  - 35 pass。
- `npm --prefix internal/server/web/admin audit --json --cache /SourceCode/CyberMonitor/.cache/npm`
  - 0 vulnerabilities。
- `npm --prefix internal/server/web/admin outdated --json --cache /SourceCode/CyberMonitor/.cache/npm`
  - `{}`。
- `scripts/verify-local.sh`
  - 通过。
- `git diff --check`
  - 通过。

### 提升

- 后续进入整体验收前，还需要继续收敛 dirty worktree 中跨 server / agent / updater / public UI 的大 diff，并决定旧 admin Kumo/i18n 测试是重写为发布版合同还是等待下一轮 Kumo 化。
- `systemUpdateManager` 现在已经解决 release refresh 的主要锁竞争和 message 污染问题，后续只需在 route 层增加更高阶的端到端 POST 竞态测试，而不是再扩大状态机。

## 2026-07-06 / Contract and agent runtime correctness pass

### 审视

- 发布版 admin 样式恢复后，`verify-local.sh` 仍引用 Kumo/i18n/admin contract 旧测试，导致统一验证入口和当前源码状态不一致。
- Admin 前端没有消费 `cm-admin-boot` 的 `base_path`，子路径部署下 API 与 WebSocket 会打到根路径。
- 删除节点接口会返回 `history_error`，但前端仍按完整成功提示，掩盖历史数据清理失败。
- Agent stats gRPC fallback 只看 `lastMode=http`，backoff 过期后高频 stats 上报可能长期停在 HTTP。
- 网络测试缓存 key 没包含 `PublicOnly` 与 `IntervalSec`，远程探测策略变化可能复用旧结果。
- `updateNodeStats` 在 read gate 下调用要求 mutation gate 的离线恢复收口逻辑，存在并发写 offline event 的风险。

### 执行

- 收敛 `scripts/verify-local.sh` 的 Node 测试入口，移除已撤回的 Kumo/i18n 断言，保留并恢复有效的 admin API/delete contract 测试。
- 在 admin API 层新增 `normalizeBasePath`、`apiPath`、`adminSocketURL`、`adminAppPath`，所有 fetch 与 WebSocket 统一走 boot base path。
- WebSocket snapshot 只合并公开设置到 `publicSettings`，不覆盖 settings 表单状态。
- `NodeDeleteResponse` 增加 `history_error`，删除节点 partial success 仅显示 warning，不再二次 success。
- Agent stats HTTP 快路径改为只在 gRPC backoff 窗口内生效，backoff 过期后重新尝试 gRPC。
- `testKey` / `networkTestConfigSignature` 纳入 `PublicOnly` 与 `IntervalSec`，策略变化会清理旧缓存。
- `updateNodeStats` 返回 `offlineRecoveryCandidate`，调用方释放 read gate 后再通过 `completeOfflineRecovery` 获取 mutation gate 收口。
- 移除 admin 直连冗余 devDependencies：`autoprefixer`、`postcss`、`tsx`。
- 升级 admin 前端依赖到 npm 当前 latest，`vite` 从 `8.0.8` 升到 `8.1.3`，清除 npm audit 中的 high severity advisory。

### 验证

- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
  - 35 pass。
- `npm --prefix internal/server/web/admin ci --cache /SourceCode/CyberMonitor/.cache/npm`
  - 通过，`found 0 vulnerabilities`。
- `npm --prefix internal/server/web/admin run lint`
  - 通过。
- `npm --prefix internal/server/web/admin run build:admin`
  - 通过，Vite `8.1.3` 产物生成成功。
- `npm --prefix internal/server/web/admin audit --json --cache /SourceCode/CyberMonitor/.cache/npm`
  - 0 vulnerabilities。
- `npm --prefix internal/server/web/admin outdated --json --cache /SourceCode/CyberMonitor/.cache/npm`
  - `{}`。
- `go vet ./...`
  - 通过。
- `go test ./...`
  - 通过。
- `go test -race ./internal/server -run 'Test.*Offline|TestAgentUpdateDeliveredTaskReconcilesSuccessFromStats|TestServerServesStaticAssetsAndAdminBoot|TestAdminBootPayloadHonorsForwardedPrefix' -count=1`
  - 通过。
- `go test -race ./internal/agent -run 'TestReportStatsHTTPFallbackExpiresAfterGRPCBackoff|TestNetworkTestCacheInvalidatesWhenPublicOnlyChanges|TestNetworkTestConfigSignatureIncludesInterval|TestRuntimeConfigMarksRemoteTestsPublicOnlyByDefault' -count=1`
  - 通过。
- `scripts/verify-local.sh`
  - 通过。
- `git diff --check`
  - 通过。

### 提升

- 下一阶段优先处理 `system_update.go` 的 refresh 锁拆分：远程 release check 不应持有状态锁，也不应在更新中覆盖 update message。
- Admin 仍有 `admin-i18n.test.mjs`、`admin-frontend-contract.test.mjs`、`admin-agent-update.test.mjs` 这类旧优化路线测试保留在未跟踪文件里；后续要么按发布版合同重写，要么在重新 Kumo/i18n 化前不要纳入统一验证入口。

## 2026-07-02 / Restore admin style to GitHub release v0.6.3

### 审视

- 用户要求先关闭本地 demo，再把管理后台样式还原为 GitHub 已发布版本。
- GitHub latest release 确认为 `v0.6.3`，其 `target_commitish` 为 `475fe42cdd53ddf73364fa29c4d1c81e2af2fc06`。
- 当前本地 `HEAD` 同为 `475fe42cdd53ddf73364fa29c4d1c81e2af2fc06`，因此发布版后台样式源码可直接用 `HEAD` 作为还原源。

### 执行

- 关闭仍在运行的 `0.0.0.0:25213` demo，并验证端口释放。
- 用 `git archive HEAD internal/server/web/admin` 导出发布版后台前端源码，再解包覆盖 `internal/server/web/admin`。
- 恢复发布版本地 `@/components/ui/*` wrapper 组件和对应页面样式，移除已跟踪 admin 目录中的 Kumo 重构差异。
- 按发布版 `package-lock.json` 重新执行 admin 依赖安装，修复 `class-variance-authority` 等发布版依赖缺失的问题。

### 验证

- `ss -ltnp`
  - `*:25213` 已不再监听。
- `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:25213/admin/`
  - 返回 `000`，确认 demo 已关闭。
- `git diff --name-status -- internal/server/web/admin`
  - 无输出，说明已跟踪 admin 前端源码已回到发布版状态。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite production build 通过。
- `node /tmp/style-restore-check.mjs`
  - 桌面 1440px 与移动端 390px 节点管理页面真实渲染通过。
  - `horizontalOverflow: 0`，无 framework overlay，无 Kumo runtime class，存在发布版 rounded card / shadow / border 样式标记。
- `/tmp/style-restore-server-desktop.png`、`/tmp/style-restore-server-mobile.png`
  - 目检通过，已恢复发布版左侧大圆角侧栏、蓝色 active nav、卡片阴影和淡背景视觉。

### 提升

- 后续若继续迭代后台，应先明确方向：继续基于发布版样式微调，还是重新推进 Kumo 化；两条路线不应混合推进。

## 2026-06-26 / Server install guide compact polish

### 审视

- `ServerManagement` 的 Agent 快速接入卡仍有局部硬编码 `space-y-4 p-5`、`grid gap-4` 和平台按钮 `min-w-[148px] px-4`。
- 安装命令按钮把 `cm-hover-border` 与 code block 样式写在页面内，和前面已经收敛到 `admin-ui.ts` 的 Kumo shared token 方向不一致。
- 服务器管理列表区域也复用了同一段硬编码 outer body spacing，后续继续打磨节点卡时容易出现卡片节奏不一致。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminServerSectionBodyClass`，统一 ServerManagement 顶层卡片 body 的响应式 padding 和 spacing。
  - 新增 `adminServerInstallStackClass`、`adminServerInstallPlatformGroupClass`、`adminServerInstallPlatformButtonClass`，让平台切换按钮在移动端稳定双列同排，桌面端保持 148px 最小宽度。
  - 新增 `adminServerInstallCommandStackClass`、`adminServerInstallCommandButtonClass`，把安装命令块的 Kumo code panel、hover border、focus ring 收敛为共享 token。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - Agent 快速接入卡切到 `adminServerInstall*` token。
  - 服务器管理列表外层 body 切到 `adminServerSectionBodyClass`。
  - 移除页面内对 `adminCodeBlockPanelClass` 的直接组合，降低页面级样式散落。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 Server install guide compact layout 回归。
  - 调整 hover border contract，允许 ServerManagement 通过 shared token 使用 `cm-hover-border`，而不是要求页面源码内联该 class。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 96 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite production build 通过。
- `node /tmp/kumo-server-check.mjs`
  - 桌面 1440px 与移动端 390px 节点管理真实渲染通过，`horizontalOverflow: 0`。
  - 桌面 Linux/macOS 与 Windows 按钮同排，命令块宽度 1046px 且在 viewport 内。
  - 移动端 Linux/macOS 与 Windows 按钮同排，命令块宽度 316px 且在 viewport 内。
  - 页面无 framework overlay，无 console/runtime error。
- `/tmp/kumo-server-install-desktop.png`、`/tmp/kumo-server-install-mobile.png`
  - 目检通过，Agent 快速接入卡在桌面和移动端都保持 Kumo 风格的紧凑卡片节奏。

### 提升

- 下一轮继续检查 `ServerManagement` 的节点卡 action rail 和编辑弹窗内部 probe/lifecycle 区域，重点看长文本、标签组和移动端控件是否还有密度跳变。

## 2026-06-26 / Basic settings compact action polish

### 审视

- `BasicSettings` 的凭据双列区域仍使用硬编码 `grid gap-4 md:grid-cols-2`，密码字段带 hint 后会把同排输入框拉出 14px 的纵向错位。
- 服务端更新版本卡片和 action row 仍有旧 spacing，移动端更新操作只能纵向堆叠，视觉密度和已打磨页面不一致。
- 配置备份的导出/导入按钮仍纵向整行铺满，桌面和移动端都显得过重。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminBasicSettingsFieldGridClass`，使用 `items-start + gap-3` 统一两列字段/卡片网格，并修复 hint 导致的同排输入错位。
  - 新增 `adminBasicSettingsActionGroupClass`，让更新操作在移动端双列、桌面端自然 inline。
  - 新增 `adminBasicSettingsBackupActionGridClass`，让导出/导入在移动端双列，桌面端限制到 `sm:max-w-md`。
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 后台账号/新密码、服务端版本卡片切换到共享 compact grid。
  - 服务端更新按钮从旧 flex-stack 切到 compact action group，发布说明链接在移动端保持整行。
  - 配置导出/导入按钮切到两列紧凑按钮组。
- `internal/server/web/admin-kumo.test.mjs`
  - 更新 BasicSettings 回归，锁定旧 `grid gap-4 md:grid-cols-2` 和旧 `flex flex-col items-stretch` 不回流。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 95 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite production build 通过。
- `node /tmp/kumo-basic-check.mjs`
  - 桌面 1440px 与移动端 390px 基础设置真实渲染通过，`horizontalOverflow: 0`。
  - 桌面后台账号/新密码输入框同排且 y 坐标一致；当前版本/最新版本同排；检查更新/立即更新同排；导出/导入同排且按钮宽度不超过 240px。
  - 移动端凭据字段自然堆叠；版本卡片自然堆叠；检查更新/立即更新双列同排；导出/导入双列同排。
- `/tmp/kumo-basic-security-desktop.png`、`/tmp/kumo-basic-backup-desktop.png`、`/tmp/kumo-basic-security-mobile.png`、`/tmp/kumo-basic-backup-mobile.png`
  - 目检通过，基础设置的安全和备份更新区域保持更紧凑的 Kumo 风格。

### 提升

- 下一轮继续检查 `ServerManagement` 的列表/详情长页面，重点看节点卡 action rail、编辑弹窗内多组 section 在移动端是否还有密度跳变。

## 2026-06-26 / AI provider accordion density polish

### 审视

- `AIProvider` 的 provider accordion 仍沿用旧的 `adminFormSectionBodyClass + adminInsetCardClass`，折叠项比当前 Kumo compact surface 更厚。
- provider panel 内部继续使用 `grid gap-4 md:grid-cols-2`、独立 `KumoSeparator` 和 `space-y-4 pb-4`，字段区与 action row 密度跳变明显。
- 移动端 action 区仍靠 `flex-wrap` 自然换行，新增兼容服务商后的删除按钮没有稳定整行铺满语义。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminAIProviderBodyClass`、`adminAIProviderAccordionRootClass`、`adminAIProviderItemClass`、`adminAIProviderTriggerClass`、`adminAIProviderPanelInnerClass`。
  - 新增 `adminAIProviderFieldGridClass`、`adminAIProviderActionRowClass`、`adminAIProviderActionGroupClass`，统一 provider 字段和 action 行的响应式节奏。
- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - provider accordion 改用 AI provider 专用 Kumo rhythm token。
  - 移除 provider panel 内的独立 separator，改由 action row 的 top border 承接分区。
  - action buttons 桌面端右对齐同排；移动端两枚普通按钮同排，删除按钮整行铺满。
- `internal/server/web/admin-kumo.test.mjs`
  - 更新 AI provider accordion 回归，锁定 Kumo primitive、compact token、无旧 separator、无旧 `adminInsetCardClass` 和无旧 `gap-4` 回流。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 95 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite production build 通过。
- `node /tmp/kumo-ai-check.mjs`
  - 桌面 1440px 与移动端 390px AI provider 真实渲染通过，`horizontalOverflow: 0`。
  - 桌面显示名称/API Key 同排，Base URL/模型同排，获取模型/测试连接/删除三枚按钮同排右对齐。
  - 移动端字段自然堆叠，获取模型/测试连接双列同排，删除按钮 290px 宽并整行铺满。
- `/tmp/kumo-ai-desktop.png`、`/tmp/kumo-ai-mobile.png`
  - 目检通过，provider accordion 观感更接近当前 Kumo 管理后台密度。

### 提升

- 下一轮继续检查 `BasicSettings` 长表单和更新操作区域，重点看 tab panel body、导入导出/系统更新 action stacking 是否还有密度不一致。

## 2026-06-26 / Probe settings density polish

### 审视

- 继续检查 `ProbeSettings` 页面时，探测列表 meta 仍复用 workspace meta card，并用额外 `md:grid-cols-3 xl:grid-cols-3` 覆盖。
- 编辑弹窗 body 继续使用 `adminFormSectionBodyClass + grid gap-4`，名称/类型与 TCP 端口/间隔两组字段的密度比已收敛页面更松。
- 类型切换器仍硬编码 `p-2`，和当前 Kumo compact form rhythm 不一致。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminProbeMetaGridClass`、`adminProbeMetaCardClass`，让 probe list meta 使用专用紧凑三列。
  - 新增 `adminProbeDialogBodyClass`、`adminProbeDialogFieldGridClass`、`adminProbeTypeToggleClass`，统一编辑弹窗字段间距和类型切换器 padding。
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - 探测列表 meta 从 workspace meta class 切到 probe 专用 compact class。
  - 编辑弹窗 body 从 `gap-4` 收紧到 `gap-3`，名称/类型和 TCP 字段共用专用 responsive grid。
  - 类型切换器改用共享 class，移动端保持双按钮稳定宽度。
- `internal/server/web/admin-kumo.test.mjs`
  - 更新 probe dialog spacing 回归，锁定旧 `adminFormSectionBodyClass`、`grid gap-4` 和硬编码 type toggle 不回流。
  - 新增 probe list meta compact card 回归，锁定不再复用 workspace meta card。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 95 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite production build 通过。
- `node /tmp/kumo-probe-check.mjs`
  - 桌面 1440px 与移动端 390px 真实渲染通过，dialog/list `horizontalOverflow: 0`。
  - 桌面编辑弹窗宽 620px，名称/类型同排，TCP 端口/间隔同排。
  - 桌面列表 meta 三列同排，三张 meta card 宽 342px。
  - 移动端编辑弹窗字段自然堆叠，端口/间隔输入宽 324px。
  - 移动端列表 meta 自然堆叠，三张 meta card 宽 308px。
- `/tmp/kumo-probe-dialog-desktop.png`、`/tmp/kumo-probe-list-desktop.png`、`/tmp/kumo-probe-dialog-mobile.png`、`/tmp/kumo-probe-list-mobile.png`
  - 目检通过，探测设置弹窗和列表卡片都保持更紧凑的 Kumo 风格。

### 提升

- 后续继续检查 `AIProvider` 与 `BasicSettings` 的长表单区块，重点看 accordion/panel body、测试按钮行和移动端 action stacking 是否还存在密度跳变。

## 2026-06-26 / Notification alert panel density polish

### 审视

- 继续检查 `NotificationAlert` 页面时，三块告警设置卡仍复用通用 `adminDetailGroupClass`，表单内层节奏和当前 Kumo compact surface 不一致。
- Telegram 双字段区仍使用 `grid gap-4 md:grid-cols-2`，比已收敛的 editor/profile 表单更松散。
- 测试推送 footer 通过 `justify-end` 但缺少 `flex`，桌面右对齐语义不完整，移动端也没有稳定的全宽按钮布局。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminAlertSectionBodyClass`、`adminAlertFieldGridClass`、`adminAlertFieldPanelClass`。
  - 新增 `adminAlertFooterClass`，让告警卡片 footer 使用显式 flex 对齐。
- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - 全局策略、Telegram、飞书三个设置卡改用 alert 专用 compact field panel。
  - Telegram 字段 grid 从 `gap-4` 收紧到 `gap-3`，移动端自然堆叠。
  - 两个测试推送按钮在移动端改为 footer 内全宽，桌面保持右对齐。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 notification alert compact rhythm 回归，锁定旧 `adminDetailGroupClass`、`adminFormSectionBodyClass`、`grid gap-4` 和无效 `panelFooterClass` 不回流。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 94 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite production build 通过。
- `node /tmp/kumo-alert-check.mjs`
  - 桌面 1440px 与移动端 390px 告警页真实渲染通过，`horizontalOverflow: 0`。
  - 桌面 Telegram 两字段同排，footer 右侧间距 24px。
  - 移动端 Telegram 字段堆叠，测试推送按钮 316px 宽并填满 footer 可用宽度。
  - Telegram 测试推送交互会聚焦 `telegram-token` 并显示 token/user id 校验错误。
- `/tmp/kumo-alert-desktop.png`、`/tmp/kumo-alert-mobile.png`、`/tmp/kumo-alert-mobile-telegram.png`
  - 目检通过，告警设置卡在桌面和移动端都保持更紧凑的 Kumo 风格。

### 提升

- 后续继续检查 `ProbeSettings` 的编辑弹窗和 probe meta list，重点看 `grid gap-4`、workspace meta card 与 dialog body 是否还存在密度跳变。

## 2026-06-26 / Server editor profile density polish

### 审视

- 继续检查 `ServerManagement` 节点编辑弹窗时，profile 区块仍使用通用 `adminDetailGroupClass` 和 `grid gap-4`。
- 识别信息与资源标注的布局密度不一致，meta card 继续复用 workspace 样式，移动端纵向高度偏大。
- 首轮真实渲染 QA 发现 390px 移动端下资源区最后一个输入会贴近并被固定 footer 压住。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminEditorProfileSectionClass`、`adminEditorProfileFieldGridClass`、`adminEditorProfileResourceGridClass`。
  - 新增 `adminEditorProfileMetaGridClass`、`adminEditorProfileMetaItemClass`，让 profile meta 信息使用 editor 内部节奏。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - profile identity/resources 两个 subsection 改用专用 compact class。
  - hostname/node id meta 从 workspace meta card 切到 profile meta item。
  - resource fields 在移动端使用双列布局，避免带宽输入被底部 footer 遮挡。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 server editor profile compact layout 回归，锁定旧 `adminDetailGroupClass`、`grid gap-4` 和 `adminWorkspaceMetaCardClass` 不回流。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 94 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite production build 通过。
- `node /tmp/kumo-profile-check.mjs`
  - 桌面 1440px 与移动端 390px 真实弹窗测量通过，profile `horizontalOverflow: 0`。
  - 移动端 profile 高度从 644px 降到 564px，`footerOverlapsProfile: false`。
  - 截图 `/tmp/kumo-profile-mobile.png` 目检通过，带宽输入未被固定 footer 遮挡。

### 提升

- 后续继续检查 `ServerManagement` 编辑弹窗的整体滚动节奏，重点看 Agent update、profile、probe、lifecycle、group 连续区块之间是否还存在层级跳变。

## 2026-06-26 / Server editor lifecycle and group density polish

### 审视

- 继续检查 `ServerManagement` 节点编辑弹窗时，发现 lifecycle 区块仍使用通用 `adminDetailGroupClass` 和 `grid gap-4`。
- 分组选择器宽度偏窄，dropdown option 仍是 flex 布局，长分组名和已选标签缺少统一截断策略。
- 真实渲染 QA 还发现续费方案 Select 显示原始值 `none`，影响 Kumo 化后的观感和本地化一致性。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminEditorLifecycleSectionClass`、`adminEditorLifecycleFieldGridClass`、`adminEditorLifecycleRowClass`、`adminEditorLifecycleStatusClass`。
  - 新增 `adminEditorGroupSelectedListClass`、`adminEditorGroupSelectedLabelClass`，让已选分组标签在移动端可滚动并可截断。
  - 分组 picker 从 `max-w-[26rem]` 扩到 `w-full max-w-[30rem]`，dropdown 内容同步扩到 `min(30rem, calc(100vw - 3rem))`。
  - dropdown option 改为 `grid-cols-[minmax(0,1fr)_auto]`，避免长分组名挤压状态位。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - lifecycle 两个 subsection 改用专用 compact class。
  - 分组 option 和已选 tag label 增加 `min-w-0 truncate`。
  - 续费方案 Select 增加 `renderValue`，显示本地化文案而不是原始 value。
- `internal/server/web/admin-kumo.test.mjs`
  - 更新 group picker 宽度和 dropdown option 布局断言。
  - 新增 lifecycle/group compact layout 回归，锁定 renderValue 与已选标签截断。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 93 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite production build 通过。
- `node /tmp/kumo-lifecycle-group-check.mjs`
  - 桌面 1440px 与移动端 390px 真实弹窗测量通过，lifecycle/group `horizontalOverflow: 0`。
  - 移动端 dropdown 宽 342px，高 369px，无横向溢出，长标签选项存在且被视觉截断。
  - 续费方案渲染文本为 `不自动续费`，不再显示原始 `none`。
- `/tmp/kumo-lifecycle-group-mobile.png` 与 `/tmp/kumo-lifecycle-group-mobile-dropdown.png`
  - 目检通过，底部固定操作区未遮挡 lifecycle/group 控件。

### 提升

- 后续继续检查 `ServerManagement` 编辑弹窗的 profile 区块，重点看识别信息、资源标注和 meta card 在移动端是否还能进一步降低纵向滚动成本。

## 2026-06-26 / Server editor probe list density polish

### 审视

- 继续检查 `ServerManagement` 节点编辑弹窗时，发现探测配置列表仍使用页面内硬编码 `px-4 py-4`、`gap-3` 和 `lg:flex-row`。
- TCP interval 输入固定为 `w-[148px]`，ICMP fixed 标记和 TCP 控件不是同一套行内结构。
- 该区块通常位于 Agent 更新区之后，移动端滚动成本高，适合继续收敛为共享 editor probe class。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminEditorProbeListClass`、`adminEditorProbeItemBaseClass`、`adminEditorProbeControlClass`、`adminEditorProbeIntervalInputClass` 等 probe 专用 class。
  - 列表移动端间距改为 `space-y-2.5`，item 移动端 padding 改为 `px-3 py-3`。
  - TCP interval 与 ICMP fixed chip 使用同一 control row，移动端按 `minmax(0,1fr)_7.75rem` 对齐。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 探测列表项移除页面内硬编码几何尺寸，改用共享 class。
  - interval 输入从 `h-10 w-[148px]` 收敛为移动端 `h-9 w-full`、桌面 `md:w-[132px]`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 server editor probe compact controls 回归，锁定旧大尺寸 class 不回流。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 92 项通过，覆盖 Kumo 结构、前端契约和 i18n 文案。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite production build 通过。
- `node /tmp/kumo-agent-density-check.mjs`
  - 桌面 1440px 与移动端 390px 真实弹窗测量通过，probe 区块 `horizontalOverflow: 0`。
  - 移动端截图 `/tmp/kumo-agent-density-mobile-actions.png` 目检通过，probe 控件未被底部操作区遮挡。

### 提升

- 后续继续检查节点编辑弹窗中 lifecycle 与 group 区块的移动端衔接，减少同一弹窗内的视觉层级跳变。

## 2026-06-26 / Server editor Agent update density polish

### 审视

- 继续打磨 `ServerManagement` 编辑弹窗时，发现 Agent 更新区仍沿用两张 `adminPreviewPanelClass` 大卡。
- 该区块位于弹窗第一屏，移动端会抢占过多空间，并让后续节点档案、探测、生命周期配置下沉。
- 问题不是业务逻辑，而是 Kumo 化后的信息层级偏重；适合用共享 editor-agent class 收敛。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminEditorAgentVersionGridClass`、`adminEditorAgentVersionPanelClass`、`adminEditorAgentStatePanelClass`、`adminEditorAgentActionsClass` 等布局 class。
  - 版本信息从重卡片收敛为紧凑 version strip，移动端高度更低，桌面仍保持双列。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - Agent 更新区移除 `adminPreviewPanelClass` 和 `text-2xl` 版本号。
  - 检查更新、立即更新按钮在移动端改为双列等宽，桌面恢复自然宽度。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 Agent update compact layout 回归，锁定不再回到大 preview card。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 91 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite build 通过，已重新生成 `internal/server/web/dist/admin`。
- CDP/headless Chrome 真实渲染：
  - 临时 server：`go run ./cmd/server --listen 127.0.0.1:25055 --admin-path qa-admin --admin-user admin --admin-pass password --data-dir .tmp/kumo-agent-density-data`。
  - 临时 `state.json` 预置 `agent-density-node` 在线 Linux 节点，带 `agent_version`，覆盖 Agent 更新按钮分支。
  - `desktop` 弹窗尺寸为 `1120x960`，Agent 更新区 `1055x303`，无横向溢出，Runtime/Log problem 为 0。
  - `mobile` 弹窗尺寸为 `358x776`，Agent 更新区 `316x361`，两个操作按钮为 `137x40` 双列，无横向溢出。
  - 移动端滚动到 action row 后 `buttonsVisibleInScroller=true`，按钮未被 footer 遮挡。

### 提升

- 后续继续检查编辑弹窗中 probe 列表项的移动端密度，尤其是 TCP interval 输入和固定 ICMP 标记的对齐。

## 2026-06-26 / Server editor dialog mobile spacing polish

### 审视

- 继续源码巡检时发现 `ServerManagement` 编辑弹窗仍散落 `space-y-6`、`space-y-5 p-6`、`space-y-4 p-6`。
- 这些是 Kumo 化前偏大的 panel body 间距，在移动端节点编辑场景会放大滚动长度。
- 弹窗是节点管理的高频操作面，应优先收敛为共享响应式 spacing，而不是继续在页面内硬编码。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminEditorDialogStackClass`、`adminEditorPanelBodyClass`、`adminEditorPanelBodyCompactClass`。
  - 移动端统一使用 `space-y-4 p-4`，桌面逐步恢复 `sm:p-5 md:p-6`。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 节点编辑弹窗外层 stack 与 5 个 panel body 改用共享 editor spacing class。
- `internal/server/web/admin-kumo.test.mjs`
  - 扩展 Server editor spacing 回归，锁定编辑弹窗不再直接使用旧大间距 class。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 90 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite build 通过，已重新生成 `internal/server/web/dist/admin`。
- CDP/headless Chrome 真实渲染：
  - 临时 server：`go run ./cmd/server --listen 127.0.0.1:25054 --admin-path qa-admin --admin-user admin --admin-pass password --data-dir .tmp/kumo-editor-data`。
  - 临时 `state.json` 预置 `editor-demo-node` profile-only 节点，并真实打开节点编辑弹窗。
  - `mobile` 弹窗尺寸为 `358x776`，无横向溢出，Runtime/Log problem 为 0。
  - `desktop` 弹窗尺寸为 `1120x960`，无横向溢出，scroll region 正常。

### 提升

- 后续继续看节点编辑弹窗内部的内容层级，尤其是 Agent 更新卡片在移动端的两张版本卡是否还能进一步压缩。

## 2026-06-26 / Shared page header mobile action rhythm polish

### 审视

- 全页 desktop/mobile CDP 巡检显示没有横向溢出，console 仅有 Chrome 对 password input 不在 form 内的 verbose 建议。
- 视觉抽查发现 AI 服务商、基础设置这类单 action 页面在 390px 移动端仍强制把“保存更改”压到标题下一行。
- 分组管理、探测设置这类多 action 页面需要保留自然换行，因此应修共享 header rhythm，而不是给单页添加 override。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - `adminPageHeaderClass` 从移动端强制 `flex-col` 改为 `flex-wrap items-center justify-between`。
  - 单 action 页面在空间足够时标题与按钮同行；多 action 页面空间不足时仍自然换到下一行。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 page header 回归，锁定共享 header 不再回到移动端强制单列和 `lg:flex-row` 断点式修补。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 90 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite build 通过，已重新生成 `internal/server/web/dist/admin`。
- CDP/headless Chrome 真实渲染：
  - 临时 server：`go run ./cmd/server --listen 127.0.0.1:25053 --admin-path qa-admin --admin-user admin --admin-pass password --data-dir .tmp/kumo-pass2-data`。
  - `ai-mobile` header 从 `350x101` 收敛到 `350x57`，标题与“保存更改”同行，无横向溢出、无控件裁剪。
  - `settings-mobile` header 从 `350x101` 收敛到 `350x57`，tabs 与首个表单区整体上移。
  - `groups-mobile` / `probes-mobile` header 保持 `350x101`，双 action 自然换行且无横向溢出。

### 提升

- 后续继续按“共享 rhythm 优先”检查列表工具栏、抽屉表单和空态，避免单页局部 class 分叉。

## 2026-06-26 / Notification alert quad stat grid polish

### 审视

- Dashboard mobile 已收敛为 2x2 指标卡后，`NotificationAlert` 仍使用页面内 `grid auto-rows-fr gap-4 md:grid-cols-2 xl:grid-cols-4`。
- 这会让通知告警页移动端 4 张统计卡单列堆叠，把“全局告警策略”继续往下推。
- 问题属于跨页 4 指标统计 pattern，不适合继续保留页面局部 class。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminQuadStatGridClass`，统一 4 指标统计区的移动端 2x2、桌面四列布局。
- `internal/server/web/admin/src/pages/Dashboard.tsx`
  - 删除页面局部 `dashboardStatGridClass`，改用共享 `adminQuadStatGridClass`。
- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - 顶部统计区改用共享 `adminQuadStatGridClass`。
  - 统计卡 header/icon 改用 compact stat 类，移动端隐藏图标，避免小卡挤压文案。
- `internal/server/web/admin-kumo.test.mjs`
  - 扩展共享 stat grid 回归，锁定 Dashboard 与 NotificationAlert 共用同一 4 指标布局。
  - 增加旧单列 grid 的负向断言。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 89 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite build 通过，已重新生成 `internal/server/web/dist/admin`。
- CDP/headless Chrome 真实渲染：
  - 临时 server：`go run ./cmd/server --listen 127.0.0.1:25052 --admin-path qa-admin --admin-user admin --admin-pass password --data-dir .tmp/kumo-alert-data`。
  - `alerts-mobile` 统计区为 `350x195`，无横向溢出、无控件裁剪、无 Runtime/Log error。
  - `alerts-desktop` 统计区为 `1073x94`，保持四列布局。
  - `dashboard-mobile` 继续保持 `350x193` 的 2x2 指标布局。

### 提升

- 后续继续优先查跨页共享 rhythm，尤其是移动端统计区、表单 section 和列表工具栏，避免单页局部修补重新分叉。

## 2026-06-25 / Dashboard mobile stat grid polish

### 审视

- 延续全页 desktop/mobile CDP 巡检，首页、节点管理、分组管理、探测设置、基础设置、通知告警、AI 服务商均无横向溢出和 Runtime/Log error。
- 但 Dashboard mobile 的 4 张顶部统计卡仍按单列堆叠，统计区高度达到 `418px`。
- 这会把“核心配置”推到首屏下半段，和已收敛的 Server/Group 紧凑统计节奏不一致。

### 执行

- `internal/server/web/admin/src/pages/Dashboard.tsx`
  - 新增 `dashboardStatGridClass`，移动端使用 `grid-cols-2 gap-2`，形成 2x2 统计卡。
  - `sm` 以上恢复 `gap-4`，`xl` 继续保持桌面四列指标。
  - 统计卡 header/icon 改用共享 `adminCompactStatCardHeaderClass` 与 `adminCompactStatIconChipClass`，移动端隐藏图标，避免小卡挤压文字。
- `internal/server/web/admin-kumo.test.mjs`
  - 扩展 Dashboard compact mobile rhythm 回归测试，锁定 2x2 统计 grid 和共享 compact stat 类。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 89 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite build 通过，已重新生成 `internal/server/web/dist/admin`。
- CDP/headless Chrome 真实渲染：
  - 临时 server：`go run ./cmd/server --listen 127.0.0.1:25051 --admin-path qa-admin --admin-user admin --admin-pass password --data-dir .tmp/kumo-next-data`。
  - 覆盖 7 个页面的 desktop `1440x1050` 与 mobile `390x844`。
  - Dashboard mobile 统计区高度从 `418px` 收敛到 `193px`。
  - Dashboard mobile 整页高度从 `1242px` 收敛到 `1017px`。
  - 全部巡检页面 `horizontalOverflow=false`，无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Server mobile search and shared stat density polish

### 审视

- 全页 desktop/mobile CDP 巡检覆盖首页、节点管理、分组管理、探测设置、基础设置、通知告警、AI 服务商。
- 自动指标显示无横向溢出、无 Runtime/Log error，但肉眼抽查发现节点管理移动端搜索框图标和 placeholder 重叠。
- 同页统计卡在移动端单列堆叠，和刚收敛后的分组管理统计区密度不一致，会延后“服务器管理”列表进入首屏。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminCompactStatGridClass`、`adminCompactStatCardHeaderClass`、`adminCompactStatIconChipClass`。
  - 将移动端 3 列紧凑统计、移动端隐藏图标、桌面恢复常规 padding 的 pattern 提炼为共享类。
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - 将上一轮页面局部统计类替换为共享 compact stat 类。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 搜索框 class 改为 `${adminInputClass} ... !pl-11`，明确覆盖共享 `px-3`，给左侧 Search 图标留出空间。
  - 节点统计卡改用共享 compact stat 类，移动端保持 3 列紧凑展示。
- `internal/server/web/admin-kumo.test.mjs`
  - 扩展共享 stat 类断言。
  - 新增 ServerManagement 移动端搜索框和统计区几何回归测试。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 89 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite build 通过，已重新生成 `internal/server/web/dist/admin`。
- CDP/headless Chrome 真实渲染：
  - 临时 server：`go run ./cmd/server --listen 127.0.0.1:25050 --admin-path qa-admin --admin-user admin --admin-pass password --data-dir .tmp/kumo-full-data`。
  - 覆盖 7 个页面的 desktop `1440x1050` 与 mobile `390x844`。
  - 所有页面 `horizontalOverflow=false`，无 Vite overlay，无 Runtime/Log error。
  - 节点管理移动端 `pageHeight` 从 2134 收敛到 1917，搜索框图标与 placeholder 不再重叠。
  - AI 页脚本报告的 `1x1` clipped input 是 Kumo/Select 隐藏控件，不是可见 UI 裁切。

## 2026-06-25 / Group mobile stat density polish

### 审视

- 真实渲染巡检显示分组管理桌面布局稳定，但移动端统计区仍按单列堆叠。
- 三张统计卡纵向堆叠会推迟“分组编辑”面板进入首屏，管理后台在手机宽度下显得松散。
- 该问题只影响 GroupManagement 的统计区，不适合改全局 stat card 组件，否则会牵动 Dashboard、NotificationAlert 等页面。

### 执行

- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - 使用 compact stat 类让移动端直接使用 3 列紧凑统计卡，`sm` 以上保持同一三列节奏。
  - 统计卡内边距在移动端收敛到 `p-4`，桌面仍使用原有 `p-5 sm:pb-3` 密度。
  - 统计图标从 `sm` 起显示，避免移动端小卡内文字被图标挤压。
- `internal/server/web/admin-kumo.test.mjs`
  - 扩展分组管理移动端 Kumo spacing 回归测试，锁定紧凑统计 grid、统计 header、移动端隐藏图标和旧 `md:grid-cols-3` 形态不再出现。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 88 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite build 通过，已重新生成 `internal/server/web/dist/admin`。
- CDP/headless Chrome 真实渲染：
  - 临时 server：`go run ./cmd/server --listen 127.0.0.1:25049 --admin-path qa-admin --data-dir .tmp/kumo-wide-data`。
  - 桌面巡检：分组管理、探测设置、通知告警、AI 服务商；移动端巡检：分组管理。
  - 移动端分组管理：`horizontalOverflow=false`，`statGridHeight=93`，`groupEditorTop=360`。
  - 所有巡检页面：无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Basic settings segmented rail polish

### 审视

- 真实渲染巡检显示基础设置页已经完成 Kumo Tabs 替换，但顶部 segmented rail 的激活态层级偏弱。
- 当前 rail 背景与 active indicator 过于接近，截图中“安全控制”不像明确选中态，容易被看成普通文字。
- 这是管理后台高频配置页的主导航，应该比普通表单说明文字更清晰，但不应把所有表单 label 一起加重。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - `adminSettingsTabsRailClass` 改用 `bg-[var(--cm-muted-surface)]`，让 rail track 与 active pill 拉开层级。
  - `adminSettingsTabClass` 显式声明 `text-kumo-subtle aria-selected:text-kumo-default`，保持 inactive/active 文本状态稳定。
  - 新增 `adminSettingsTabIndicatorClass`，只作用于基础设置页 Kumo Tabs 的 active indicator。
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 为 Kumo `Tabs` 传入 `indicatorClassName={adminSettingsTabIndicatorClass}`。
- `internal/server/web/admin/src/index.css`
  - 新增 `.cm-admin-settings-tab-indicator` 明暗模式样式，明确 active pill 背景、边框和轻阴影。
- `internal/server/web/admin-kumo.test.mjs`
  - 扩展基础设置 Tabs 回归测试，锁定 muted rail、selected 文本 token、indicator class 和 CSS 覆盖。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 88 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite build 通过，已重新生成 `internal/server/web/dist/admin`。
- CDP/headless Chrome 真实渲染：
  - 临时 server：`go run ./cmd/server --listen 127.0.0.1:25048 --admin-path qa-admin --data-dir .tmp/kumo-polish-data ...`。
  - 桌面巡检：首页、节点管理、基础设置；移动端巡检：节点管理。
  - 基础设置 active tab indicator computed style：`background=rgb(255, 255, 255)`，`box-shadow=rgba(15, 23, 42, 0.12) 0px 0px 0px 1px, rgba(15, 23, 42, 0.08) 0px 1px 2px 0px`。
  - Selected tab：`安全控制`，computed `color=oklch(0.205 0 0)`。
  - 无横向溢出，无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Admin dialog shell token polish

### 审视

- ServerManagement 编辑弹窗底部仍有一条 Kumo `Separator` 使用 `bg-slate-200 dark:bg-slate-800`。
- 这条线位于滚动内容和 footer 操作区之间，属于 dialog 结构边界，应该和 `adminDialogFooterClass` / `adminDialogHeaderClass` 使用同一套面板边框 token。
- AI Provider 的 separator 已经直接用 Kumo primitive，本轮只收敛 Server 编辑弹窗里的旧 slate 分隔线。
- 真实渲染截图显示 Server 编辑弹窗层级偏轻；进一步采样发现 Kumo Dialog 会通过 inline `--tw-shadow` 覆盖普通 Tailwind shadow class，需要用管理后台专用 shell class 明确覆盖。

### 执行

- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 将编辑弹窗 footer 前的 `KumoSeparator` 从 `bg-slate-200 dark:bg-slate-800` 改为 `bg-[var(--cm-panel-border)]`。
- `internal/server/web/admin/lib/admin-ui.ts`
  - 为共享 `adminDialogContentClass` 增加 `cm-admin-dialog-shell`、`text-kumo-default` 和 `ring-[var(--cm-panel-border)]`，保持 dialog 内容实底和层级 token 一致。
- `internal/server/web/admin/src/index.css`
  - 在 components layer 增加 `.cm-admin-dialog-shell` / `.dark .cm-admin-dialog-shell` 的明确 `box-shadow` 覆盖，避开 Kumo Dialog inline shadow 变量覆盖问题。
- `internal/server/web/admin-kumo.test.mjs`
  - 更新 Kumo Separator 回归测试，锁定 ServerManagement 分隔线使用 `--cm-panel-border`。
  - 防止该页面重新出现旧 `bg-slate-200 dark:bg-slate-800` 分隔线。
  - 扩展 dialog layer 回归测试，锁定 `cm-admin-dialog-shell`、实底、ring 和明暗模式阴影规则。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
  - 88 项通过。
- `npm --prefix internal/server/web/admin run lint`
  - `tsc --noEmit` 通过。
- `npm --prefix internal/server/web/admin run build`
  - Vite build 通过，已重新生成 `internal/server/web/dist/admin`。
- CDP/headless Chrome 真实渲染：
  - 临时 server：`go run ./cmd/server --listen 127.0.0.1:25047 --admin-path qa-admin --data-dir .tmp/kumo-separator-data ...`。
  - 通过浏览器上下文登录并导入 profile-only 节点，打开 Server 编辑弹窗。
  - Dialog computed style：`background=rgb(255, 255, 255)`，`z-index=80`，`box-shadow=rgba(15, 23, 42, 0.12) 0px 0px 0px 1px, rgba(15, 23, 42, 0.42) 0px 24px 70px -28px`。
  - Separator computed style：`className=h-px w-full shrink-0 bg-[var(--cm-panel-border)]`，`height=1px`，`background=rgba(15, 23, 42, 0.12)`。
  - 无横向溢出，无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Admin muted chrome token polish

### 审视

- 高权重文本收敛后，管理后台仍有低权重 chrome 使用旧 `slate` token。
- 残留主要集中在登录页输入图标、Server 搜索/分组选择器图标、分组选择器边框、loading/meta 默认文字和 subtle badge。
- 这些元素不主导页面，但会在 Kumo 控件旁边形成细碎的色阶不一致。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - `adminLoadingCardContentClass`、`adminWorkspaceMetaGridClass` 改用 `text-kumo-subtle`。
  - `adminWorkspaceDropdownHelpClass` 改用 `border-[var(--cm-panel-border)]` 和 `text-kumo-subtle`。
  - `adminWorkspaceSelectedTagLevelClass` 改用 `bg-[var(--cm-control-bg)] text-kumo-subtle`。
  - `adminSubtleOutlineBadgeClass` 改用 `border-[var(--cm-panel-border)] text-kumo-subtle`。
- `internal/server/web/admin/src/pages/Login.tsx`
  - 账号/密码输入框图标改用 `adminMutedTextClass`。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 搜索图标、分组选择器 chevron、禁用状态点、分组 tag count 和下拉列表边框改用 Kumo token。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 muted chrome 回归测试，防止这些低权重 UI 元素回退到旧 `slate` class。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25046 --data-dir .tmp/kumo-muted-data ...`
- CDP/headless Chrome 真实渲染：
  - 登录页账号/密码图标：`className` 均包含 `text-kumo-subtle`，computed `color=oklch(0.556 0 0)`。
  - Server 页搜索图标：`className=... text-kumo-subtle`，computed `color=oklch(0.556 0 0)`。
  - Server 首屏截图已目检：搜索框、统计卡、空态和侧栏布局稳定。
  - 无横向溢出，无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Admin cross-page strong text token polish

### 审视

- 基础设置页收敛后，Probe、Group、AI Provider、Server 页面仍有高权重标题和值文本使用 `text-slate-900 dark:text-slate-50/100`。
- 这些位置包括探测名称、分组编辑标题、AI Provider 名称、节点名称、节点编辑弹窗标题、Agent 版本值和编辑区分组标题。
- `adminStatValueToneClassByTone.neutral` 保留不动，因为它是统计卡 tone map 的显式语义，不属于页面散落 class。

### 执行

- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - 探测名称和弹窗标题改用 `adminStrongTextClass`。
  - 探测目标 meta value 改用 `adminWorkspaceMetaValueClass`，保留 `font-mono`。
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - 分组编辑标题和标签区域标题改用 `adminStrongTextClass`。
  - 分组使用量/标签数量容器改用 `adminMutedTextClass`。
- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - Provider 名称改用 `adminStrongTextClass`。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 快速安装、节点管理、节点卡名称、编辑弹窗标题、编辑区分组标题和 Agent 版本值统一改用 `adminStrongTextClass`。
  - 编辑弹窗描述、探测说明、离线告警状态和分组选择器辅助文本改用 `adminMutedTextClass`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增跨页强文本回归测试，防止高权重页面文本回退到 `text-slate-900 dark:text-slate-50/100`。
  - 同时锁定目标页面不再使用旧的 `text-slate-400/500/600/700 dark:text-slate-*` 文本组合。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25045 --data-dir .tmp/kumo-cross-data ...`
- CDP/headless Chrome 跨页真实渲染：
  - groups：`分组编辑` 标题 `className=flex items-center gap-3 text-kumo-default`。
  - servers：`Agent 快速接入` / `服务器管理` 标题均使用 `text-kumo-default`。
  - probes：新增探测节点弹窗可打开，按钮尺寸稳定，无页面错误。
  - ai：Provider 名称 `OpenAI` 使用 `text-left font-medium text-kumo-default`。
  - 无横向溢出，无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Admin settings strong text token polish

### 审视

- 基础设置页已经大量迁移到 Kumo class，但分区标题和预览/更新版本值仍残留 `text-slate-900 dark:text-slate-*`。
- 这些文本是卡片中的高权重信息，和 `adminPreviewPanelClass`、Kumo `LayerCard` 放在一起时会暴露色阶不一致。
- 目标是先收敛设置页可见强文本，不扩大到其他页面，避免一次性样式改动过大。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminStrongTextClass = "text-kumo-default"`，作为管理后台强文本共享 token。
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 安全、预览、更新分区标题改用 `adminStrongTextClass`。
  - 站点预览、首页预览、当前版本、最新版本等值文本改用 `adminStrongTextClass`。
  - 保留原有字号、字重、间距和图标 tone。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增回归测试，锁定基础设置页强文本使用 Kumo default token。
  - 防止基础设置页回退到 `text-slate-900 dark:text-slate-50/100`。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25044 --data-dir .tmp/kumo-strong-data ...`
- CDP/headless Chrome 真实渲染：
  - 安全页标题 `防爆破策略`：`className=flex items-center gap-2 text-kumo-default`，`color=oklch(0.205 0 0)`。
  - 展示页预览值：`text-xl/text-2xl font-semibold text-kumo-default`，字号分别为 `20px` / `24px`。
  - 备份页版本值：`text-2xl font-semibold text-kumo-default`。
  - 无横向溢出，无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Admin form hint text token polish

### 审视

- Kumo 表单控件周边的辅助说明文字仍混用 `text-slate-500 dark:text-slate-400` 和 `text-[11px] font-medium text-slate-400`。
- 这些 hint 文案分布在登录页、基础设置、探测设置和通知告警，视觉上靠近 Kumo `Input` / `Label`。
- 继续保留页面局部 slate 文本会让表单说明的色阶和行高脱离 Kumo token 体系。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 将 `adminMutedTextClass` 收敛为 `text-kumo-subtle`。
  - 将 `adminFieldHintClass` 收敛为 `text-xs leading-relaxed text-kumo-subtle`。
- `internal/server/web/admin/src/pages/Login.tsx`
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - 表单辅助说明统一使用 `adminFieldHintClass`。
  - 移除目标表单 hint 中的硬编码 slate 文本色和 11px 局部样式。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增回归测试，锁定 shared hint token 和目标页面不再使用旧 slate hint class。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25043 --data-dir .tmp/kumo-hint-data ...`
- CDP/headless Chrome 真实渲染：
  - 基础设置 `#admin-pass-hint`：`className=text-xs leading-relaxed text-kumo-subtle`，`fontSize=12px`，`lineHeight=19.5px`。
  - 通知告警 `#offline-minutes-hint` / `#telegram-user-ids-hint`：均使用 Kumo subtle hint class。
  - 无横向溢出，无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Admin hover border token polish

### 审视

- 管理后台多处共享 Kumo class 已使用 `--cm-panel-border` / `--cm-control-border` 作为基础边框。
- 但 hover 态仍散落 `hover:border-slate-300 dark:hover:border-slate-700`。
- 这会让浅色、暗色、侧栏和内容卡片在 hover 时脱离 CyberMonitor/Kumo token 体系。

### 执行

- `internal/server/web/admin/src/index.css`
  - 新增 `--cm-hover-border` 浅色和暗色 token。
  - 新增 `.cm-hover-border:hover`，显式把 hover 边框收敛到 `--cm-hover-border`。
  - 保留 `!important` 只用于 hover `border-color`，避免 Tailwind utility 生成顺序覆盖交互态。
- `internal/server/web/admin/lib/admin-ui.ts`
  - 将 shared card、outline button、stat card、workspace item、sidebar button、summary row、quick action 等通用 class 接入 `cm-hover-border`。
  - 移除共享 class 中硬编码的 `hover:border-slate-*` / `dark:hover:border-slate-*`。
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 收敛页面内局部 hover border class，统一走 `cm-hover-border`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增回归测试，锁定 hover border token、专用 CSS class 和目标源码中不再使用旧 slate hover border。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25042 --data-dir .tmp/kumo-hover-data ...`
- CDP/headless Chrome 真实渲染：
  - hover probe：`退出登录` sidebar button。
  - hover 前 `borderColor=rgba(15, 23, 42, 0.12)`。
  - hover 后 `borderColor=rgba(15, 23, 42, 0.24)`，匹配 `--cm-hover-border`。
  - `matchesHover=true`，无横向溢出，无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Admin skip link focus polish

### 审视

- 管理后台 shell 的跳转主内容入口仍沿用旧式 `rounded-full` 视觉语义。
- 进一步用 CDP 聚焦检查发现，`sr-only` / `focus:not-sr-only` 组合在生产构建里会出现尺寸或定位覆盖问题。
- 后续尝试的 Tailwind transform utility 也暴露出状态覆盖顺序风险，焦点入口不适合依赖多组 utility 互相抵消。

### 执行

- `internal/server/web/admin/src/App.tsx`
  - skip link 改为 Kumo 风格 `rounded-lg`。
  - 删除 `sr-only` / `focus:not-sr-only` 和 transform focus utility 组合。
  - 使用 `cm-skip-link` 专用 class 管理默认隐藏与焦点可见状态。
- `internal/server/web/admin/src/index.css`
  - 新增 `.cm-skip-link` 和 `.cm-skip-link:focus`，显式控制 `opacity`、`pointer-events` 和 `transform`。
- `internal/server/web/admin-kumo.test.mjs`
  - 将 skip link className 抽取后单独断言。
  - 锁定 `rounded-lg`、`cm-skip-link` 和 CSS focus 规则。
  - 防止回退到 `rounded-full`、`sr-only` / `focus:not-sr-only` 或 Tailwind transform focus utility。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25041 --data-dir .tmp/kumo-skiplink-clean-data ...`
- CDP/headless Chrome 真实渲染：
  - skip link 聚焦态 `borderRadius=8px`，`position=fixed`，`opacity=1`。
  - 聚焦态尺寸 `123x31`，位置 `x=16 y=16`。
  - 无横向溢出，无 Vite overlay，无 Runtime/Log error。

## 2026-06-25 / Admin notification stat border token polish

### 审视

- 通知告警统计卡已使用 Kumo `LayerCard` 和 tone surface。
- 但 `adminOverviewCardClass` 仍带旧式 `border-slate-200/60 dark:border-slate-800/60`。
- 这会让 overview card 同时存在基础边框和 tone surface 边框语义，增加页面间视觉不一致风险。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 将 `adminOverviewCardClass` 收敛为只负责 `overflow-hidden`。
  - 边框颜色统一交给 `adminStatSurfaceClassByTone`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增回归测试，锁定 overview card 不再携带硬编码 slate 边框。
  - 保证通知告警统计卡继续组合 `adminOverviewCardClass`、`adminStatCardClass` 和 tone surface class。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25038 --data-dir .tmp/kumo-notification-border-data ...`
- CDP/headless Chrome 真实渲染：
  - notification alert desktop `1440x1000`：无横向溢出，无 Vite overlay，无 Runtime/Log error。
  - notification alert mobile `390x844`：无横向溢出，无 Vite overlay，无 Runtime/Log error。
  - 统计卡仍保留 tone surface border，overview class 不再叠加旧 slate border。

## 2026-06-25 / Admin login title mobile density polish

### 审视

- 登录页是管理后台的第一入口，迁到 Kumo 后整体结构已经干净。
- 但品牌标题仍固定使用 `text-4xl`，移动端也渲染为 36px。
- 后台登录页不是营销 hero，移动端标题应更接近管理工具的紧凑密度。

### 执行

- `internal/server/web/admin/src/pages/Login.tsx`
  - 登录页品牌标题从固定 `text-4xl` 改为 `text-3xl md:text-4xl`。
  - 桌面端保留 36px 识别度，移动端收敛到 30px。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增回归测试，锁定登录页标题必须使用 responsive Kumo density。
  - 防止再次回到所有 viewport 都使用 hero 级标题。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25037 --data-dir .tmp/kumo-login-final-data ...`
- CDP/headless Chrome 真实渲染：
  - desktop `1440x1000`：登录页 H1 `font-size=36px`，保持桌面识别度。
  - mobile `390x844`：登录页 H1 `font-size=30px`，`line-height=36px`。
  - 两个 viewport 均无横向溢出、无 Vite overlay、无 Runtime/Log error。

## 2026-06-25 / Admin stat value rhythm polish

### 审视

- 多个管理页的统计卡已经迁到 Kumo `LayerCard`，但数值字号仍散落在页面内。
- Dashboard、ServerManagement、NotificationAlert 使用重复的 `text-3xl font-semibold`。
- GroupManagement 仍保留 `text-4xl`，在 Kumo 后的紧凑卡片里显得比其它页更重。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 新增 `adminStatValueClass`，统一普通统计卡数值字号、字重、行高和 tracking。
  - 新增 `adminStatInlineValueClass`，统一带单位统计卡的 inline 排布。
- `internal/server/web/admin/src/pages/Dashboard.tsx`
  - 首页统计卡改用 `adminStatValueClass`。
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - 分组统计卡从页面内 `text-4xl` 收敛到共享 `adminStatValueClass`。
- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - 离线阈值等带单位统计卡改用 `adminStatInlineValueClass`。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 节点统计卡改用 `adminStatValueClass`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增回归测试，锁定统计数值必须使用共享 class。
  - 防止页面内重新出现散落的 `text-4xl` 或 `text-3xl font-semibold`。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25035 --data-dir .tmp/kumo-stat-qa-data ...`
- CDP/headless Chrome 真实渲染：
  - 覆盖 dashboard、settings、servers、groups、alerts、ai。
  - desktop 与 mobile 两种 viewport 均无横向溢出。
  - 无按钮文字裁剪。
  - 无 Vite overlay。
  - 无 Runtime/Log error。

## 2026-06-25 / Admin group picker dialog layering polish

### 审视

- 节点配置编辑弹窗内的分组选择器已经迁到 Kumo `DropdownMenu`，但下拉层级仍有粗糙点。
- 桌面端触发器会被父级布局拉到整行宽度，和实际菜单宽度不一致。
- 菜单 DOM 已存在，但 portal 默认挂到 document body 时会被 Kumo dialog 层级遮住，真实截图中看不到下拉内容。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 增加分组选择器共享 class：shell、trigger、dropdown content、help、list、group、option、selected tag。
  - 统一限制 picker 最大宽度为 `26rem`，移动端用 `calc(100vw - 3rem)` 收敛。
  - dropdown list 限制为 `min(22rem, calc(100vh - 10rem))`，避免菜单撑出 viewport。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 分组选择器改用共享 class，消除散落的 inline Tailwind 字符串。
  - 在 Kumo dialog 内放置本地 portal container。
  - 使用 state-backed callback ref 传给 `DropdownMenu.Content.container`，让菜单层级进入 dialog 局部上下文。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增回归测试，锁定共享 picker 样式、dialog-local portal container 和旧 inline 宽度不可回退。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25033 --data-dir .tmp/kumo-group-qa-final2 ...`
- CDP/headless Chrome 真实渲染：
  - desktop `1440x1000`：trigger width=416，menu width=416，`elementFromPoint` 命中 menu 内元素。
  - mobile `390x844`：bodyWidth=390，scrollWidth=390，menu width=342，`elementFromPoint` 命中 menu 内元素。
  - 两个 viewport 均无横向溢出、无 Vite overlay、无 Runtime/Log error。

## 2026-06-25 / Admin node card identity polish

### 审视

- 节点管理列表卡片仍把 Node ID、主机名、Agent 版本拼成一条 slash 分隔文本。
- 长 Node ID 或 hostname 在移动端会压缩标题区域，也不利于扫描。
- 编辑入口在移动端被 flex stretch 拉满，视觉上像嵌套的大按钮。

### 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - 增加 `adminWorkspaceIdentityRailClass` 和 `adminWorkspaceIdentityChipClass`，复用在节点卡片身份信息上。
  - 调整 `adminWorkspaceActionChipClass`，让编辑 chip 保持自适应宽度。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 将节点卡片顶部的 Node ID、主机名、Agent 版本拆为 3 个可换行 identity chips。
  - chip label 显式使用 `shrink-0 whitespace-nowrap`，避免 `Node ID` 和“主机名”在移动端拆行。
  - 编辑 chip 显式使用 `w-fit self-start`，避免移动端拉满。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增回归测试，锁定节点卡片身份信息使用 compact identity chips。
  - 防止退回 slash 分隔文本。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25027 --data-dir .tmp/kumo-card-qa ...`
- CDP/headless Chrome 真实渲染：
  - desktop `1440x1000`：identity chipCount=3，overflowX=false。
  - mobile viewport：identity chipCount=3，overflowX=false，label computed `white-space=nowrap`。
  - 由于 Go server 嵌入的是启动时的 `web/dist`，admin build 后必须重启临时 server 才能验证最新 chunk。

## 2026-06-25 / Admin Kumo switch polish

### 审视

- 节点编辑弹窗的“离线告警”仍使用自制二段按钮，视觉上比同页 Kumo 表单控件更重。
- 二段按钮在移动端会挤压状态文案，也不符合二元设置应使用 switch/toggle 的交互语义。
- 本地 `@cloudflare/kumo` 已提供 `Switch`，可直接替换，不需要保留额外 wrapper 或兼容分支。

### 执行

- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 引入 `@cloudflare/kumo/components/switch`。
  - 将“离线告警”二段按钮替换为受控 `Switch`。
  - 保留当前状态文案和禁用态。
  - 使用 `aria-checked:bg-kumo-brand` 覆盖 Kumo 默认蓝色，使 checked 状态匹配 CyberMonitor 品牌色。
  - 移动端布局改为纵向排布，避免开关挤压文字。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增回归测试，锁定离线告警必须使用 Kumo `Switch`。
  - 防止回退到 `updateFormField("alertEnabled", true/false)` 的自制二段按钮。

### 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build`
- 临时 server：`go run ./cmd/server --listen 127.0.0.1:25026 --data-dir .tmp/kumo-switch-qa ...`
- CDP/headless Chrome 真实渲染：
  - desktop `1440x1000`：Switch visible=true，`aria-checked=true`，背景色 `rgb(196, 81, 0)`。
  - mobile `390x844`：Switch visible=true，`aria-checked=true`，背景色 `rgb(196, 81, 0)`。
  - 截图保存在 `.tmp/kumo-switch-desktop.png` 和 `.tmp/kumo-switch-mobile.png`，收尾清理前仅用于本轮 QA。

## 2026-06-08

### MAGI 审视 / runtime path smoke

- 前面已经有 Go route tests、Node static tests 和 admin build，但还缺一次真实 server 运行时验证。
- `go run ./cmd/server` 在未设置 `CM_ADMIN_PATH` 时会初始化随机 admin path；直接访问 `/admin/` 404 是预期安全行为，不是资源路径错误。
- Playwright MCP 在当前环境报 `Playwright Extension not found`，需要按既定 fallback 切 headless Chrome CLI。

### MAGI 执行 / runtime path smoke

- 使用临时数据目录 `/tmp/cm-runtime-smoke-data` 启动本地 server，验证：
  - `/api/v1/health` 返回 200。
  - `/` public HTML 使用 `./assets/...` 相对资源。
  - `/config.json` 返回当前 origin 的 API/WS URL。
  - 带 `X-Forwarded-Prefix: /cm` 的 `/config.json` 返回 `/cm` 前缀 API/WS URL。
  - 真实随机 admin path 返回 admin HTML，boot meta 可注入 `base_path`。
  - admin 无尾斜杠路径会 302 到带尾斜杠路径。
  - admin bundle 资源可按真实 admin path 访问。
- 使用 headless Chrome dump DOM 验证 public 页面和 admin login 页面可以加载到实际 DOM。
- smoke server 已停止，25213 端口关闭。

### MAGI 验证 / runtime path smoke

- `go run ./cmd/server` with `CM_LISTEN=127.0.0.1:25213` and `/tmp/cm-runtime-smoke-data`
- `curl -s -i http://127.0.0.1:25213/api/v1/health`
- `curl -s http://127.0.0.1:25213/`
- `curl -s http://127.0.0.1:25213/config.json`
- `curl -s -H 'X-Forwarded-Prefix: /cm' http://127.0.0.1:25213/config.json`
- `curl` against the initialized admin path and admin bundle asset
- `google-chrome --headless=new --no-sandbox --disable-gpu --dump-dom` for public and admin pages

### MAGI 审视 / pending cleanup finalization and canonical data cleanup

- `DeleteNode` 已能在 history cleanup 失败时保留 retry intent，但还缺一个完成态分支：当 node/profile 已不存在、已有 pending delete intent、且 TSDB history 也已不存在时，当前实现会返回 not found 并留下 stale pending intent。
- `cleanup_server_config` 使用 `data_real` 做 install-dir 归属和 mountpoint 判断，但最终删除使用原始 `data_dir`。校验对象和删除对象不一致，会削弱 canonical path 保护。
- 前端/admin/public 路径 sidecar 未发现阻断问题；保留 `/cm` 无尾斜杠反代场景为部署层 canonical URL 约束，不引入额外兼容分支。

### MAGI 执行 / pending cleanup finalization and canonical data cleanup

- `internal/server/server.go`
  - `DeleteNode` 在 history 已不存在但存在既有 pending delete intent 时，清理该 intent 并返回 `deleted=true`。
  - 持久化场景复用同一 snapshot 写入路径，避免 pending history delete 长期残留。
- `internal/server/server_delete_test.go`
  - 新增 stale pending delete intent 回归测试，覆盖内存和 persisted state 都清空。
- `scripts/one-click.sh`
  - `cleanup_server_config` 改为删除已完成 owned/mountpoint 检查的 canonical `data_real`。
- `scripts/one-click.test.mjs`
  - 新增静态回归，锁定 owned check、mountpoint check、最终 `rm -rf` 必须使用同一个 canonical path。

### MAGI 验证 / pending cleanup finalization and canonical data cleanup

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run TestDeleteNodeClearsExistingPendingHistoryCleanupWhenHistoryIsGone -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestDeleteNode(ClearsExistingPendingHistoryCleanupWhenHistoryIsGone|KeepsExistingPendingHistoryCleanupOnHistoryOnlyError|KeepsPendingHistoryCleanupOnHistoryError)' -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(Delete|Clear|Admin|Forwarded|Route|DockerManaged|SystemUpdate)' -count=1`
- `node --test scripts/one-click.test.mjs`
- `scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `scripts/build-local.sh`

### MAGI 审视 / handler partial success and Docker update busy state

- `DeleteNode` 的 history-only retry 场景已确认有回归测试覆盖：既有 `pending_history_deletes` 不会被本次失败误清。
- Store 级 partial-success 已覆盖，但 HTTP handler 层原本缺少直接断言，未来可能把 `200 + history_error` 退回成 503。
- Docker-managed server update 原本只确认 helper container 启动成功；helper 后续失败时父 server 会继续保持 `updating=true`，导致后续更新被 busy state 卡住。
- Docker rollback 的 rename-back 失败路径已确认会继续尝试启动旧容器。

### MAGI 执行 / handler partial success and Docker update busy state

- `internal/server/server.go`
  - 抽出 `handleAdminDeleteNodeRequest` 和 `handleAdminClearNodesRequest`。
  - 保持原路由行为不变，并把 partial history cleanup error 固定为 `200`、`status`、`history_error` payload。
  - Docker-managed update 改为调用 `LaunchSelfContainerUpdateAndWait`，让 helper 早期失败回传到父 server。
  - `systemUpdateManager.Start` 在 docker-managed apply 返回后清理 `updating`，记录完成时间，并允许后续更新重新启动。
- `internal/server/server_routes_test.go`
  - 新增 Delete single node / Clear all nodes handler-level partial-success 测试。
- `internal/server/system_update_test.go`
  - 锁定 docker-managed apply 返回后必须清理 busy state。
- `internal/updater/docker_managed.go`
  - 新增 helper wait 路径，等待 helper `not-running` 并检查非零退出码。
  - 保留 detached helper 启动路径供 agent 自更新继续使用。
- `internal/updater/docker_managed_test.go`
  - 锁定 helper 非零退出码会返回错误。

### MAGI 验证 / handler partial success and Docker update busy state

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAdmin(DeleteNode|ClearNodes)HandlerReturnsHistoryErrorPartialSuccess' -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestSystemUpdateManager' -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run 'Test(LaunchDockerUpdateHelper|RollbackCreatedContainer)' -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run TestDockerManagedSystemUpdateUsesBoundedWaitContext -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server ./internal/updater -count=1`
- `scripts/verify-local.sh`
- `scripts/build-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

### MAGI 审视

- 当前 worktree 起点为 clean；历史记忆只作为线索，实际以本轮 `git status`、代码扫描和测试输出为准。
- 已确认 `DeleteNode` / `ClearNodes` 会清理 `configRefresh`，本轮未发现同等级的节点删除语义缺口。
- 本轮高确定性问题集中在回滚路径：
  - Windows Agent 安装失败回滚只恢复旧 `binPath` 和运行态，没有恢复旧 `StartMode`。
  - Docker-managed recreate helper 在旧容器已 stop、备份 rename 失败时，没有重新启动旧容器。
- 仍待下一轮收敛：
  - Docker-managed update 启动替换容器后缺少 bounded health gate。
  - Docker-managed update 的 Docker 分支仍受二进制 `DownloadURL` gate 影响。
  - 主控卸载的数据目录删除策略还缺少 owned sentinel / mountpoint 保护。

### MAGI 执行

- `scripts/agent.ps1`
  - 新增 `ConvertTo-ScStartMode`，把 `Win32_Service.StartMode` 直接映射到 `sc.exe config start=` 参数。
  - 失败回滚恢复旧服务路径时同步恢复旧启动类型。
  - 对“原服务为 Disabled 但当时 Running”的状态，先临时设为 `demand` 恢复运行态，再在局部 `finally` 中设回 `disabled`。
- `scripts/agent-ps1.test.mjs`
  - 新增 Node 标准库静态回归测试，锁定 Windows Agent rollback 必须恢复旧 `StartMode`。
- `internal/updater/docker_managed.go`
  - 新增最小 rollback client interface 和 `rollbackCreatedContainer`。
  - Docker replacement rollback 现在记录 `oldStopped`。
  - 旧容器 stop 后若 rename 失败，rollback 会删除新容器并重新启动旧容器。
  - 旧容器已 rename 时仍按原顺序恢复名称后启动。
- `internal/updater/docker_managed_test.go`
  - 新增 Go 单元测试覆盖 stopped-before-rename、renamed-back、not-stopped、rename-back-failed 四种 rollback 状态。

### MAGI 提升

- 回滚状态机必须显式记录每个外部副作用是否已经发生。不要只记录“最终 rename 成功”这类晚阶段状态。
- 对安装器/更新器这类脚本和 helper，即使缺少完整集成环境，也应补最小可重复的静态或单元回归检查。
- 下一轮优先级建议：
  1. 为 Docker-managed replacement 增加 health gate，只有新容器 running/healthy 后才删除旧容器。
  2. 拆掉 Docker-managed 分支对二进制 release asset 的冗余依赖。
  3. 给 server uninstall 数据目录增加 owned sentinel 和 mountpoint 保护。

### 验证记录

- `npm ci --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

- `node --test scripts/agent-ps1.test.mjs`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater`
- `bash -n scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh`
- `sh -n scripts/docker-entrypoint.sh`
- `git diff --check`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./...`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go vet ./...`

`pwsh` is not installed in this environment, so PowerShell parser validation was not available.

## 2026-06-08 / Docker health gate

### MAGI 审视

- 上一轮 Docker rollback 已能在 rename 失败时重启旧容器，但替换容器启动后仍会立即提交更新并删除旧容器。
- Dockerfile 已定义 healthcheck，`ContainerStart` 成功不等于服务健康；新容器可能处于 `starting`、`unhealthy`、`exited` 或 `dead`。
- 直接可用的状态来源是 Docker `ContainerInspect` 返回的 `State.Running` 和 `State.Health.Status`，不需要引入额外依赖。

### MAGI 执行

- `internal/updater/docker_managed.go`
  - 新增 bounded readiness gate：默认最多等待 120s，每 2s inspect 一次替换容器。
  - 有 healthcheck 时只接受 `healthy` 且 `State.Running == true`；`starting` 继续等待；`unhealthy` 直接失败并触发现有 rollback。
  - 无 healthcheck 时直接要求 `State.Running == true`。
  - `exited`、`dead` 或 Docker state error 会直接失败，避免删除旧容器。
  - readiness gate 位于新容器 `ContainerStart` 之后、`rollbackReplacement = false` 之前。
  - readiness wait 使用 `context.WithTimeout` 包住每次 `ContainerInspect`，timeout 到期会取消卡住的 Docker inspect 请求。
- `internal/updater/docker_managed_test.go`
  - 增加 readiness 判定测试：healthy、starting、unhealthy、running-without-healthcheck、exited、healthy-but-not-running。
  - 增加 wait helper 测试：从 starting 轮询到 healthy，以及 unhealthy 立即失败。
  - 增加 blocked inspect timeout 测试，防止 helper 在 Docker daemon/socket 卡住时无限等待。

### MAGI 提升

- 对 Docker-managed update，后续提交旧容器删除前必须先证明替换容器至少进入可服务状态。
- health gate 已收敛；下一轮优先级变为：
  1. 拆掉 Docker-managed 分支对二进制 `DownloadURL` 的冗余 gate。
  2. 给 server uninstall 数据目录增加 owned sentinel 和 mountpoint 保护。
  3. 进一步改善 Docker rollback 失败时的可观测性，不只吞掉 rollback API 错误。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -count=1`

## 2026-06-08 / Build-first local verification contract

### MAGI 审视

- `internal/server/server.go` 的 `go:embed web/dist/admin/*` 仍要求 Go 编译前已有生成的 admin assets。
- CI 的 `verify-go` 已通过 `build-admin` cache restore 走 build-first 路径，但本地验证还缺一个明确入口来承接同一契约。
- 继续支持 clean checkout 直接裸跑 `go test ./...` 会形成第二套路径，不符合当前“简洁直接、不要冗余兼容”的要求。

### MAGI 执行

- `scripts/verify-local.sh`
  - 新增本地验证入口：shell syntax、Node regression、admin `npm ci/lint/build:admin`、`go vet ./...`、`go test ./...`。
  - Go 命令前固定先生成 admin dist。
- `scripts/build-local.sh`
  - 改为先调用 `scripts/verify-local.sh`，再只负责本地 server/agent binary 构建。
  - 移除重复的 npm/admin build/Go verify 块。
- `scripts/build-local.test.mjs`
  - 锁定 `verify-local.sh` 必须先 `build:admin` 再 Go verify。
  - 锁定 `build-local.sh` 必须复用 verify 入口且不得重复 `go vet` / `go test`。
- `.github/workflows/build-release.yml`
  - 将新脚本和新测试纳入 build input、shell syntax 和 Node regression 检查。
- `.github/workflows/build-release.test.mjs`
  - 锁定 workflow 会运行 `scripts/build-local.test.mjs`。

### MAGI 提升

- 本仓不追求 bare checkout 裸 Go 编译；唯一支持路径是 Go 验证前先 build 或 restore generated admin assets。
- 下一轮重点转向完整验证矩阵和当前 diff 全局审查。

### 验证记录

- `node --test scripts/build-local.test.mjs`
- `node --test .github/workflows/build-release.test.mjs`
- `bash -n scripts/verify-local.sh scripts/build-local.sh`

## 2026-06-08 / Delete cleanup and static path contract

### MAGI 审视

- 当前树没有旧记忆里的 admin `test:unit` 或 public-tests；真实前端入口是 `lint` 和 `build:admin`。
- split mode 下 admin 前端会请求 `/api/v1/public/snapshot` 读取公开标题/图标，但该 endpoint 原本只挂在 public mux，admin 端口返回 404。
- `DeleteNode` / `ClearNodes` 当前实现是 fail-closed：history cleanup 失败会 rollback pending intent 并阻止业务状态删除；这与 pending history cleanup 和前端 `history_error` warning 契约不一致。
- public 静态页使用 root-only `/assets` 和 `/config.json`；反代子路径下会错误请求站点根路径。
- admin 前端 API/WS 也使用 root-only `/api` 和 `/ws`；需要由服务端 boot payload 注入统一 base path。

### MAGI 执行

- `internal/server/server.go`
  - split mode 下将 `/api/v1/public/snapshot` 同时注册到 admin mux，保证 admin 登录页依赖的公开配置可在 admin 端口读取。
  - `DeleteNode` 在 node/profile 存在且 history cleanup 失败时，保留 `pending_history_deletes`，清理 node/profile/offline session/test history/configRefresh，并返回 typed partial cleanup error。
  - `ClearNodes` 在 history cleanup 失败时，保留 `pending_history_clear`，清理全部业务内存状态和 `configRefresh`，并返回 typed partial cleanup error。
  - admin delete / clear handler 识别 partial cleanup error，返回 `200` 和 `history_error`，同时广播新的 snapshot。
  - `buildDefaultPublicConfig` 支持 `X-Forwarded-Prefix`，生成带前缀的 API base 和 WS URL。
  - `forwardedPrefix` 只接受 path-only prefix，拒绝 query、fragment、scheme、backslash、control char、encoded dot segment，并规范化重复 slash。
  - admin boot payload 注入 `base_path`，来源同样是 `X-Forwarded-Prefix`。
- `internal/server/web/public/index.html`
  - public CSS/JS 改为 `./assets/...` 相对路径。
- `internal/server/web/public/assets/monitor.js`
  - `CONFIG_PATH` 改为 `./config.json`，适配静态托管或反代子路径。
- `internal/server/web/admin/lib/admin-api.ts`
  - 新增 admin base path helper，所有 admin fetch 和 WebSocket 通过 boot payload 的 `base_path` 生成路径。
  - 前端 base path helper 与后端同样拒绝 malformed prefix，避免手工注入或旧 boot payload 污染 API/WS 路径。
- `internal/server/web/admin/lib/admin-types.ts`
  - `NodeDeleteResponse` 增加 `history_error`。
  - `AdminBootPayload` 增加 `base_path`。
- `internal/server/web/admin/src/App.tsx`
  - 删除节点返回 `history_error` 时显示 warning toast，再刷新节点列表。
- `internal/server/server_delete_test.go`
  - 新增单节点删除和批量清空的 partial history cleanup 回归测试。
- `internal/server/server_routes_test.go`
  - 新增 unified admin API、split admin public snapshot、admin/static asset、public relative asset/config、forwarded prefix、admin boot prefix 回归测试。
  - 增加 malformed forwarded prefix 表驱动测试，并为测试 HTTP client 增加 timeout。

### MAGI 提升

- 删除节点属于业务状态变更；history cleanup 失败应作为可重试的二级清理任务保留，而不是让坏 history store 永久阻塞节点删除。
- 前端路径不要零散硬编码 root；同一部署前缀必须从服务端请求上下文进入 boot/config，再由前端统一生成 API/WS 路径。
- 当前仍应保留 build-first 契约：Go embed 依赖 admin dist，裸 `go test` 前需要先构建 admin。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(UnifiedServerServesAdminAPI|SplitAdminServerServesPublicSnapshotForAdminApp|ServerServesStaticAssetsAndAdminBoot|BuildDefaultPublicConfigHonorsForwardedPrefix|AdminBootPayloadHonorsForwardedPrefix|DeleteNodeKeepsPendingHistoryCleanupOnHistoryError|ClearNodesKeepsPendingHistoryCleanupOnHistoryError)' -count=1`
- `npm --prefix internal/server/web/admin run lint`

## 2026-06-08 / Build-first verification and public fallback

### MAGI 审视

- 当前 `verify-go` workflow 已依赖 `build-admin` 并恢复 `admin-web-sync.tar.gz`，实现上符合 Go embed 的 build-first 契约。
- 回归测试未锁住该契约，后续改 workflow 时可能重新把 `verify-go` 变成 clean checkout 裸 Go 验证。
- public `CONFIG_PATH` 已改为相对路径，但 `resolveTargets()` 在 config 缺失时仍 fallback 到 `location.origin` 和 root `/ws`，静态子路径托管会退回根路径语义。

### MAGI 执行

- `.github/workflows/build-release.test.mjs`
  - 增加 `verify-go` 必须依赖 `build-admin` 的静态回归测试。
  - 锁定 `verify-go` 必须 restore `admin-web-sync.tar.gz`、`fail-on-cache-miss: true`，且恢复 admin assets 后才运行 Go verification。
  - 锁定 `build-admin` 必须 package/save generated admin assets 给 Go embed jobs。
- `internal/server/web/public/assets/monitor.js`
  - 抽出 `buildFallbackTarget()`，`resolveTargets()` 的 fallback 改为从 `new URL("./", location.href)` 推导 base。
  - fallback WebSocket 用 `new URL("ws", fallbackBase)` 生成，静态子路径下保持同一前缀。
- `internal/server/web/public-assets.test.mjs`
  - 新增 public fallback target 回归测试，直接执行 `buildFallbackTarget()`，覆盖 `/`、`/dashboard`、`/cm/` 和 http/https。
- `.github/workflows/build-release.yml`
  - 将 `internal/server/web/public-assets.test.mjs` 纳入 build-admin 的 Node 回归测试和输入文件存在性检查。
- `.github/workflows/build-release.test.mjs`
  - 加强 build-first workflow 测试，锁定 admin asset cache save/restore key 一致，以及 package step 必须早于 cache save。

### MAGI 提升

- Go embed 依赖 generated admin assets，应把 build-first 作为 CI contract，而不是隐式依赖当前工作区已有 ignored dist。
- public 页面在缺失远端 config 时也不应跳出当前静态托管前缀；fallback 要从当前 document URL 推导。

### 验证记录

- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`

## 2026-06-08 / Final verification

### 验证记录

- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs .github/workflows/build-release.test.mjs`
- `bash -n scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh`
- `sh -n scripts/docker-entrypoint.sh`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./...`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go vet ./...`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

### 限制说明

- 当前 `internal/server/web/admin/package.json` 没有 `test:unit` script；本轮未执行该不存在的命令。
- 当前环境没有 `pwsh`；PowerShell 脚本做了 Node 静态回归和 workflow 中的 PowerShell parser 验证接入，但未在本地执行 PowerShell parser。

## 2026-06-08 / Reviewer follow-up hardening

### MAGI 审视

- scripts/CI reviewer 发现两处 Important：
  - `mountpoint` 命令不可用或检测异常时，主控卸载会 fail-open 删除已标记数据目录。
  - Windows rollback 只恢复 `auto/manual/disabled`，没有恢复 Automatic Delayed Start。
- backend reviewer 发现两处 Important：
  - Docker-managed 服务端更新启动 helper 后过早清空 `updating`，允许重复 helper 并发重建同一容器。
  - 无 healthcheck 的 Docker replacement 只要第一次 inspect 为 `Running` 就提交，Agent 容器启动后快速退出时会错过 rollback。

### MAGI 执行

- `scripts/one-click.sh`
  - `mountpoint` 缺失或返回未知状态时保留数据目录，不再进入 `rm -rf`。
  - 安装主控创建 data dir 前先验证路径安全。
- `scripts/one-click.test.mjs`
  - 增加 mountpoint unknown fail-closed 回归测试。
  - 增加 data dir 必须在 `mkdir -p` 前验证的静态回归测试。
- `scripts/agent.ps1`
  - `Get-ServiceSnapshot` 记录 `DelayedAutoStart`。
  - `ConvertTo-ScStartMode` 在原服务为 delayed automatic 时恢复 `start= delayed-auto`。
- `scripts/agent-ps1.test.mjs`
  - 增加 delayed-auto snapshot 和 rollback 参数静态回归检查。
- `internal/server/system_update.go`
  - `Start` 接收调用方已判定的 `dockerManaged`。
  - Docker-managed helper 启动成功后保持 `updating=true`，防止同一进程内重复启动 helper。
  - Binary update 成功返回后仍按原逻辑清空 `updating`。
- `internal/server/system_update_test.go`
  - 增加 Docker-managed helper in-flight 时第二次 Start 必须 conflict 的回归测试。
  - 增加 binary update 成功后可再次 Start 的回归测试。
- `internal/updater/docker_managed.go`
  - 无有效 healthcheck 的 replacement 必须连续两次 inspect 都处于 `Running` 才算 ready。
  - 如果第一次 `Running` 后第二次变为 `exited`，readiness wait 失败并触发 rollback。
- `internal/updater/docker_managed_test.go`
  - 增加无 healthcheck 稳定 Running 和 Running-then-Exited 两个回归测试。

### MAGI 提升

- 危险删除必须 fail-closed。不能把“无法判断”当作“安全删除”。
- Docker-managed 更新的 server 侧状态只能证明 helper 已启动，不能证明容器替换完成；因此 manager 必须继续阻止重复提交。
- 无 healthcheck 场景没有应用级 ready 信号，只能用更保守的稳定运行窗口降低误删旧容器的概率。

### 验证记录

- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs`
- `bash -n scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server ./internal/updater -count=1`
- `git diff --check`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./...`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go vet ./...`
- `node --test scripts/agent-ps1.test.mjs`
- `bash -n scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh`
- `sh -n scripts/docker-entrypoint.sh`
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin NotificationAlert Kumo Input Label direct migration

### MAGI 审视

- `NotificationAlert` 有四个真实输入字段：offline-minutes、telegram-token、telegram-user-ids、feishu-webhook。
- 四个输入都已有显式 `name`，不依赖本地 `Input` wrapper 的 `name || id` fallback。
- 本地 `Input` wrapper 原来隐式补 `aria-labelledby` 和 `w-full min-w-0`；本地 `Label` wrapper 原来按 `htmlFor` 派生 label id。直连 Kumo 后必须在页面中显式保留 accessible-name 和宽度行为。
- 页面里 `Bot Token` 是可见硬编码文案，Feishu webhook placeholder 也是可见 placeholder；本轮纳入 i18n，避免局部迁移留下文案缺口。

### MAGI 执行

- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - 将 `Input` 改为从 `@cloudflare/kumo/components/input` 直连导入。
  - 将 `Label` 改为从 `@cloudflare/kumo/components/label` 直连导入。
  - 为 offline threshold、Telegram token、Telegram user ids、Feishu webhook 输入显式补 `aria-label={t("notificationAlert.field.*")}`。
  - 将四个输入 class 改为 `cn("w-full min-w-0", adminInputClass)`，保留原 wrapper 的宽度行为。
  - 将 Telegram token label 改为 i18n 字典文案。
  - 将 Feishu webhook placeholder 改为 `t("notificationAlert.placeholder.webhook")`。
  - 为 offline threshold 和 Telegram user ids 的说明文本补稳定 id，并让 `aria-describedby` 在错误状态下同时指向 hint 与 error。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增 `notificationAlert.field.telegramToken`。
  - 新增 `notificationAlert.placeholder.webhook`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 NotificationAlert 直连 Kumo `Input` / `Label` 的静态回归。
  - 锁定四个输入的 `id`、`name`、`aria-label`、宽度 class、hint/error 描述链和 webhook placeholder i18n。
- `internal/server/web/admin-i18n.test.mjs`
  - 锁定新增的 NotificationAlert 字典键。

### MAGI 提升

- `NotificationAlert` 已不再使用本地 `Input` / `Label` wrapper。
- 表单可访问名称不再依赖 wrapper 的隐式 label-id 派生，页面本身持有可验证语义。
- 剩余 `Input` / `Label` wrapper 调用仍分布在 BasicSettings、AIProvider、ServerManagement、GroupManagement，后续应继续按页面逐个审视，不做跨页面批量替换。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：30 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-08 / Docker asset gate

### MAGI 审视

- Docker-managed Agent update 和 system update 都只需要目标版本与当前容器镜像来推导 `targetImage`。
- 二进制 `DownloadURL` / `ChecksumURL` 只属于 binary self-update；让 Docker-managed 分支先经过该 gate 会把“有镜像但无当前平台二进制 asset”的 release 错误拒绝。
- 原入口结构里，Agent POST 和 System POST 都在进入 Docker-managed 分支前要求 `DownloadURL`，属于冗余 gate。

### MAGI 执行

- `internal/server/system_update.go`
  - 新增 `agentUpdateReleaseAssetError`。
  - 新增 `systemUpdateReleaseAssetError`。
  - Docker-managed 分支直接跳过二进制 asset 要求。
  - Binary 分支仍要求 `DownloadURL` 和 `ChecksumURL`。
- `internal/server/server.go`
  - Agent update POST 改为调用 `agentUpdateReleaseAssetError`。
  - System update POST 捕获一次 `dockerManaged := updater.CanDockerManagedUpdate()`，同一布尔值同时用于 asset gate 和实际更新分支。
  - 删除旧的 `isChecksumOptionalForAgentUpdate`，避免只把 checksum 特判成“可选”而保留 DownloadURL 冗余 gate。
- `internal/server/update_assets_test.go`
  - 覆盖 Agent Docker-managed 缺 binary asset 不报错。
  - 覆盖 Agent binary 缺 `DownloadURL` / 缺 `ChecksumURL` 报错。
  - 覆盖 System Docker-managed 和 binary 两条语义。

### MAGI 提升

- 更新路径的校验要按实际执行模式绑定，不能用 release asset 形态反向限制 Docker image update。
- 下一轮优先级变为：
  1. 给 server uninstall 数据目录增加 owned sentinel 和 mountpoint 保护。
  2. 改善 Docker rollback 失败时的可观测性。
  3. 评估是否需要对 Docker-managed 分支补“缺少目标版本”的显式 guard。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test.*ReleaseAsset' -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server ./internal/agent ./internal/updater -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./...`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go vet ./...`
- `node --test scripts/agent-ps1.test.mjs`
- `git diff --check`
- `bash -n scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh`
- `sh -n scripts/docker-entrypoint.sh`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-08 / Server uninstall data guard

### MAGI 审视

- `scripts/one-click.sh` 的主控卸载会在数据目录位于 `INSTALL_DIR` 子路径时直接 `rm -rf`。
- 该判断只能证明路径归属相对位置，不能证明目录确实由安装脚本创建，也不能排除数据目录被挂载为独立卷。
- 高风险点是误删未标记目录，或删除挂载点内的外部持久化数据。

### MAGI 执行

- `scripts/one-click.sh`
  - 新增 `SERVER_DATA_OWNED_MARKER=.cybermonitor-server-data`。
  - 安装主控创建数据目录前先执行 `reject_unsafe_path`，拒绝路径穿越和 symlink 路径。
  - 安装主控时，只对本次新建的数据目录写入 owned marker。
  - 安装失败回滚清理本次新建数据目录前会先移除 marker，避免 marker 让空目录无法 `rmdir`。
  - 主控卸载删除数据目录前同时要求路径位于安装目录下、owned marker 存在、且目录不是 mountpoint。
  - 未标记目录、挂载点目录和自定义目录均保留，仅删除主控配置文件。
- `scripts/one-click.test.mjs`
  - 增加 Node 标准库脚本回归测试，覆盖安装前 data dir 验证、安装 marker、未标记目录保留、已标记目录删除、已标记挂载点保留。

### MAGI 提升

- 卸载脚本只应删除自己能证明拥有的数据目录；路径位置不是所有权证明。
- 下一轮优先级变为：
  1. 改善 Docker rollback 失败时的可观测性。
  2. 评估 Docker-managed 分支缺少目标版本时是否需要更早的显式 guard。
  3. 复核 release workflow 是否还存在重复构建和产物复用问题。

### 验证记录

- `node --test scripts/one-click.test.mjs`
- `bash -n scripts/one-click.sh`

## 2026-06-08 / Release artifact reuse

### MAGI 审视

- `.github/workflows/build-release.yml` 的 `build-server` / `build-agent` matrix 已经按目标平台构建所有 release binary。
- `release` job 仍在 `Prepare release files` 中再次执行同一组 `go build`，导致发布链路重复构建。
- 重复构建会增加耗时，也会把 release 阶段变成第二个构建入口，后续 ldflags、平台矩阵或 embed 资产调整更容易漂移。

### MAGI 执行

- `.github/workflows/build-release.yml`
  - `build-server` 和 `build-agent` job 增加 artifact 上传，artifact 名称直接使用 `matrix.output`。
  - `release` job 改为下载 `cyber-monitor-*` artifacts 到 `release/`，再执行权限修正、web asset 打包、checksum 和 GitHub Release 发布。
  - 移除 `release` job 中的 `actions/setup-go` 和二次 `go build`。
  - `build-admin` 增加 Node 回归测试步骤，覆盖脚本测试和 workflow 静态测试。
- `.github/workflows/build-release.test.mjs`
  - 新增静态回归测试，锁定 build job 必须上传 artifact、release job 必须下载 artifact、release 阶段不得再 `go build`。
  - 锁定 workflow 会运行 `scripts/agent-ps1.test.mjs`、`scripts/one-click.test.mjs` 和自身 workflow test。

### MAGI 提升

- 发布 job 应只组装、校验和发布已有产物；构建职责保留在 matrix build jobs。
- 下一轮优先级变为：
  1. 改善 Docker rollback 失败时的可观测性。
  2. 评估 Docker-managed 分支缺少目标版本时是否需要更早的显式 guard。
  3. 最后跑全局验证并审查当前 diff 的耦合面。

### 验证记录

- `node --test .github/workflows/build-release.test.mjs`

## 2026-06-08 / Docker target version guard

### MAGI 审视

- `ResolveDockerTargetImage(currentImage, "")` 原本会剥掉当前 tag 后返回裸 repo。
- Docker 对裸 repo 通常会按 `latest` 解析；这会把“Release 缺少目标版本”的异常元数据变成隐式 latest 更新。
- Server 入口在 Docker-managed 分支跳过 binary asset gate 后，也需要独立校验目标版本存在。

### MAGI 执行

- `internal/updater/docker_managed.go`
  - `ResolveDockerTargetImage` 在当前镜像或目标版本为空时返回空目标镜像。
  - 已有 `LaunchSelfContainerUpdate` 的空目标镜像保护会继续拒绝执行 helper。
- `internal/server/system_update.go`
  - Agent/System release asset gate 先校验 `LatestVersion`，Docker-managed 分支不再绕过目标版本校验。
- `internal/updater/docker_managed_test.go`
  - 增加空目标版本不得解析成裸 repo 的回归测试。
- `internal/server/update_assets_test.go`
  - 增加 Docker-managed Agent/System 缺目标版本必须报错的回归测试。

### MAGI 提升

- Docker image update 只应使用显式版本 tag；不能用缺失目标版本推导 `latest`。
- 下一轮优先级变为：
  1. 改善 Docker rollback 失败时的可观测性。
  2. 跑完整验证矩阵。
  3. 最后做当前 diff 全局审查。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestResolveDockerTargetImageRequiresTargetVersion -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run TestDockerManagedReleaseAssetErrorRequiresTargetVersion -count=1`

## 2026-06-08 / Docker rollback observability

### MAGI 审视

- Docker recreate helper 的 rollback 会执行删除替换容器、恢复旧容器名称、重启旧容器等外部副作用。
- 原实现吞掉 rollback API 错误；如果原始失败之后 rollback 也失败，调用方只能看到原始失败原因。
- 这会掩盖最关键的信息：旧容器是否真的恢复成功。

### MAGI 执行

- `internal/updater/docker_managed.go`
  - `rollbackCreatedContainer` 改为返回 error。
  - 删除替换容器失败不会阻止后续恢复旧容器；多个 rollback 错误通过 `errors.Join` 汇总。
  - helper defer 会把 rollback 错误追加到原始错误上，包含 `Docker 更新回滚失败` 上下文。
- `internal/updater/docker_managed_test.go`
  - 更新既有 rollback 调用测试，要求成功路径 error 为空。
  - 增加删除替换容器失败和重启旧容器失败的组合错误测试。
  - 增加原始错误与 rollback 错误组合的回归测试。

### MAGI 提升

- 回滚路径不仅要尽力恢复，还要把恢复失败准确暴露给调用方。
- 当前高确定性语义 gap 已收敛；下一步是完整验证矩阵和最终 diff 审查。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -count=1`

## 2026-06-08 / Agent Docker helper failure propagation

### MAGI 审视

- Server Docker-managed update 已改为等待 helper 退出，能在旧 server 容器停止前回传 helper 早期失败。
- Agent Docker-managed update 仍只调用 detached helper launch。
- 这意味着 helper 容器只要启动成功，Agent 就会上报 `restarting`；后续拉镜像、创建替换容器或就绪检查失败时，旧 Agent 仍可能继续运行，但控制面不会收到 failed 状态。

### MAGI 执行

- `internal/agent/agent.go`
  - `dockerManagedUpdater` 接口增加 `LaunchSelfContainerUpdateAndWait`。
  - Docker-managed Agent 更新改为等待 helper，而不是只等待 helper container 启动。
  - helper wait timeout 从 15 秒调整为 10 分钟，覆盖 image pull、容器重建和 readiness 检查。
- `internal/agent/agent_update_test.go`
  - 新增回归测试，锁定 helper 非零失败必须让 `maybeApplyRemoteUpdate` 返回错误并上报 failed。

### MAGI 提升

- Docker-managed server 和 agent 更新现在使用同一条 helper wait 语义：早期 helper 失败必须回传；旧容器停止后的 late failure 仍依赖 helper rollback 和新进程恢复。
- 下一步是跑完整验证矩阵，并最终审查当前 diff 中 release、install、runtime、deployment 的耦合面。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run TestMaybeApplyRemoteDockerUpdateReportsHelperFailure -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent ./internal/updater ./internal/server -count=1`

## 2026-06-08 / Full local verification after semantic pass

### MAGI 审视

- 本轮继续按 current worktree 审查，而不是用旧 summary 判断完成。
- 重点复核了 release artifact 复用、build-first 本地入口、PowerShell rollback、one-click 数据目录删除、Delete/Clear pending history cleanup、public/admin 子路径和 Docker-managed update。
- 发现并修复了 Agent Docker-managed update 没有等待 helper 的语义缺口；未再发现需要立即落地的新阻断项。

### MAGI 执行

- 保持当前大 patch set 未提交。
- 重新跑完整本地验证入口和 race 矩阵。
- 复核 GitHub 官方 tag refs，确认 workflow 使用的 `actions/upload-artifact@v7` 与 `actions/download-artifact@v8` 存在。

### MAGI 提升

- 当前 phase 可以作为一次局部收口，但 repo-wide 长期目标仍不能标记完成。
- 下一轮应继续从当前 diff 出发，优先做实际运行 smoke：子路径反代、Docker-managed helper 真实 daemon 路径、Windows installer CI 结果。

### 验证记录

- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
- `bash -n scripts/verify-local.sh scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh`
- `sh -n scripts/docker-entrypoint.sh`
- `scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build-race GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `scripts/build-local.sh`
- `git diff --check`

## 2026-06-08 / Final review follow-up tightening

### MAGI 审视

- 子代理 `019ea515-5c5c-7ba3-b60f-2d8c30fa5f6b` 被用于只读审视，但连续等待超时，最终关闭；本轮不把它当完成证据。
- 主线继续按 current worktree 做人工 diff review 和验证，而不是依赖旧日志或子代理输出。
- 发现两个可直接收敛的边界：
  - `DeleteNode` 在只剩 `pending_history_deletes` 且当前没有 history manager 时会返回 not found，并留下 stale pending intent。
  - admin `base_path` 归一化只 decode 一次，和后端 `X-Forwarded-Prefix` 的多轮 decode 防护不一致。

### MAGI 执行

- `internal/server/server.go`
  - `DeleteNode` 在无业务状态、无 history manager、但存在 pending delete intent 时，清理该 intent 并返回 `deleted=true`。
- `internal/server/server_delete_test.go`
  - 新增无 history manager 时 stale pending delete intent 收口的回归测试。
- `internal/server/web/admin/lib/admin-api.ts`
  - `normalizeBasePath` 改为最多 4 轮 decode，并在每轮后复核非法 prefix，和后端 forwarded prefix 约束保持一致。
- `internal/server/web/admin-api.test.mjs`
  - 新增 admin base path 函数级回归，覆盖 double-encoded dot segment、encoded colon、绝对 URL、重复 slash 和正常 path-only prefix。
- `scripts/verify-local.sh` 与 `.github/workflows/build-release.yml`
  - 将 admin API 回归测试纳入本地验证和 release workflow 的 Node regression。
- `.github/workflows/build-release.test.mjs`
  - 锁定 workflow 会运行新的 admin API regression。

### MAGI 提升

- pending cleanup 状态机需要覆盖“清理资源缺席”的终态；否则 retry intent 会变成永久残留。
- 前后端共享的路径安全规则必须同向收敛。即使前端 boot payload 正常来自后端，也不应让同一输入规则出现不同强度。
- 子代理不可用时，不能把 delegation 当阻塞理由；需要回到主线证据和本地验证矩阵。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run TestDeleteNodeClearsExistingPendingHistoryCleanupWithoutHistoryManager -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(DeleteNode|ClearNodes|Admin.*HandlerReturnsHistoryError)' -count=1`
- `node --test internal/server/web/admin-api.test.mjs .github/workflows/build-release.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build-race GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

## 2026-06-08 / Docker-managed helper daemon smoke

### MAGI 审视

- 上一轮 runtime smoke 已覆盖 server/public/admin/ws，但 Docker-managed helper 还只有 mock/unit 证据。
- 当前 Docker daemon 可用：`docker --version` 与 `docker info` 均成功，daemon server version 为 `29.5.3`。
- 子代理 `019ea52b-6c85-70e2-b21f-c5af5d89ecb4` 只读审视确认真实 daemon smoke 可行，并强调只能操作一次性容器，不能触碰现有运行容器。
- 当前 daemon 上原有运行容器包括 `cli-proxy-api` 和 `cyber-monitor-agent`；本轮未对它们执行 stop/remove/rename。

### MAGI 执行

- 拉取 `alpine:3.20` 作为一次性 target image。
- 创建 disposable old container：
  - 名称：`cm-docker-helper-smoke-20260608b`
  - label：`cybermonitor.smoke=20260608b`
  - 原 ID：`2c59e79df106...`
  - 命令：`sh -c 'trap "exit 0" TERM; while true; do sleep 1; done'`
- 直接执行当前代码的 helper 子命令：
  - `go run ./cmd/agent docker-recreate-helper`
  - `CM_DOCKER_HELPER_TARGET_CONTAINER=2c59e79df106...`
  - `CM_DOCKER_HELPER_TARGET_IMAGE=alpine:3.20`
  - `CM_DOCKER_HELPER_SOCKET_TARGET=/var/run/docker.sock`
  - `CM_DOCKER_HELPER_NODE_ID=smoke-node-20260608b`
- helper exit 0，证明真实 daemon 路径完成：
  - pull target image。
  - inspect old container。
  - create replacement container。
  - stop old container。
  - rename old container to backup name。
  - rename replacement to original name。
  - start replacement。
  - readiness wait 在无 healthcheck 场景下通过 stable running。
  - cleanup old backup container。
- 验证替换后原名容器：
  - 新 ID：`84bd3c0a4841...`
  - 状态：`running`
  - 镜像：`alpine:3.20`
  - 环境变量包含 `CM_NODE_ID=smoke-node-20260608b`
- 删除 disposable container `cm-docker-helper-smoke-20260608b`。
- 确认没有 `cybermonitor.smoke=20260608b` label 容器残留，也没有 `cm-docker-helper-smoke-20260608b` 名称残留。

### MAGI 提升

- Docker-managed helper 的真实 daemon 主路径已经有实证，不再只是 mock/unit 证据。
- 本轮没有清理 `alpine:3.20` 镜像；这是 Docker image cache，不是运行中资源。删除镜像会引入额外 Docker 状态变更，后续验证也可能复用它。
- 当前仍不能标记长期目标 complete；剩余外部验证点主要是 CI 上的 Windows PowerShell parser、GitHub Actions release workflow 真实运行，以及生产式 Docker image update 的跨架构发布链路。

### 验证记录

- `docker --version`
- `docker info --format '{{json .ServerVersion}}'`
- `docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}'`
- `docker ps --format '{{.Names}} {{.Image}} {{.Status}}'`
- `docker pull alpine:3.20`
- `docker ps -a --filter name=^/cm-docker-helper-smoke-20260608b$ --format '{{.ID}} {{.Names}} {{.Status}}'`
- `docker run -d --name cm-docker-helper-smoke-20260608b --label cybermonitor.smoke=20260608b alpine:3.20 sh -c 'trap "exit 0" TERM; while true; do sleep 1; done'`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build CM_DOCKER_HELPER_TARGET_CONTAINER=2c59e79df106f24f258dbb4b8c0a059291361259c4f7d8185e7db400180cd247 CM_DOCKER_HELPER_TARGET_IMAGE=alpine:3.20 CM_DOCKER_HELPER_SOCKET_TARGET=/var/run/docker.sock CM_DOCKER_HELPER_NODE_ID=smoke-node-20260608b go run ./cmd/agent docker-recreate-helper`
- `docker inspect cm-docker-helper-smoke-20260608b --format '{{.Id}} {{.State.Status}} {{.Config.Image}} {{range .Config.Env}}{{println .}}{{end}}'`
- `docker ps -a --filter label=cybermonitor.smoke=20260608b --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}'`
- `docker ps -a --filter name=cm-docker-helper-smoke-20260608b-prev --format '{{.ID}} {{.Names}} {{.Status}}'`
- `docker rm -f cm-docker-helper-smoke-20260608b`
- `docker ps -a --filter label=cybermonitor.smoke=20260608b --format '{{.ID}} {{.Names}} {{.Status}}'`
- `docker ps -a --filter name=cm-docker-helper-smoke-20260608b --format '{{.ID}} {{.Names}} {{.Status}}'`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run 'Test(LaunchDockerUpdateHelper|RollbackCreatedContainer|WaitReplacementContainerReady|ReplacementContainerReady|ResolveDockerTargetImage|CleanupOldContainer)' -count=1`
- `scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build-race GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

## 2026-06-08 / Runtime smoke and release-side review

### MAGI 审视

- 继续以 current worktree 为准，不用上一轮口头结论替代本轮证据。
- 本轮重点从静态测试推进到真实 server runtime：
  - public root 与 `./assets` 静态路径。
  - `/config.json` 与 `X-Forwarded-Prefix: /cm` 子路径配置。
  - admin 无尾斜杠 redirect、admin boot payload 和 admin asset。
  - `/ws` WebSocket upgrade。
  - headless Chrome public/admin DOM。
- 子代理 `019ea521-549d-78f0-bd9d-7f45003cdb3b` 只读复核 release workflow、Dockerfile、one-click、PowerShell rollback、Docker-managed updater，结论为无高确定性 findings。

### MAGI 执行

- 使用临时数据目录 `/tmp/cm-runtime-smoke-20260608b` 和端口 `127.0.0.1:25214` 启动 server。
- 验证 `/api/v1/health` 返回 200。
- 验证 public HTML 使用 `./assets/styles.css`、`./assets/theme.js`、`./assets/monitor.js`。
- 验证 `/config.json` 返回当前 origin 的 API/WS URL。
- 验证带 `X-Forwarded-Prefix: /cm` 的 `/config.json` 返回 `/cm` 前缀 API/WS URL。
- 验证 `/admin-smoke` 302 到 `/admin-smoke/`，带 prefix 时 302 到 `/cm/admin-smoke/`。
- 验证 `/admin-smoke/` 的 boot meta 可注入 `base_path=/cm`。
- 验证 admin JS/CSS asset 返回 200。
- 验证 `/ws` WebSocket upgrade 返回 101 并推送 snapshot。
- 使用 headless Chrome CLI 验证 public DOM 完成动态渲染，admin login DOM 完成 lazy loading。
- smoke server 已停止，25214 端口无监听。
- 已清理本轮 `/tmp/cm-runtime-smoke-20260608b` 与 Chrome 临时 profile/cache。

### MAGI 提升

- 当前 public/admin 子路径、config 和 WebSocket 的真实 runtime 证据已经补齐。
- Chrome CLI 在当前容器仍会输出 `/root/.config`、DBus、fontconfig 相关噪声；exit 0 和 DOM 内容才是本轮有效证据。
- 下一轮仍不能直接宣称长期目标 complete；优先方向是：
  1. 有 Docker daemon 时跑 Docker-managed helper 的真实 daemon 路径。
  2. 等 CI 验证 Windows PowerShell parser 和 release workflow。
  3. 继续审查当前大 patch set 的耦合面，避免 release、runtime、installer 三条路径互相漂移。

### 验证记录

- `go run ./cmd/server` with `CM_LISTEN=127.0.0.1:25214` and `/tmp/cm-runtime-smoke-20260608b`
- `curl -s -i http://127.0.0.1:25214/api/v1/health`
- `curl -s http://127.0.0.1:25214/`
- `curl -s http://127.0.0.1:25214/config.json`
- `curl -s -H 'X-Forwarded-Prefix: /cm' http://127.0.0.1:25214/config.json`
- `curl -s -i http://127.0.0.1:25214/admin-smoke`
- `curl -s -i -H 'X-Forwarded-Prefix: /cm' http://127.0.0.1:25214/admin-smoke`
- `curl -s http://127.0.0.1:25214/admin-smoke/`
- `curl -s -H 'X-Forwarded-Prefix: /cm' http://127.0.0.1:25214/admin-smoke/`
- `curl -s -i http://127.0.0.1:25214/admin-smoke/assets/index-Ch1bl-nB.js`
- `curl -s -i http://127.0.0.1:25214/admin-smoke/assets/index-DVNdk-5h.css`
- `curl -s -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' http://127.0.0.1:25214/ws`
- `google-chrome --headless=new --no-sandbox --disable-gpu --user-data-dir=/tmp/cm-chrome-profile --disk-cache-dir=/tmp/cm-chrome-cache --virtual-time-budget=5000 --dump-dom http://127.0.0.1:25214/admin-smoke/`
- `google-chrome --headless=new --no-sandbox --disable-gpu --user-data-dir=/tmp/cm-chrome-profile-public --disk-cache-dir=/tmp/cm-chrome-cache-public --virtual-time-budget=3000 --dump-dom http://127.0.0.1:25214/`
- `lsof -nP -iTCP:25214 -sTCP:LISTEN`
- `scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build-race GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

## 2026-06-08 / Docker daemon smoke regression hook

### MAGI 审视

- Docker-managed helper 已有真实 daemon smoke 证据，但原证据是手工命令，不方便后续按需复跑。
- 这个测试不能进入默认破坏性路径；默认 `go test` 必须只编译并 skip，不能创建、停止、rename 或删除 Docker 容器。
- 显式开启时，测试资源必须全程限定在唯一 label 的 disposable container 上，不能触碰 daemon 上已有容器。

### MAGI 执行

- `internal/updater/docker_managed_integration_test.go`
  - 新增 `TestDockerRecreateHelperDaemonSmoke`。
  - 默认通过 `CM_RUN_DOCKER_DAEMON_TEST` skip。
  - 显式设置 `CM_RUN_DOCKER_DAEMON_TEST=1` 时，使用 Docker API 创建一次性 `alpine:3.20` 容器。
  - 直接调用 `RunDockerRecreateHelper`，验证真实 helper 主路径：pull、inspect、create replacement、stop old、rename、start、stable running readiness、old cleanup。
  - 验证 replacement 仍使用原名、新 ID、running 状态、目标镜像和回填的 `CM_NODE_ID`。
  - cleanup 使用唯一 `cybermonitor.smoke=<runID>` label 强制移除本测试创建的容器。

### MAGI 提升

- Docker daemon 真实路径现在有可重复的默认跳过 integration hook；后续需要实证时不必重新拼手工命令。
- 本轮仍不清理 `alpine:3.20` image cache。它不是运行资源，且后续 smoke 可以复用。
- 长期目标仍不能标记 complete；外部剩余证据仍包括 CI 上的 Windows PowerShell parser、GitHub Actions release workflow 真实运行和生产式跨架构镜像更新。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestDockerRecreateHelperDaemonSmoke -count=1 -v`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build CM_RUN_DOCKER_DAEMON_TEST=1 go test ./internal/updater -run TestDockerRecreateHelperDaemonSmoke -count=1 -v`
- `docker ps -a --filter label=cybermonitor.smoke --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}'`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -count=1`
- `scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build-race GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

## 2026-06-08 / Local static build parity

### MAGI 审视

- 子代理 Turing 因 `429 Too Many Requests` 失败，本轮不把 delegation 当审查证据。
- 真实 Docker build smoke 验证了 `release-server-prebuilt` 和 `release-agent-prebuilt` 的 amd64 target 可构建。
- smoke 前的 `dist/cyber-monitor-*-local` 是动态链接 ELF；release workflow 和 Dockerfile build stage 都使用 `CGO_ENABLED=0`，本地构建入口与发布构建语义漂移。

### MAGI 执行

- `scripts/build-local.sh`
  - 在本地 server/agent build 前默认导出 `CGO_ENABLED=0`。
  - 仍允许调用方显式覆盖 `CGO_ENABLED`，但默认路径与 release/Docker 静态构建保持一致。
- `scripts/build-local.test.mjs`
  - 新增静态回归测试，锁定 `build-local.sh` 必须在 `go build` 前设置 `CGO_ENABLED="${CGO_ENABLED:-0}"`。

### MAGI 提升

- 本地 build 入口应和 release build 保持同一核心编译语义；否则 local smoke 产物会证明错误的运行环境。
- Docker prebuilt target 已有实际 build smoke 证据，但本轮只覆盖 amd64 target。arm64 仍依赖 GitHub Actions buildx/QEMU 跑完整矩阵。
- 子代理不可用时继续主线审查；delegation 只能增强证据，不能替代本地验证。

### 验证记录

- `docker build --target release-server-prebuilt --platform linux/amd64 -t cm-prebuilt-smoke:server .`
- `docker build --target release-agent-prebuilt --platform linux/amd64 -t cm-prebuilt-smoke:agent .`
- `docker rmi cm-prebuilt-smoke:server cm-prebuilt-smoke:agent`
- `rm -rf docker-release`
- `node --test scripts/build-local.test.mjs` before fix: failed on missing `CGO_ENABLED`
- `node --test scripts/build-local.test.mjs`
- `bash -n scripts/build-local.sh scripts/verify-local.sh`
- `scripts/build-local.sh`
- `file dist/cyber-monitor-server-local dist/cyber-monitor-agent-local`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build-race GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

## 2026-06-08 / Docker build context hygiene

### MAGI 审视

- 子代理 Locke 因 `429 Too Many Requests` 失败，本轮继续不把 delegation 当完成证据。
- release workflow 和本地 Node regression 列表一致，`actions/upload-artifact@v7`、`actions/download-artifact@v8`、`actions/cache@v4`、`actions/checkout@v6` tag 已用 `git ls-remote` 验证存在。
- `.dockerignore` 已排除 `.serena`，但没有排除 `.codex` 和 `.agents`。这两个目录属于本地 agent 状态，不应进入 Docker build context。

### MAGI 执行

- `.dockerignore`
  - 新增 `.codex`。
  - 新增 `.agents`。
- `.github/workflows/build-release.test.mjs`
  - 新增 `docker build context excludes local agent state directories` 静态回归测试。
  - 锁定 `.dockerignore` 必须排除 `.serena`、`.codex`、`.agents`。

### MAGI 提升

- Docker build context 是发布输入边界；agent 状态、IDE 状态和本地上下文目录必须显式排除。
- 本轮 Docker prebuilt smoke 仍能通过，说明排除 agent 状态目录没有破坏 `docker-release` bind mount 输入。
- 子代理连续 429 时，继续走本地审查和命令证据；不要把子代理不可用当作阻塞或完成证据。

### 验证记录

- `node --test .github/workflows/build-release.test.mjs` before fix: failed on missing `.codex`
- `node --test .github/workflows/build-release.test.mjs`
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
- `docker build --target release-server-prebuilt --platform linux/amd64 -t cm-prebuilt-smoke:server .`
- `docker build --target release-agent-prebuilt --platform linux/amd64 -t cm-prebuilt-smoke:agent .`
- `docker rmi cm-prebuilt-smoke:server cm-prebuilt-smoke:agent`
- `rm -rf docker-release`
- `scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build-race GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

## 2026-06-08 / Docker replacement healthcheck preservation

### MAGI 审视

- Docker-managed replacement 会复制旧容器的命令、入口、label、端口和 HostConfig，但原实现没有复制 `Config.Healthcheck`。
- 如果用户通过 compose 或 Docker API 为容器配置了自定义 healthcheck，replacement 会丢失该配置。
- 丢失 healthcheck 会让 readiness gate 从应用级健康检查退化为 stable running 判断，降低 Docker-managed 更新的安全性。

### MAGI 执行

- `internal/updater/docker_managed_test.go`
  - 新增 `TestBuildReplacementSpecPreservesCustomHealthcheck`。
  - 先验证 RED：当前 replacement healthcheck 为 nil。
  - 测试同时要求 `Healthcheck.Test` 被深拷贝，避免和 inspect source 共享 slice。
- `internal/updater/docker_managed.go`
  - `buildReplacementSpec` 复制旧容器的 `Healthcheck`。
  - 新增 `cloneHealthConfig`，只做直接深拷贝，不引入兼容包装。

### MAGI 提升

- Docker replacement spec 要保留影响运行语义和 readiness 的容器配置；healthcheck 属于提交 replacement 前的关键安全信号。
- 只复制必要字段，避免引入第二套 Docker spec abstraction。
- 下一轮可继续补强 replacement spec 的 env/label/host config 单元语义，减少对真实 daemon smoke 的依赖。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestBuildReplacementSpecPreservesCustomHealthcheck -count=1` before fix: failed on nil replacement healthcheck
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestBuildReplacementSpecPreservesCustomHealthcheck -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -count=1`
- `scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build-race GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

## 2026-06-08 / Docker replacement HostConfig collection cloning

### MAGI 审视

- `buildReplacementSpec` 对 `HostConfig` 做结构体浅拷贝后，会继续共享 slice/map 类集合字段。
- Docker client 当前未必会修改 inspect source，但 replacement spec 不应和旧 inspect 结果存在 alias。否则后续补字段或预处理时会制造隐性耦合。
- `Binds`、`PortBindings`、`Tmpfs`、`Sysctls` 等字段属于容器替换语义；丢失或被源对象后续修改污染，都会改变用户原本的运行约束。

### MAGI 执行

- `internal/updater/docker_managed_test.go`
  - 新增 `TestBuildReplacementSpecDoesNotShareHostConfigCollections`。
  - 先验证 RED：replacement 和 inspect source 共享 `Binds` slice。
  - 测试覆盖 `Binds`、`PortBindings`、`Tmpfs`、`Sysctls` 的 alias 风险。
- `internal/updater/docker_managed.go`
  - 对 HostConfig 常见集合字段做直接深拷贝：bind、port binding、volumes-from、annotation、capability、DNS、extra hosts、group、links、security option、storage option、tmpfs、sysctl、masked path、readonly path。
  - 新增 `clonePortMap`，保持实现简洁，不引入第二套 Docker spec abstraction。

### MAGI 提升

- replacement spec helper 应直接复制影响运行语义的 Docker 配置字段；不要通过兼容 shim 掩盖字段缺失。
- 下一轮继续审视 env/label/network 别名边界，确认 replacement spec 没有遗漏运行时语义。
- 长期目标仍不能标记 complete；外部剩余证据仍包括 CI Windows PowerShell parser、GitHub Actions release workflow 真实运行和 arm64 buildx/QEMU 矩阵。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestBuildReplacementSpecDoesNotShareHostConfigCollections -count=1` before fix: failed on shared `Binds` slice
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run 'TestBuildReplacementSpec(DoesNotShareHostConfigCollections|PreservesCustomHealthcheck)' -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -count=1`
- `scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build-race GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`

## 2026-06-08 / Docker replacement network endpoint sanitization

### MAGI 审视

- `network.EndpointSettings` 同时包含用户配置和运行时状态。
- 原 `cloneEndpointSettings` 先做结构体浅拷贝，再修补 aliases/links/driver opts，会把旧容器的 `MacAddress`、`NetworkID`、`EndpointID`、`Gateway`、`IPAddress`、`DNSNames` 等运行时 endpoint 状态带进 replacement spec。
- replacement 创建发生在旧容器还存在时；复用旧 endpoint 身份会放大网络冲突风险，也会让 replacement spec 混入不属于新容器的运行时事实。

### MAGI 执行

- `internal/updater/docker_managed_test.go`
  - 新增 `TestBuildReplacementNetworkingCopiesUserConfigWithoutRuntimeEndpointState`。
  - 先验证 RED：replacement endpoint 保留了旧 `MacAddress`、`NetworkID`、`EndpointID`、`Gateway`、`IPAddress`、`DNSNames`。
  - 测试要求保留 `IPAMConfig`、`Links`、`Aliases`、`DriverOpts`、`GwPriority`，并验证这些可变字段不和 inspect source 共享。
- `internal/updater/docker_managed.go`
  - `cloneEndpointSettings` 改为显式构造用户配置字段，不再浅拷贝整个 endpoint。
  - 新增 `cloneEndpointIPAMConfig`，深拷贝 `LinkLocalIPs`。
  - 不引入兼容包装；network replacement 的边界收敛为“只复制用户配置，不复制运行时 endpoint 身份”。

### MAGI 提升

- Docker inspect 结果不能直接等同于 create/connect 输入；包含运行时身份的结构必须显式挑字段。
- 下一轮可继续做最终 whole-diff review，优先看宽范围 patch set 是否还有类似“inspect output 直接复用为 desired spec”的边界问题。
- 长期目标仍不能标记 complete；外部剩余证据仍包括 CI Windows PowerShell parser、GitHub Actions release workflow 真实运行和 arm64 buildx/QEMU 矩阵。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestBuildReplacementNetworkingCopiesUserConfigWithoutRuntimeEndpointState -count=1` before fix: failed on runtime endpoint state copied into replacement endpoint
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestBuildReplacementNetworkingCopiesUserConfigWithoutRuntimeEndpointState -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -count=1`

## 2026-06-08 / Local Go path cache hygiene

### MAGI 审视

- 全局验证后 status 出现 `.gopath/`，这是本地 Go workspace cache，不是项目源码或发布输入。
- `.gitignore` 已覆盖 `.cache/`、`.gocache/`、`.gomodcache/`，但没有覆盖 `.gopath/`。
- `.dockerignore` 同样没有排除 `.gopath`，会让本地验证缓存进入 Docker build context。

### MAGI 执行

- `.github/workflows/build-release.test.mjs`
  - 扩展 Docker build context hygiene 静态测试，要求 `.dockerignore` 排除 `.gopath`。
  - 先验证 RED：测试失败于 `.dockerignore must exclude .gopath`。
- `.dockerignore`
  - 新增 `.gopath`。
- `.gitignore`
  - 新增 `.gopath/`。

### MAGI 提升

- 本地验证产生的 workspace cache 必须被 git 和 Docker context 同时排除。
- 下一轮若调整验证脚本缓存路径，应同步检查 `.gitignore`、`.dockerignore` 和 workflow 静态测试。

### 验证记录

- `node --test .github/workflows/build-release.test.mjs` before fix: failed on missing `.gopath`
- `node --test .github/workflows/build-release.test.mjs`

## 2026-06-08 / Docker replacement static IP daemon smoke

### MAGI 审视

- 上一轮清理了 `EndpointSettings` 的运行时状态，但仍需要验证静态 `IPAMConfig` 下 helper 生命周期顺序是否会被旧 endpoint 占用阻断。
- 不能仅凭推断重排 `RunDockerRecreateHelper` 的 create/connect/stop/rename/start 顺序；重排会影响 rollback 语义。
- 子代理 Descartes 因 `401 token_invalidated` 失败，本轮不把 delegation 当审视证据。

### MAGI 执行

- `internal/updater/docker_managed_integration_test.go`
  - 新增 `TestDockerRecreateHelperDaemonStaticIPSmoke`。
  - 默认继续由 `CM_RUN_DOCKER_DAEMON_TEST` skip，不触碰 Docker daemon。
  - 显式 opt-in 时创建唯一 label 的 disposable bridge network 和旧容器，旧容器使用静态 IPv4 `172.30.240.12`。
  - 调用真实 `RunDockerRecreateHelper`，验证 replacement 仍使用原容器名、新 ID，并保留同一静态 IPv4。
  - cleanup 使用本轮唯一 label 和 network name 清理测试资源。
- 实证结果显示当前 Docker daemon 上静态 IPv4 replacement 成功；本轮不重排生产 helper 生命周期。

### MAGI 提升

- 对 Docker daemon 生命周期风险，优先补可重复 opt-in smoke，而不是靠猜测改主路径。
- 当前证据覆盖单网络静态 IPv4；多网络静态 IP、固定 MAC、IPv6 静态地址仍可作为后续实证方向。
- 长期目标仍不能标记 complete；外部剩余证据仍包括 CI Windows PowerShell parser、GitHub Actions release workflow 真实运行和 arm64 buildx/QEMU 矩阵。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestDockerRecreateHelperDaemonStaticIPSmoke -count=1 -v`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build CM_RUN_DOCKER_DAEMON_TEST=1 go test ./internal/updater -run TestDockerRecreateHelperDaemonStaticIPSmoke -count=1 -v`

## 2026-06-08 / Latest component alignment and secondary static IP smoke

### MAGI 审视

- 新目标要求组件使用最新版，同时要求不要把工作重心转向 GitHub Actions 构建脚本。
- `npm outdated --json` 显示 admin 前端多项依赖落后；`Dockerfile` 仍使用 Node 24，和当前 Node latest 26 不一致。
- 官方 Go release history 显示 1.26 线已到 1.26.4；当前 `go.mod` 和 `Dockerfile` 为 1.26.2。
- 多网络 Docker replacement 仍缺少实证：secondary network 的静态 IP 在旧容器仍连接时，当前 helper 会先 `NetworkConnect` replacement，再 stop old。

### MAGI 执行

- `internal/server/web/admin/package.json` 与 `package-lock.json`
  - 将 admin 前端 direct dependencies/devDependencies 升到 npm registry latest。
  - `npm outdated --json` 已返回 `{}`。
- `Dockerfile`
  - `GO_IMAGE_VERSION` 从 `1.26.2` 对齐到 `1.26.4`。
  - `NODE_IMAGE_VERSION` 从 `24` 对齐到 `26`。
- `go.mod`
  - `go` directive 从 `1.26.2` 对齐到 `1.26.4`。
- `internal/updater/docker_managed_integration_test.go`
  - 新增 `TestDockerRecreateHelperDaemonSecondaryStaticIPSmoke`。
  - 使用两个 disposable bridge network，旧容器在 primary/secondary 都使用静态 IPv4。
  - 显式 opt-in 真实 daemon smoke 通过，说明当前 Docker daemon 上 secondary static IP replacement 未复现冲突；因此本轮不重排生产 helper 生命周期。

### MAGI 提升

- 版本对齐只做最小必要变更：更新组件版本和 lockfile，不深挖 workflow 构建逻辑。
- Docker replacement 生命周期风险继续用 opt-in daemon smoke 实证；没有 RED 证据时不改生产主路径。
- 后续可继续验证固定 MAC、IPv6 static address、以及 release workflow 在 CI 上实际使用 Node 26 / Go 1.26.4 的结果。

### 验证记录

- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json` before fix: listed outdated admin packages
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm install @base-ui/react@latest @fontsource-variable/geist@latest @tailwindcss/vite@latest @types/node@latest @types/react@latest @vitejs/plugin-react@latest lucide-react@latest postcss@latest react@latest react-dom@latest tailwind-merge@latest tailwindcss@latest tsx@latest typescript@latest vite@latest`
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestDockerRecreateHelperDaemonSecondaryStaticIPSmoke -count=1 -v`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build CM_RUN_DOCKER_DAEMON_TEST=1 go test ./internal/updater -run TestDockerRecreateHelperDaemonSecondaryStaticIPSmoke -count=1 -v`

## 2026-06-08 / Docker replacement fixed MAC preservation

### MAGI 审视

- Docker API 的 `EndpointSettings.MacAddress` 既可作为 create-time 用户配置，也会在 running 后承载实际 endpoint MAC。
- 当前 `cloneEndpointSettings` 明确复制 `IPAMConfig`、`Aliases`、`DriverOpts`、`Links`、`GwPriority`，但丢弃 `MacAddress`。
- 真实 daemon smoke 证明 fixed MAC replacement 会丢失用户指定 MAC，replacement 得到 Docker 生成的 MAC。
- 子代理 Leibniz 的只读审视与本地证据一致：`MacAddress` 应从 runtime-state blacklist 中移出；但 secondary endpoint 的 desired MAC 不通过 inspect API 暴露，不能无来源地恢复。

### MAGI 执行

- `internal/updater/docker_managed_integration_test.go`
  - 新增 `TestDockerRecreateHelperDaemonFixedMacSmoke`。
  - RED：显式 opt-in 真实 Docker daemon 测试失败，replacement fixed MAC 变成 Docker 生成值。
  - 默认路径仍由 `CM_RUN_DOCKER_DAEMON_TEST` skip，不触碰 Docker daemon。
- `internal/updater/docker_managed.go`
  - `cloneEndpointSettings` 保留 `MacAddress`。
  - 继续丢弃 `NetworkID`、`EndpointID`、`Gateway`、`IPAddress`、`DNSNames` 等纯运行时状态。
- `internal/updater/docker_managed_test.go`
  - 更新 `TestBuildReplacementNetworkingCopiesUserConfigWithoutRuntimeEndpointState`，把 fixed MAC 纳入用户 endpoint 配置断言。
- secondary fixed MAC smoke 曾暴露 replacement 仍无法保留 secondary desired MAC；Moby inspect API 不暴露 `DesiredMacAddress`，本轮不保留不可实现的错误验收测试。

### MAGI 提升

- Docker inspect 输出中同一个字段可能同时承载配置和运行态；需要用 daemon smoke 验证，不靠字段名猜测。
- primary fixed MAC 已可保留；secondary fixed MAC 需要额外配置来源或 Docker API 暴露 desired MAC 后再实现。
- 下一轮可继续验证 IPv6 static address，或转入 broader whole-diff review。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build CM_RUN_DOCKER_DAEMON_TEST=1 go test ./internal/updater -run TestDockerRecreateHelperDaemonFixedMacSmoke -count=1 -v` before fix: failed because replacement fixed MAC became generated
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestBuildReplacementNetworkingCopiesUserConfigWithoutRuntimeEndpointState -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestDockerRecreateHelperDaemonFixedMacSmoke -count=1 -v`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build CM_RUN_DOCKER_DAEMON_TEST=1 go test ./internal/updater -run TestDockerRecreateHelperDaemonFixedMacSmoke -count=1 -v`

## 2026-06-08 / Docker replacement static IPv6 daemon smoke

### MAGI 审视

- 当前 `cloneEndpointIPAMConfig` 使用 struct copy，已经保留 `EndpointIPAMConfig.IPv6Address`。
- 缺口不在生产代码推断，而在真实 Docker daemon 是否会通过 inspect 暴露 static IPv6 desired config，以及 replacement 是否实际拿到同一个 `GlobalIPv6Address`。
- 子代理 Hubble 只读审视结论一致：IPv6Address 已在 replacement spec 中保留；daemon smoke 缺 IPv6 覆盖；IPv6 能力缺失只能在前置 network/container setup 阶段 skip。

### MAGI 执行

- `internal/updater/docker_managed_integration_test.go`
  - 新增 `dockerDaemonIPv6SmokeEnv = CM_RUN_DOCKER_IPV6_DAEMON_TEST`。
  - 新增 `TestDockerRecreateHelperDaemonStaticIPv6Smoke`。
  - 测试默认仍由 `CM_RUN_DOCKER_DAEMON_TEST` skip；真实 IPv6 smoke 需要同时设置 `CM_RUN_DOCKER_DAEMON_TEST=1` 和 `CM_RUN_DOCKER_IPV6_DAEMON_TEST=1`。
  - 测试创建 disposable IPv6-enabled bridge network，并使用动态 ULA `/64` 降低残留 subnet overlap 风险。
  - 旧容器成功启动后，若 inspect 未保留 `IPAMConfig.IPv6Address` 或 replacement 未得到同一个 `GlobalIPv6Address`，直接 fail。
  - 仅在 IPv6 bridge network 前置能力缺失时 skip，并在 skip 文案中记录 Docker server/API version。
- 本地双 opt-in daemon smoke 通过；因此本轮不改 `internal/updater/docker_managed.go`。

### MAGI 提升

- IPv6 static address 已有真实 daemon 覆盖，和 IPv4 static IP、secondary IPv4 static IP、fixed MAC 形成同一类 replacement 网络配置证据。
- 后续如继续扩展 Docker replacement，可优先审视 network aliases、link-local IP、driver opts 和 gateway priority 的真实 daemon 行为。
- 长期目标仍未完成；还需要继续 whole-diff review，并分离当前 dirty worktree 中哪些变更属于同一可交付批次。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -run TestDockerRecreateHelperDaemonStaticIPv6Smoke -count=1 -v`
- `env CM_RUN_DOCKER_DAEMON_TEST=1 CM_RUN_DOCKER_IPV6_DAEMON_TEST=1 GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -run TestDockerRecreateHelperDaemonStaticIPv6Smoke -count=1 -v`
- `docker ps -a --filter name=cm-docker-helper-smoke --format '{{.ID}} {{.Names}} {{.Status}}'`
- `docker network ls --filter name=cm-docker-helper-net --format '{{.ID}} {{.Name}} {{.Driver}}'`

## 2026-06-08 / Docker helper wait AutoRemove preservation

### MAGI 审视

- 后端 whole-diff 复核发现 `LaunchSelfContainerUpdateAndWait` 的 wait 模式会把 helper `HostConfig.AutoRemove` 改成 `false`。
- 自更新路径中 helper 会停止旧容器，调用方进程可能在 helper 退出前被停止，调用方的 defer cleanup 不保证执行。
- 如果 wait 模式禁用 AutoRemove，成功更新后 helper exited container 可能残留。

### MAGI 执行

- `internal/updater/docker_managed.go`
  - `launchDockerUpdateHelper` 保留 helper spec 原始 `AutoRemove`。
  - cleanup 仍保留为尽力清理，用于 start failure 或调用方未被停止的路径。
  - cleanup 对 Docker 已自动删除的 NotFound 静默处理。
- `internal/updater/docker_managed_test.go`
  - 将 `TestLaunchDockerUpdateHelperWaitModeDisablesAutoRemove` 改为 `TestLaunchDockerUpdateHelperWaitModeKeepsAutoRemove`。
  - 断言 wait 模式不再篡改 caller host config，也不再关闭 helper AutoRemove。

### MAGI 提升

- 对自更新路径，不能假设调用方能执行 helper 后置 cleanup；由 Docker daemon 管理的 AutoRemove 更可靠。
- 等待 helper exit code 与 AutoRemove 不冲突；保留 AutoRemove 才符合自更新进程会被停止的生命周期。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -run 'TestLaunchDockerUpdateHelper|TestDockerRecreateHelperDaemonStaticIPv6Smoke|TestBuildReplacementNetworkingCopiesUserConfigWithoutRuntimeEndpointState' -count=1 -v`

## 2026-06-08 / Release artifact retention hardening

### MAGI 审视

- 脚本/workflow 子代理 Bernoulli 复核未发现必须修问题，但指出 matrix build artifacts 的 `retention-days: 1` 对排队或 manual rerun 超过 24 小时的 release workflow 不够稳。
- 该项属于低成本发布可靠性提升，不改变 build matrix、artifact naming、download pattern 或 Docker prebuilt 逻辑。

### MAGI 执行

- `.github/workflows/build-release.yml`
  - 将 build-server 和 build-agent 上传 matrix artifacts 的 `retention-days` 从 `1` 提升到 `7`。
- `.github/workflows/build-release.test.mjs`
  - 同步静态断言，继续锁住 artifact upload 配置和 release/docker jobs 复用 matrix artifacts。

### MAGI 提升

- 保留 artifact reuse 的简洁主路径，只扩大可下载窗口，降低 release job 延迟或 rerun 的偶发失败概率。
- 不继续深挖 GitHub Actions 构建脚本，符合当前目标的程序代码优先边界。

### 验证记录

- `node --test .github/workflows/build-release.test.mjs`

## 2026-06-08 / Admin delete partial-success toast contract

### MAGI 审视

- 前端 whole-diff 子代理 Plato 指出：删除节点 partial-success 已经通过 `history_error` 返回并在 `App.tsx` 发 warning，但 `ServerManagement.tsx` 仍无条件发 `toast.success("节点已删除")`。
- 这会让同一次删除操作在 history cleanup 失败时同时出现 warning 和 success，用户需要自己判断哪个状态更重要。
- 这是 UI 合同问题，不需要兼容包装；直接让删除回调返回后端 payload，并由子组件根据 `history_error` 决定是否显示 success。

### MAGI 执行

- `internal/server/web/admin-delete-node.test.mjs`
  - 新增静态回归测试。
  - RED：当前 `handleDeleteNode` 返回 `Promise<void>`，测试失败。
- `internal/server/web/admin/src/App.tsx`
  - `handleDeleteNode` 返回 `Promise<NodeDeleteResponse>`。
  - 保留 `history_error` warning，并在刷新节点后返回后端删除响应。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - `onDeleteNode` prop 改为 `Promise<NodeDeleteResponse>`。
  - 删除成功后仅在没有 `history_error` 时显示 success toast。
- `scripts/verify-local.sh` 与 `.github/workflows/build-release.yml`
  - 将新增回归测试纳入现有 Node test 矩阵。
- `.github/workflows/build-release.test.mjs`
  - 同步锁住 workflow 中新增测试项。

### MAGI 提升

- partial-success 状态应该只有一个主导提示：history cleanup 失败时显示 warning，不再叠加成功 toast。
- 后端响应 payload 不应在中间层丢弃；子组件可以基于同一个响应做直接 UI 决策。

### 验证记录

- `node --test internal/server/web/admin-delete-node.test.mjs` before fix: failed because `handleDeleteNode` still returned `Promise<void>`
- `node --test internal/server/web/admin-delete-node.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `node --test internal/server/web/admin-delete-node.test.mjs .github/workflows/build-release.test.mjs`

## 2026-06-08 / Public forwarded-prefix base injection

### MAGI 审视

- public HTML 已使用 `./assets/...` 和 `./config.json`，在 `/cm/` 这类带尾斜杠 subpath 下工作正常。
- 但当反向代理通过 `X-Forwarded-Prefix: /cm` 暴露 public 页面，且浏览器入口为 `/cm` 无尾斜杠时，浏览器按 URL 标准会把相对资源解析到站点根。
- 服务端已经用 `forwardedPrefix` 生成 `/cm/config.json` 和 `/cm/ws`，缺口是 public HTML 没有给浏览器提供同一个 base。

### MAGI 执行

- `internal/server/server_routes_test.go`
  - 新增 `TestPublicIndexHonorsForwardedPrefixBase`。
  - RED：请求 public index 并设置 `X-Forwarded-Prefix: /cm` 时，HTML 没有 `<base href="/cm/">`。
- `internal/server/server.go`
  - `writePublicIndexHTML` 在有效 forwarded prefix 存在时，向 `<head>` 后注入 `<base href="/prefix/" />`。
  - 普通根路径请求不注入 base，保持现有 root 部署行为。
  - base href 使用 `html.EscapeString`，复用既有 `forwardedPrefix` 过滤结果。

### MAGI 提升

- public subpath 不再只依赖调用方记住尾斜杠；服务端在已知 forwarded prefix 时直接把浏览器相对资源基准写入 HTML。
- 该实现是单一路径，不新增 fallback 分支；prefix 解析仍集中在已有 `forwardedPrefix`。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/server -run TestPublicIndexHonorsForwardedPrefixBase -count=1 -v` before fix: failed because base href was empty
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/server -run 'TestPublicIndexHonorsForwardedPrefixBase|TestServerServesStaticAssetsAndAdminBoot|TestBuildDefaultPublicConfigHonorsForwardedPrefix|TestForwardedPrefix' -count=1 -v`
- `node --test internal/server/web/public-assets.test.mjs`

## 2026-06-08 / Exact latest GitHub and Docker Actions

### MAGI 审视

- 官方 release API 查询时间：2026-06-08 14:06:22 CST +0800。
- workflow 已提升到最新 major，但 `actions/checkout@v6`、`actions/cache/restore@v4`、`docker/build-push-action@v7` 这类 major-only ref 不能证明当前使用的是官方最新 patch release。
- 该问题属于 latest components 收口，不需要深度重构 GitHub Actions；直接把现有 `uses:` 行固定到当前 latest tag，并用静态测试防止退回 major-only。

### MAGI 执行

- `.github/workflows/build-release.test.mjs`
  - 新增 `workflow pins action steps to current exact release tags`。
  - 锁定当前官方 latest action refs：
    - `actions/checkout@v6.0.3`
    - `actions/setup-go@v6.4.0`
    - `actions/cache/restore@v5.0.5`
    - `actions/cache/save@v5.0.5`
    - `actions/upload-artifact@v7.0.1`
    - `actions/download-artifact@v8.0.1`
    - `actions/setup-node@v6.4.0`
    - `docker/setup-qemu-action@v4.1.0`
    - `docker/setup-buildx-action@v4.1.0`
    - `docker/login-action@v4.2.0`
    - `docker/build-push-action@v7.2.0`
- `.github/workflows/build-release.yml`
  - 只替换 `uses:` tag。
  - 保持 job 拓扑、权限、命令和 artifact/cache 语义不变。

### MAGI 提升

- latest component 目标现在有静态回归测试支撑，不再依赖人工扫 `uses:` 行。
- 该测试会在下一次官方 release 出现后提醒更新 exact tag；这是可预期的维护成本。

### 验证记录

- `node --test .github/workflows/build-release.test.mjs` before fix: failed because `actions/checkout` still used `v6` while the expected latest exact tag was `v6.0.3`
- `node --test .github/workflows/build-release.test.mjs`

## 2026-06-08 / Review-driven semantic closure

### MAGI 审视

- frontend/public 子代理指出 public forwarded-prefix 覆盖只验证了 base/config 生成，没有验证不剥离 prefix 的实际 route、assets、config、ws 链路。
- scripts/workflow 子代理指出 Node 仍只 pin major `26`，不能证明使用当前 Node latest `26.3.0`。
- scripts/workflow 子代理指出 Windows agent 成功更新既有服务时仍硬编码 `start= auto`，只在 rollback 分支恢复 StartMode。
- backend/updater 子代理指出 Docker replacement ready 后旧容器 cleanup 会吞掉所有 `ContainerRemove` 错误；NotFound 可以忽略，但权限、daemon、deadline 错误不应报告完全成功。
- admin prefix 子代理指出 admin API/WS 只测了 base path normalization，没直接执行 `apiPath()` / `adminSocketURL()` 组合。

### MAGI 执行

- `Dockerfile`
  - `NODE_IMAGE_VERSION` 从 `26` 精确到 `26.3.0`。
- `.github/workflows/build-release.test.mjs`
  - 新增 Node exact version 静态断言，避免退回 major-only channel。
- `scripts/agent.ps1`
  - 既有 Windows service 成功更新时复用 `ConvertTo-ScStartMode`。
  - 对先前 disabled 的服务临时用 `demand` 完成启动，再恢复 `disabled`。
  - 新建服务仍按安装语义使用 `auto`。
- `scripts/agent-ps1.test.mjs`
  - 新增成功更新路径的 StartMode preservation 静态测试。
- `internal/updater/docker_managed.go`
  - replacement ready 后不再丢弃 cleanup 返回值。
  - `cleanupOldContainerAfterReplacement` 只忽略 `errdefs.IsNotFound`；其他 remove 错误返回 `清理旧容器失败`。
- `internal/updater/docker_managed_test.go`
  - 拆分 NotFound 忽略和非 NotFound 返回错误两个测试。
- `internal/server/server.go`
  - 新增 `stripForwardedPrefixPath`。
  - 当请求带有效 `X-Forwarded-Prefix` 且 path 未被反代剥离时，在进入 mux 前剥离 prefix；config/base 生成仍保留 prefix。
  - public server 和 split admin server 都使用该 wrapper。
- `internal/server/server_routes_test.go`
  - 新增 `TestPublicRoutesHonorUnstrippedForwardedPrefix`，覆盖 `/cm/`、`/cm/assets/monitor.js`、`/cm/config.json`、`ws://.../cm/ws`。
- `internal/server/web/admin-api.test.mjs`
  - 新增 VM 行为测试，直接执行 `apiPath()` 和 `adminSocketURL()`，验证 boot base path 进入 admin fetch/ws。

### MAGI 提升

- latest component 不再停留在 latest major，而是把 Node 和 Actions 都固定到当前官方 exact release。
- Docker managed update 对“更新成功但旧容器清理失败”的状态不再沉默；调用方可以看到 cleanup 失败。
- forwarded-prefix 现在同时支持 strip-prefix 和 non-strip-prefix 两类常见反代形态，且没有改浏览器端 fallback。
- Windows 成功更新路径和 rollback 路径统一使用同一套 StartMode 转换规则，降低管理员手动 StartMode 被覆盖的风险。

### 验证记录

- `node --test .github/workflows/build-release.test.mjs` before Node fix: failed because `NODE_IMAGE_VERSION` was `26`, expected `26.3.0`
- `node --test .github/workflows/build-release.test.mjs`
- `node --test scripts/agent-ps1.test.mjs` before StartMode fix: failed because existing service success branch still used `start= auto`
- `node --test scripts/agent-ps1.test.mjs`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -run 'TestCleanupOldContainerAfterReplacement' -count=1 -v` before cleanup fix: failed because non-NotFound remove error returned nil
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -run 'TestCleanupOldContainerAfterReplacement' -count=1 -v`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/server -run TestPublicRoutesHonorUnstrippedForwardedPrefix -count=1 -v` before route fix: failed with 404 for `/cm/`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/server -run 'TestPublicRoutesHonorUnstrippedForwardedPrefix|TestPublicIndexHonorsForwardedPrefixBase|TestBuildDefaultPublicConfigHonorsForwardedPrefix|TestServerServesStaticAssetsAndAdminBoot|TestForwardedPrefix' -count=1 -v`
- `node --test internal/server/web/admin-api.test.mjs`

## 2026-06-08 / Final verification pass

### MAGI 审视

- 子代理复核、review feedback、本地 completion audit 后，本轮剩余 must-fix/important 已完成代码或测试收口。
- `/tmp` 曾被历史 Go cache 填满，导致 sandbox bubblewrap mount 报 no space；清理 `/tmp/cm-*` Go/Node 临时 cache 后恢复验证。

### MAGI 执行

- 未新增功能改动。
- 只补记最终验证证据。

### MAGI 提升

- 后续遇到 sandbox no space 时，先 `df -h /tmp /SourceCode/CyberMonitor` 和 `du -sh /tmp/cm-*` 定位，优先清理可重建 cache，避免误判测试失败。

### 验证记录

- `scripts/verify-local.sh`
  - Node tests: 27 pass
  - admin `tsc --noEmit`: pass
  - admin `vite build`: pass
  - Go `vet` / `test ./...`: pass
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`
- `grep -nE 'uses: .+@(v[0-9]+)$|actions/cache/(restore|save)@v4|docker/.+@v[0-9]+$' .github/workflows/build-release.yml .github/workflows/build-release.test.mjs`
  - no output
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
  - `{}`

## 2026-06-08 / Active-goal recheck 20:48 CST

### MAGI 审视

- Goal 再次进入 active continuation 后，重新读取当前 goal、worktree diff 和验证入口。
- 当前 diff 与上一轮完成态一致，未发现新漂移；`git diff --check` 仍无输出。
- 同一目标下此前 backend/frontend/scripts 只读子代理被上游 `403/503` 拦截，本轮不重复派发；改用当前本地验证覆盖同等审计范围。

### MAGI 执行

- 未新增产品代码改动。
- 刷新全局验证、非缓存 race、latest 组件和 npm outdated 证据。

### MAGI 提升

- 对重复 active continuation，当前证据没有变化时不继续改代码；只补充最小审计记录并关闭 goal，避免制造冗余实现。

### 验证记录

- `scripts/verify-local.sh`
  - Node tests: 29 pass
  - `npm ci`: 0 vulnerabilities
  - admin `tsc --noEmit`: pass
  - admin `vite build`: pass
  - Go `vet` / `test ./...`: pass
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - pass
- `node -e ... https://go.dev/dl/?mode=json https://nodejs.org/dist/index.json`
  - Go latest stable: `1.26.4`
  - Node latest: `26.3.0` (`2026-06-01`)
- `git ls-remote --tags --refs` latest action tags:
  - `actions/checkout v6.0.3`
  - `actions/setup-go v6.4.0`
  - `actions/setup-node v6.4.0`
  - `actions/cache v5.0.5`
  - `actions/upload-artifact v7.0.1`
  - `actions/download-artifact v8.0.1`
  - `docker/setup-qemu-action v4.1.0`
  - `docker/setup-buildx-action v4.1.0`
  - `docker/login-action v4.2.0`
  - `docker/build-push-action v7.2.0`
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
  - `{}`

## 2026-06-08 / Active-goal recheck 18:37 CST

### MAGI 审视

- Goal 再次进入 active continuation 后，重新读取当前 goal、worktree diff 和验证入口。
- 当前 diff 未出现新漂移；`git diff --check` 仍无输出。
- 上一轮已记录子代理上游 `403/503`，本轮不重复派发同类只读子代理，改用本地主线复核当前证据。

### MAGI 执行

- 未新增产品代码改动。
- 刷新全局验证、非缓存 race、latest 组件和 npm outdated 证据。

### MAGI 提升

- 对重复 active continuation，只有当前证据发生变化才继续改代码；否则保持实现不变，只刷新审计证据并关闭 goal。

### 验证记录

- `scripts/verify-local.sh`
  - Node tests: 29 pass
  - `npm ci`: 0 vulnerabilities
  - admin `tsc --noEmit`: pass
  - admin `vite build`: pass
  - Go `vet` / `test ./...`: pass
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - pass
- `node -e ... https://go.dev/dl/?mode=json https://nodejs.org/dist/index.json`
  - Go latest stable: `1.26.4`
  - Node latest: `26.3.0` (`2026-06-01`)
- `git ls-remote --tags --refs` latest action tags:
  - `actions/checkout v6.0.3`
  - `actions/setup-go v6.4.0`
  - `actions/setup-node v6.4.0`
  - `actions/cache v5.0.5`
  - `actions/upload-artifact v7.0.1`
  - `actions/download-artifact v8.0.1`
  - `docker/setup-qemu-action v4.1.0`
  - `docker/setup-buildx-action v4.1.0`
  - `docker/login-action v4.2.0`
  - `docker/build-push-action v7.2.0`
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
  - `{}`
- `docker ps -a --filter name=cm-docker-helper-smoke --format '{{.Names}} {{.Status}}'`
  - no output
- `docker network ls --filter name=cm-docker-helper-net --format '{{.Name}}'`
  - no output
- `df -h /tmp /SourceCode/CyberMonitor`
  - `/tmp`: 1.9G available
  - `/SourceCode/CyberMonitor`: 90G available

## 2026-06-08 / Public fallback baseURI closure

### MAGI 审视

- frontend 子代理指出：服务端已经支持 `X-Forwarded-Prefix: /cm` 下的 `/cm` 无尾斜杠入口，但 public fallback 仍从 `location.href` 推导 base。
- 在 `https://example.test/cm` 且 config 加载失败时，浏览器端 fallback 会把 API/WS 推导到 root，而不是 `/cm`。
- 服务端注入的 `<base href="/cm/" />` 已经是浏览器当前页面的权威资源基准，fallback 应使用 `document.baseURI`。

### MAGI 执行

- `internal/server/web/public-assets.test.mjs`
  - 新增 `public fallback target follows the document base URI`。
  - RED：`document.baseURI=https://example.test/cm/`、`location.href=https://example.test/cm` 时，fallback `apiBase` 仍为 `https://example.test`。
- `internal/server/web/public/assets/monitor.js`
  - `buildFallbackTarget()` 默认参数从 `location.href` 改为 `document.baseURI || location.href`。
  - 不新增多路径兼容包装；统一以 document base 作为 fallback 基准。

### MAGI 提升

- 当 HTML 通过 `<base>` 统一相对路径语义时，JS fallback 也必须使用同一 document base，不能重新从 URL path 猜测。

### 验证记录

- `node --test internal/server/web/public-assets.test.mjs` before fix: failed because fallback `apiBase` was `https://example.test`, expected `https://example.test/cm`
- `node --test internal/server/web/public-assets.test.mjs`

## 2026-06-08 / Docker self-update detached helper closure

### MAGI 审视

- backend 子代理指出：Docker managed self-update 的调用方使用可等待 helper。
- 对正在更新的父容器来说，helper 停止目标容器后父进程通常会退出，调用方不应依赖 stop 后的 wait 返回。
- 服务端和 Agent 的生产路径应只负责成功启动 detached helper，然后把容器重建交给 Docker/helper。

### MAGI 执行

- `internal/agent/agent_update_test.go`
  - 新增 Docker managed update 测试，要求失败路径报告 launch error，成功路径在上报 restarting 前只启动 detached helper。
  - RED：当前实现调用 wait helper，`detached=0 waited=1`。
- `internal/server/update_assets_test.go`
  - 新增静态约束，禁止服务端生产路径继续引用 `LaunchSelfContainerUpdateAndWait`。
  - RED：`server.go` 仍包含 wait helper 调用。
- `internal/agent/agent.go`、`internal/server/server.go`、`internal/server/system_update.go`、`internal/updater/docker_managed.go`
  - 生产路径统一调用 `LaunchSelfContainerUpdate`。
  - 移除公开的 `LaunchSelfContainerUpdateAndWait` 冗余表面，保留内部 helper wait 测试能力。

### MAGI 提升

- self-container update 不能把“启动 helper”和“等待父容器被停止后的结果”混成一个同步成功条件。
- 调用方只报告 helper launch 结果，后续容器生命周期由 detached helper 接管。

### 验证记录

- `go test ./internal/agent -run 'TestMaybeApplyRemoteDockerUpdate' -count=1 -v` before fix: failed because success path used wait helper instead of detached helper.
- `go test ./internal/server -run TestDockerManagedSystemUpdateLaunchesDetachedHelper -count=1 -v` before fix: failed because `server.go` still referenced `LaunchSelfContainerUpdateAndWait`.
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test ./internal/agent -run 'TestMaybeApplyRemoteDockerUpdate' -count=1 -v`
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test ./internal/server -run TestDockerManagedSystemUpdateLaunchesDetachedHelper -count=1 -v`

## 2026-06-08 / Proxy header trust boundary closure

### MAGI 审视

- backend 子代理指出：`X-Forwarded-Prefix` 默认被直连请求信任。
- 这不是外部跳转漏洞，但会让直连请求改写 public config、admin redirect、admin boot base path 和 prefix stripping 语义。
- `X-Forwarded-Proto` 也属于同一代理信任边界；否则直连请求可以影响 Secure-cookie 判断和 public scheme 推导。

### MAGI 执行

- `server.Config` 新增 `TrustedProxyHeaders`，默认 false。
- `cmd/server` 新增 `--trust-proxy-headers` / `CM_TRUST_PROXY_HEADERS`。
- `forwardedPrefix`、`buildDefaultPublicConfig`、`stripForwardedPrefixPath`、`forwardedPrefixedPath`、admin boot payload、admin session cookie Secure 判断统一接入显式 trust。
- 反代测试显式打开 `TrustedProxyHeaders`；默认关闭测试验证直连 header 不再生效。

### MAGI 提升

- 代理头只应在明确部署在可信反向代理之后时启用。
- 反代子路径能力保留，但不再作为默认直连行为暴露。

### 验证记录

- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test ./internal/server -run TestPublicRoutesIgnoreForwardedPrefixByDefault -count=1 -v` before fix: failed because public index still trusted `X-Forwarded-Prefix` by default.
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test ./internal/server -run 'TestPublicRoutesIgnoreForwardedPrefixByDefault|TestPublicIndexHonorsForwardedPrefixBase|TestPublicRoutesHonorUnstrippedForwardedPrefix|TestBuildDefaultPublicConfigHonorsForwardedPrefix|TestForwardedPrefix|TestRequestIsSecureRequiresTrustedProxyHeaders|TestAdminPathRedirectHonorsForwardedPrefix|TestAdminBootPayloadHonorsForwardedPrefix' -count=1 -v`

## 2026-06-08 / Final verification refresh after proxy trust closure

### MAGI 审视

- Docker detached helper、public fallback baseURI、proxy header trust boundary 均已完成 RED/GREEN。
- 重新刷新官方版本源，Go/Node/Actions pin 与当前 latest 一致。
- GitHub REST latest API 在本轮刷新中对 `docker/setup-buildx-action` 返回 403，因此切换到公开 `git ls-remote --tags --refs` 顺序读取 tags，避免继续撞 REST rate limit。

### MAGI 执行

- 未新增功能改动。
- 补充最终验证证据，覆盖局部测试、全局脚本、race、版本 pin、diff 和残留检查。

### MAGI 提升

- 对 GitHub Actions latest tag 的验证，公开 tag 列表比 REST latest API 更适合无 token 环境。
- 对代理部署能力，默认关闭信任边界比默认信任 header 更符合直连安全预期。

### 验证记录

- `node --test internal/server/web/public-assets.test.mjs`
  - 4 pass
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test ./internal/agent -run 'TestMaybeApplyRemoteDockerUpdate' -count=1 -v`
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test ./internal/server -run 'TestDockerManagedSystemUpdateLaunchesDetachedHelper|TestPublicRoutesIgnoreForwardedPrefixByDefault|TestPublicIndexHonorsForwardedPrefixBase|TestPublicRoutesHonorUnstrippedForwardedPrefix|TestBuildDefaultPublicConfigHonorsForwardedPrefix|TestForwardedPrefix|TestRequestIsSecureRequiresTrustedProxyHeaders|TestAdminPathRedirectHonorsForwardedPrefix|TestAdminBootPayloadHonorsForwardedPrefix' -count=1 -v`
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test ./internal/updater -run 'TestLaunchDockerUpdateHelper|TestCleanupOldContainerAfterReplacement' -count=1 -v`
- `scripts/verify-local.sh`
  - Node tests: 28 pass
  - admin `tsc --noEmit`: pass
  - admin `vite build`: pass
  - Go `vet` / `test ./...`: pass
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- `git diff --check`
- `grep -nE 'uses: .+@(v[0-9]+)$|actions/cache/(restore|save)@v[0-9]+$|docker/.+@v[0-9]+$' .github/workflows/build-release.yml .github/workflows/build-release.test.mjs`
  - no output
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
  - `{}`
- `docker ps -a --filter name=cm-docker-helper-smoke --format '{{.Names}} {{.Status}}'`
  - no output
- `docker network ls --filter name=cm-docker-helper-net --format '{{.Name}}'`
  - no output
- `node -e ... https://go.dev/dl/?mode=json https://nodejs.org/dist/index.json`
  - Go latest stable: `1.26.4`
  - Node latest: `26.3.0` (`2026-06-01`)
- `git ls-remote --tags --refs` latest action tags:
  - `actions/checkout v6.0.3`
  - `actions/setup-go v6.4.0`
  - `actions/setup-node v6.4.0`
  - `actions/cache v5.0.5`
  - `actions/upload-artifact v7.0.1`
  - `actions/download-artifact v8.0.1`
  - `docker/setup-qemu-action v4.1.0`
  - `docker/setup-buildx-action v4.1.0`
  - `docker/login-action v4.2.0`
  - `docker/build-push-action v7.2.0`
- `df -h /tmp /SourceCode/CyberMonitor`
  - `/tmp`: 1.6G available
  - `/SourceCode/CyberMonitor`: 89G available

## 2026-06-08 / Docker helper dead-path cleanup

### MAGI 审视

- 本轮从当前 worktree 重新审视，不把旧验证记录当 completion 证据。
- Go 官方 `VERSION?m=text` 显示当前稳定版本为 `go1.26.4`；Node 官方 dist index 顶部版本为 `v26.3.0`。
- `npm outdated --json --cache /SourceCode/CyberMonitor/.cache/npm` 返回 `{}`；首次默认 cache 指向只读 `/root/.npm` 的失败是环境 cache 问题，不是依赖版本事实。
- Docker self-container update 的产品路径已经统一为 detached helper，这是正确方向：helper 会停止当前容器，父进程不能把“等待 helper 完整退出”作为可靠成功条件。
- 但 updater 内仍保留只被测试调用的 `launchDockerUpdateHelper` wait helper、wait-only interface 和 fake client，形成死代码与冗余验证路径。

### MAGI 执行

- `internal/updater/docker_managed.go`
  - 删除未被生产路径调用的 wait helper 和 `dockerUpdateHelperWaitClient`。
  - 保留唯一产品路径 `LaunchSelfContainerUpdate -> launchDockerUpdateHelperDetached`。
- `internal/updater/docker_managed_test.go`
  - 删除只覆盖 wait helper 的 fake client 和两条 wait-only 测试。
  - 保留 rollback、replacement readiness、healthcheck、network config 等真实产品路径相关测试。

### MAGI 提升

- 自更新代码要避免“测试很绿但产品路径不用”的假安全感。
- detached helper 是当前唯一直接路径；如果未来要观测 helper 结果，应通过 helper/container 日志或外部状态回传，不应让即将被停止的父容器同步等待。
- 下一轮继续 whole-diff review，优先检查 detached helper `ContainerStart` 失败后的 helper 容器清理、Docker daemon opt-in smoke、以及 admin/public runtime 子路径。

### 验证记录

- `scripts/verify-local.sh`
  - Node regression: 29 pass
  - admin `tsc --noEmit`: pass
  - admin `vite build`: pass
  - Go `vet` / `test ./...`: pass
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -count=1`
  - pass
- `grep -R "launchDockerUpdateHelper\|dockerUpdateHelperWaitClient\|helperLaunchClient\|ContainerWait" -n internal/updater ...`
  - only `launchDockerUpdateHelperDetached` remains.
- `git diff --check`
  - no output

## 2026-06-08 / Detached helper start-failure cleanup

### MAGI 审视

- `launchDockerUpdateHelperDetached` 已是 Docker self-container update 的唯一产品路径。
- 该路径在 `ContainerCreate` 成功、`ContainerStart` 失败时直接返回错误；未启动容器不会触发 Docker `AutoRemove`。
- 结果是 helper 可能停留在 created 状态，下一次更新还会因为同名 helper 冲突或残留容器增加排障成本。
- 这不是兼容问题，而是主路径副作用清理缺口。

### MAGI 执行

- `internal/updater/docker_managed.go`
  - `dockerUpdateHelperClient` 增加 `ContainerRemove`。
  - `launchDockerUpdateHelperDetached` 在 start failure 时 force remove 已创建 helper。
  - 若清理也失败，错误同时包含 start failure 和 cleanup failure。
- `internal/updater/docker_managed_test.go`
  - 新增 start failure 清理回归测试。
  - 新增 cleanup failure 错误传播测试。

### MAGI 提升

- detached 主路径仍然保持单一路径：create -> start -> hand off。
- 只补启动失败前的本地副作用清理，不重新引入 wait helper。
- 下一轮继续查 updater 真实 Docker daemon opt-in smoke 与 runtime 子路径 smoke，避免只靠静态断言完成目标。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -run 'TestLaunchDockerUpdateHelperDetached|TestCleanupOldContainerAfterReplacement|TestRollbackCreatedContainer' -count=1 -v`
  - pass

## 2026-06-08 / Active-goal recheck

### MAGI 审视

- Goal 再次进入 active continuation 后，重新检查当前 worktree。
- 当前 diff 仍是同一批优化改动；未发现新的代码缺口。
- 本次不再重复派发子代理：上一轮三个只读子代理均被上游 403/503 拦截，本地主线已经覆盖同等审计范围。

### MAGI 执行

- 未新增产品代码改动。
- 刷新验证证据并记录当前时间点：`2026-06-08 18:15:00 CST +0800`。

### MAGI 提升

- 对重复 active-goal continuation，先用当前命令输出确认状态；如果代码和验证证据没有漂移，就只补最小审计记录，避免制造冗余兼容或重复实现。

### 验证记录

- `git diff --check`
  - no output
- `scripts/verify-local.sh`
  - Node tests: 29 pass
  - `npm ci`: 0 vulnerabilities
  - admin `tsc --noEmit`: pass
  - admin `vite build`: pass
  - Go `vet` / `test ./...`: pass
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
  - pass
- `node -e ... https://go.dev/dl/?mode=json https://nodejs.org/dist/index.json`
  - Go latest stable: `1.26.4`
  - Node latest: `26.3.0` (`2026-06-01`)
- `git ls-remote --tags --refs` latest action tags:
  - `actions/checkout v6.0.3`
  - `actions/setup-go v6.4.0`
  - `actions/setup-node v6.4.0`
  - `actions/cache v5.0.5`
  - `actions/upload-artifact v7.0.1`
  - `actions/download-artifact v8.0.1`
  - `docker/setup-qemu-action v4.1.0`
  - `docker/setup-buildx-action v4.1.0`
  - `docker/login-action v4.2.0`
  - `docker/build-push-action v7.2.0`
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
  - `{}`

## 2026-06-08 / Minor frontend review closure

### MAGI 审视

- frontend 子代理剩余两个 minor：
  - public `<base href="/cm/" />` 会影响 skip link 的 fragment 解析。
  - admin 删除节点 partial-success 只展示历史清理错误，用户看不到“节点已删除”的语义。

### MAGI 执行

- `internal/server/web/public/index.html` 给 `#public-main-content` 增加 `tabindex="-1"`。
- `internal/server/web/public/assets/theme.js` 拦截 skip link click，在当前 document 内 `preventDefault`、`scrollIntoView` 并聚焦 main。
- `internal/server/web/admin/src/App.tsx` 将 partial-success warning 改为 `节点已删除，但...`。

### MAGI 提升

- 当页面使用 `<base>` 修正子路径资源时，fragment 导航不能再依赖浏览器默认解析。
- partial-success 文案必须同时表达已完成动作和剩余失败项。

### 验证记录

- `node --test internal/server/web/public-assets.test.mjs` before fix: failed because main missing `tabindex="-1"` and skip link had no current-document click handler.
- `node --test internal/server/web/admin-delete-node.test.mjs` before fix: failed because warning still used `result.history_error` directly.
- `node --test internal/server/web/public-assets.test.mjs`
  - 5 pass
- `node --test internal/server/web/admin-delete-node.test.mjs`
  - 1 pass
- `scripts/verify-local.sh`
  - Node tests: 29 pass
  - admin `tsc --noEmit`: pass
  - admin `vite build`: pass
  - Go `vet` / `test ./...`: pass

## 2026-06-08 / Continuation completion audit refresh

### MAGI 审视

- Goal continuation 再次变为 active 后，本轮不复用旧口头结论，重新以当前 worktree 和 fresh command output 做 completion audit。
- 新派发的 backend/frontend/scripts 只读子代理均被上游服务拦截：
  - scripts/workflow 子代理：`503 Service Unavailable`。
  - backend 子代理：`403 Forbidden`。
  - frontend 子代理：`403 Forbidden`。
- 子代理失败属于外部 agent service 故障，不作为产品代码风险；本轮用本地主线审计补齐三个域：
  - backend/server/updater：Docker detached helper、trusted proxy headers、delete/history partial success、configRefresh。
  - frontend/admin/public：public base/fallback/skip link、admin base path、delete partial-success toast。
  - scripts/workflow/latest：Go/Node/Actions exact pin、one-click data ownership、Windows StartMode、verify-local。

### MAGI 执行

- 未新增产品代码改动。
- 补充 fresh 验证证据，确认当前 diff 仍满足目标要求。

### MAGI 提升

- 子代理结果只能作为增强证据；当上游不可用时，不能把失败包装成 review success，也不能因此停住主线。
- 对 completion audit，当前命令输出、当前文件和当前 diff 比旧 summary 更权威。

### 验证记录

- `git status --short`
  - 当前 worktree 仍包含预期 tracked 修改和新增测试/日志文件。
- `git diff --stat`
  - 22 tracked files changed, `1989 insertions(+), 1253 deletions(-)`；新增测试和 `evolution_log.md` 为 untracked。
- `git diff --check`
  - no output
- `scripts/verify-local.sh`
  - Node tests: 29 pass
  - `npm ci`: 0 vulnerabilities
  - admin `tsc --noEmit`: pass
  - admin `vite build`: pass
  - Go `vet` / `test ./...`: pass
- `GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
  - pass
- `node -e ... https://go.dev/dl/?mode=json https://nodejs.org/dist/index.json`
  - Go latest stable: `1.26.4`
  - Node latest: `26.3.0` (`2026-06-01`)
- `git ls-remote --tags --refs` latest action tags:
  - `actions/checkout v6.0.3`
  - `actions/setup-go v6.4.0`
  - `actions/setup-node v6.4.0`
  - `actions/cache v5.0.5`
  - `actions/upload-artifact v7.0.1`
  - `actions/download-artifact v8.0.1`
  - `docker/setup-qemu-action v4.1.0`
  - `docker/setup-buildx-action v4.1.0`
  - `docker/login-action v4.2.0`
  - `docker/build-push-action v7.2.0`
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
  - `{}`
- `grep -nE 'uses: .+@(v[0-9]+)$|actions/cache/(restore|save)@v[0-9]+$|docker/.+@v[0-9]+$' .github/workflows/build-release.yml .github/workflows/build-release.test.mjs`
  - no output
- `grep -R "LaunchSelfContainerUpdateAndWait" -n internal ...`
  - only `internal/server/update_assets_test.go` contains the forbidden-production-path assertion.
- `df -h /tmp /SourceCode/CyberMonitor`
  - `/tmp`: 1.6G available
  - `/SourceCode/CyberMonitor`: 89G available

## 2026-06-08 / Runtime smoke trust-boundary refresh

### MAGI 审视

- 旧 runtime smoke 记录默认把 `X-Forwarded-Prefix` 当成始终生效，但当前代码默认不信任 proxy headers。
- 正确验证必须拆成两组：默认直连模式确认 forwarded prefix 被忽略，`CM_TRUST_PROXY_HEADERS=1` 模式确认反代前缀生效。
- `scripts/verify-local.sh` 是构建和静态/单元验证入口，不等同于真实 runtime smoke。
- admin asset 文件名带 hash，smoke 不能固定写死文件名；应从当前 admin HTML 解析相对 `./assets/...`。

### MAGI 执行

- `CM_TRUST_PROXY_HEADERS=1` 模式：
  - 使用临时数据目录 `/tmp/cm-runtime-smoke-random` 和随机 admin path `/HIXMBes3gtxS` 启动 server。
  - 验证 `/api/v1/health`、`/config.json`、public HTML、admin redirect、admin HTML、admin asset、root WebSocket 和 `/cm` 前缀 WebSocket。
  - 验证 `/cm/` public HTML 注入 `<base href="/cm/" />`，`/cm/HIXMBes3gtxS/` admin boot payload 注入 `base_path=/cm`。
  - 使用 headless Chrome dump DOM 验证 public 页面和 admin login 页面能加载到实际 DOM。
- 默认直连模式：
  - 使用临时数据目录 `/tmp/cm-runtime-smoke-default`、固定 admin path `/admin-smoke` 启动 server。
  - 验证 forwarded prefix header 被忽略：`/config.json` 仍返回 root API/WS，`/admin-smoke` redirect 到 `/admin-smoke/`，`/cm/` 返回 404。
  - 验证 admin HTML 使用当前构建生成的相对 `./assets/...`，boot meta 不包含 proxy `base_path`。
  - 验证 `/admin-smoke/assets/index-Do7YyGUc.js` 返回 200，root `/ws` 返回 WebSocket `101 Switching Protocols`。
- 两组 smoke 使用的临时 server 均已停止，临时数据目录已清理。

### MAGI 提升

- runtime smoke 后续应脚本化，并显式包含 default direct、trusted proxy 和 split mode 三类入口。
- WebSocket smoke 使用 `curl -N` 时应设置短 timeout；看到 `101 Switching Protocols` 后超时退出是预期行为。
- headless Chrome 在当前 sandbox 会输出只读 `/root/.config`、dconf、fontconfig warning；判断依据应是进程退出码和实际 DOM，而不是这些环境 warning。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp CM_LISTEN=127.0.0.1:25215 CM_DATA_DIR=/tmp/cm-runtime-smoke-random CM_TRUST_PROXY_HEADERS=1 go run ./cmd/server`
- `curl` against `http://127.0.0.1:25215/api/v1/health`, `/config.json`, `/`, `/cm/`, `/HIXMBes3gtxS`, `/cm/HIXMBes3gtxS`, `/HIXMBes3gtxS/`, `/cm/HIXMBes3gtxS/`, and current admin asset paths.
- `timeout 2s curl -s -i -N` against root `/ws` and trusted-prefix `/cm/ws`; both reached `101 Switching Protocols`.
- `google-chrome --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage --dump-dom` for public and admin pages on port 25215.
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp CM_LISTEN=127.0.0.1:25216 CM_DATA_DIR=/tmp/cm-runtime-smoke-default CM_ADMIN_PATH=/admin-smoke CM_ADMIN_USER=admin CM_ADMIN_PASS=Admin123456! CM_JWT_SECRET=smoke-jwt-secret CM_AGENT_TOKEN=smoke-agent-token go run ./cmd/server`
- `curl` against `http://127.0.0.1:25216/api/v1/health`, `/`, `/config.json`, `/admin-smoke`, `/cm/`, `/admin-smoke/`, `/admin-smoke/assets/index-Do7YyGUc.js`, and `/ws`.
- `lsof -nP -iTCP:25216 -sTCP:LISTEN` after cleanup returned no listener; `/tmp/cm-runtime-smoke-default` no longer exists.

## 2026-06-08 / Split runtime startup hardening

### MAGI 审视

- split mode 下 admin server 原本在 goroutine 中 `ListenAndServe`，主线程随后阻塞在 public server。
- 如果 admin 端口绑定失败，错误要等 public server 退出后才会被读取，实际表现是 public 端半启动、admin 端不可用。
- 这不是兼容问题，而是启动原子性问题；两端口模式必须要么双端都启动，要么立即失败。
- split mode 之前只有 admin public snapshot 的局部测试，没有锁住 public/admin 双端口职责隔离和 admin WebSocket 鉴权边界。

### MAGI 执行

- `internal/server/server.go`
  - split mode 改为先同步 `net.Listen` admin/public 两个 listener，再分别 `Serve`。
  - 任一 listener 绑定失败会立即返回错误，不再启动另一端。
  - 任一 server 运行中返回非 shutdown 错误时，主动 shutdown 另一端并返回原始错误。
- `internal/server/server_routes_test.go`
  - 新增 admin 端口被占用时必须快速返回错误、public 端不得半启动的回归测试。
  - 新增 split runtime 隔离测试，覆盖 public `/config.json`、public `/ws`、admin `/ws` 未授权拒绝、admin login cookie 授权 WebSocket、public 端不暴露 admin app。

### MAGI 提升

- 多 listener server 的启动路径应先完成全部 bind，再进入 serve loop；否则会产生半启动状态。
- split mode 的核心契约是端口职责隔离，不应只靠手工 runtime smoke 验证。
- 下一轮可继续把 split mode 加入脚本化 runtime smoke，但程序级回归测试已经先锁住关键边界。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/server -run 'TestSplit(ServerSeparatesPublicAndAdminRuntime|ServerReturnsAdminBindErrorBeforeServingPublic|AdminServerServesPublicSnapshotForAdminApp)' -count=1 -v`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/server -run 'Test(UnifiedServerServesAdminAPI|ServerServesStaticAssetsAndAdminBoot|PublicRoutesHonorUnstrippedForwardedPrefix|AdminBootPayloadHonorsForwardedPrefix|AdminPathRedirectHonorsForwardedPrefix)' -count=1`

## 2026-06-08 / Docker rollback network cleanup

### MAGI 审视

- Docker recreate helper 会先创建替换容器，再把附加网络逐个 `NetworkConnect` 到新容器。
- 如果其中一个附加网络连接失败，旧逻辑只删除替换容器并恢复旧容器状态，没有显式断开已经连接成功的附加网络。
- Docker 删除容器通常会清理 endpoint，但 rollback 路径不应依赖隐式副作用；外部副作用已经发生，就应记录并按反向顺序撤销。

### MAGI 执行

- `internal/updater/docker_managed.go`
  - `dockerContainerRollbackClient` 增加 `NetworkDisconnect`。
  - `RunDockerRecreateHelper` 记录已经成功连接的附加网络。
  - `rollbackCreatedContainer` 在删除替换容器前，按反向顺序显式断开已连接附加网络。
  - 断网失败会进入 rollback error 聚合，不阻止继续删除替换容器和恢复旧容器。
- `internal/updater/docker_managed_test.go`
  - 更新 rollback fake client。
  - 新增附加网络 rollback 顺序测试。
  - 新增附加网络断开失败错误聚合测试。

### MAGI 提升

- Docker update rollback 要按已完成副作用的反向顺序清理：网络连接、替换容器、旧容器名称、旧容器运行态。
- 不要把 Docker daemon 的隐式资源清理当作业务 rollback 语义。
- 下一轮可继续补真实 daemon smoke 的失败路径，但单元级状态机已经先锁住顺序。

### 验证记录

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -run 'TestRollbackCreatedContainer|TestAppendRollbackError|TestCleanupOldContainerAfterReplacement' -count=1 -v`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -count=1`

## 2026-06-08 / Agent update state convergence

### MAGI 审视

- Agent 远程更新收到目标版本后，原先用字符串相等判断“当前已是目标版本”。
- 这会把 `1.2.3` 和 `v1.2.3` 视为不同版本，触发一次无意义的 Docker helper 或二进制自更新。
- 但 `CompareVersions` 对非数字版本会解析为 `0.0.0`，不能直接把 `unknown` 和 `v0.0.0` 判等。
- Server 的 update report 匹配和 stats 自动收口也属于“同一目标版本”判断，不能继续裸用 `CompareVersions`。
- Agent 执行去重使用 instruction signature，但 terminal report 去重只看 `state+version`；同版本不同 `RequestedAt` 的手动重试失败时，第二次 failed report 会被吞掉，server 无法收口失败状态。

### MAGI 执行

- `internal/updater/updater.go`
  - 新增 `VersionsEqual`，集中处理版本等价语义。
  - 字符串完全相等直接判等。
  - 双方都包含数字版本时，才使用 `CompareVersions` 判等。
  - 任一方为空或纯非数字版本时，不做语义判等，避免把 unknown 当成 0.0.0。
- `internal/agent/agent.go`
  - Agent 本地“当前已是目标版本”判断改用 `updater.VersionsEqual`。
- `internal/agent/runtime.go`
  - 新 instruction signature 到来时，清空上一轮 terminal report 去重状态。
  - 同一 instruction 的重复 terminal report 仍会被抑制；不同 `RequestedAt` 的手动重试会重新上报终态。
- `internal/server/server.go`
  - `reconcileAgentUpdateWithStatsLocked` 与 `agentUpdateReportMatchesPendingInstruction` 改用 `updater.VersionsEqual`。
- `internal/updater/updater_test.go`
  - 覆盖 `1.2.3` vs `v1.2.3`、预发布基础版本、纯文本版本、`unknown` vs `v0.0.0`。
- `internal/agent/agent_update_test.go`
  - 新增 `1.2.3` vs `v1.2.3` 不触发远程更新的回归测试。
  - 新增 `unknown` vs `v0.0.0` 不应误判为已更新的回归测试。
  - 新增相同版本、不同 `RequestedAt` 的两次远程更新都必须上报 failed 的 runner 级测试。
- `internal/server/agent_update_test.go`
  - 新增 update report 接受语义等价目标版本的测试。
  - 新增 update report 和 stats 自动收口拒绝 `unknown` vs `v0.0.0` 的测试。

### MAGI 提升

- “版本排序”和“状态机等价”不是同一个 API：排序可以解析版本，等价必须拒绝未知文本。
- 语义比较必须先证明输入是版本值；未知文本不能通过数字解析 fallback 变成 0.0.0。
- Agent 执行去重与终态上报去重必须使用同一任务边界。当前任务边界是 instruction signature。
- 下一轮可继续补 server `QueueAgentUpdate -> DeliverAgentConfig -> ApplyAgentUpdateReport` 的完整 lease transition 测试。

### 验证记录

- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -run TestVersionsEqual -count=1`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'TestMaybeApplyRemoteUpdate|TestAgentRunnerReportsFailedAgainForSameVersionNewInstruction' -count=1`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentUpdateReport|TestReconcileAgentUpdateWithStats' -count=1`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater -count=1`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -count=1`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp bash scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`

## 2026-06-08 / Server agent update lease transition coverage

### MAGI 审视

- 上一轮已经修正了 agent/server 的版本等价和 terminal report 去重语义。
- 剩余缺口在 server 侧完整链路证据不足：`QueueAgentUpdate -> DeliverAgentConfig -> ApplyAgentUpdateReport` 没有一条测试串起 delivery lease、updating lease、lease 过期重下发和 terminal 收口。
- 这类状态机没有必要加兼容分支；应先用直接测试锁住当前契约，只有测试暴露缺陷时再改生产逻辑。

### MAGI 执行

- `internal/server/agent_update_test.go`
  - 新增 `TestAgentUpdateQueueDeliverReportAndRedeliverFlow`。
  - 覆盖 queue 后必须标记 `configRefresh`。
  - 覆盖首次 `DeliverAgentConfig` 必须下发 update、清理 refresh、设置 delivery lease。
  - 覆盖 delivery/updating lease 生效期间不能重复下发。
  - 覆盖 updating lease 过期后会重新下发 update 并刷新 delivery lease。
  - 覆盖 terminal failed 会清掉 `AgentUpdate` 和 lease，后续不再下发。
  - 新增 `TestAgentUpdateDeliveredTaskReconcilesSuccessFromStats`。
  - 覆盖 delivered 后 agent 通过 stats 上报目标版本时，server 自动收口为 succeeded，并停止后续下发。

### MAGI 提升

- Agent update 的 server 状态机应持续保持单一路径：queue 只建立任务，delivery lease 控制下发节奏，report/stats 两条路径负责收口。
- 测试要覆盖时间租约边界，而不是只验证单个 helper 函数。
- 下一轮可继续从 runtime 行为角度看 admin API 与 agent RPC/HTTP 两条入口是否完全共享这些 Store 契约。

### 验证记录

- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentUpdate(QueueDeliverReportAndRedeliverFlow|DeliveredTaskReconcilesSuccessFromStats|Report|Reconcile)' -count=1 -v`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`

## 2026-06-08 / Agent update instruction identity

### MAGI 审视

- 子代理只读审视指出一个高置信缺口：server 只用目标版本匹配 agent update report。
- 当管理端快速重试同一版本或同版本 asset 变化时，旧 instruction 的 late terminal report 可能被新 instruction 接受，进而错误清掉新任务。
- 当前 report 不匹配时 API 还会返回成功并广播 snapshot，agent 会以为 terminal report 已被接受，server 状态却没有变化。
- 这不是兼容性问题，而是协议缺少 instruction identity。

### MAGI 执行

- `internal/server/server.go`
  - `AgentUpdateInstruction` 新增 opaque `ID`。
  - `QueueAgentUpdate` 在未指定 ID 时生成新的随机 ID。
  - `AgentUpdateReport` 新增 `ID`。
  - report 匹配改为同时匹配 `ID` 和语义版本。
  - HTTP `/api/v1/agent/update/report` 接受 `update_id` 并传入 Store。
- `internal/server/agent_rpc.go`
  - gRPC config response 下发 update ID。
  - gRPC report request 带回 update ID。
  - 不匹配 report 返回 `409 Conflict`，gRPC 映射为 `FailedPrecondition`。
  - 只有 report 真正应用后才 broadcast snapshot。
- `internal/agentrpc/types.go`
  - `UpdateInstruction` 增加 `ID`。
  - `ReportUpdateRequest` 增加 `UpdateID`。
- `internal/agent/config.go`
  - `RemoteUpdateInstruction` 增加 `ID`。
- `internal/agent/agent.go`
  - 所有 update state report 都携带当前 instruction ID。
- `internal/agent/runtime.go`
  - update signature 纳入 ID。
  - terminal report 去重按 `updateID + state + version` 判断。
- `internal/agent/transport.go`
  - HTTP report payload 增加 `update_id`。
  - gRPC report request 增加 `UpdateID`。
- `internal/server/agent_update_test.go`
  - 新增 stale instruction ID 不能关闭同版本新任务的 Store 测试。
  - 新增 `agentAPI.reportUpdate` 对 stale report 返回 conflict 的测试。
  - 新增 conflict 到 gRPC `FailedPrecondition` 的映射测试。
- `internal/agent/agent_update_test.go`
  - 更新 fake transport 和 update 执行测试，断言不同 instruction ID 会分别上报 terminal state。

### MAGI 提升

- Agent update 状态机的任务边界必须是 instruction identity，不是 version。
- 同版本重试是正常业务动作，旧 report 必须被协议层拒绝。
- 不匹配 report 不能静默成功；显式 conflict 比假成功更利于 agent/server 自愈。

### 验证记录

- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'TestMaybeApplyRemoteUpdate|TestAgentRunnerReportsFailedAgainForSameVersionNewInstruction' -count=1 -v`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentUpdate|TestReconcileAgentUpdate|TestAgentUpdateAPI|TestAgentUpdateReportConflict' -count=1 -v`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agentrpc ./internal/agent ./internal/server ./internal/updater -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`

## 2026-06-08 / Admin agent update state hardening

### MAGI 审视

- 子代理 Boyle 只读审视确认 `NodeView`、snapshot、WebSocket delta 和 agent update GET 没有直接暴露 opaque update ID。
- 发现 3 个状态边界问题：
  - admin 重复触发 Agent update 会覆盖活跃 `AgentUpdateInstruction.ID`，导致正在执行的旧任务 report 后续被 409 拒绝。
  - admin 节点资料 PATCH 响应直接返回 `NodeProfile`，会把内部 `agent_update.id` 带给 admin client。
  - server/agent 已有 `restarting` 非终态，但 admin UI 会落到默认“未下发”。
- 这些问题都不需要兼容 shim；应直接统一状态机边界和 UI 展示。

### MAGI 执行

- `internal/server/server.go`
  - `QueueAgentUpdate` 改为返回 `(profile, ok, queuedNew)`。
  - 已有非终态 `AgentUpdate` 时直接复用当前 instruction，不生成新 ID、不覆盖任务、不刷新 config。
  - admin trigger 对复用任务返回 `202` + `status:"in_progress"`，只在真正新排队时广播 snapshot。
  - 新增 `nodeViewLocked` 作为 snapshot / node delta 的统一 NodeView 构造路径。
  - admin profile PATCH 响应改为 `{status:"ok"}`，避免返回 raw `NodeProfile`。
  - `Snapshot` 和 `PublicNodeDelta` 复用同一 NodeView 构造路径，降低状态字段分叉风险。
- `internal/server/web/admin/lib/admin-format.ts`
  - 新增 `resolveAgentUpdateDisplay`，明确映射 `pending/updating/restarting/succeeded/failed`。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - Agent 更新卡片新增“任务状态”展示。
  - `pending/updating/restarting` 时禁用“立即更新”，避免 UI 制造重复 trigger。
  - admin trigger 返回 `in_progress` 时显示“已有任务正在执行”。
- `internal/server/agent_update_test.go`
  - 新增 snapshot/admin NodeView 不泄露 update ID 的 JSON 测试。
  - 新增/调整队列幂等测试，证明活跃 instruction ID 不会被第二次 queue 覆盖。
- `internal/server/web/admin-agent-update.test.mjs`
  - 锁住 admin 类型不包含 raw `agent_update`。
  - 锁住 `restarting` 状态展示和非终态按钮禁用逻辑。

### MAGI 提升

- opaque ID 属于 agent wire protocol，不属于 admin UI/API view model。
- admin trigger 必须 server-side 幂等；UI 禁用只能作为用户体验补强，不能作为一致性边界。
- 非终态集合应由 server/agent state machine 反推，UI default 不能把未知进行中状态显示成“未下发”。

### 验证记录

- `node --test internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs .github/workflows/build-release.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentUpdate' -count=1`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agentrpc ./internal/agent ./internal/server ./internal/updater -count=1`
- `bash -n scripts/verify-local.sh`
- `git diff --check`

## 2026-06-08 / Agent update handler wire hardening

### MAGI 审视

- 子代理只读审视确认 update ID 实现链路没有新的高置信 bug，但指出 handler-level 仍缺“缺少 update_id 必须失败”的直接测试。
- HTTP `/api/v1/agent/update/report` 原先是 `Run` 内匿名闭包，测试只能绕到 `agentAPI.reportUpdate`，没有直接覆盖 JSON decode 字段名。
- gRPC direct handler 测试已经覆盖 `UpdateID`，但还没有证明 `GobCodec + AgentServiceClient + server` 的真实调用路径能保留 ID。

### MAGI 执行

- `internal/server/server.go`
  - 抽出 `agentUpdateReportHTTPHandler(agentAPI)`，注册路由直接复用该 handler。
  - 保持原有行为：只接受 POST，解码 `node_id/update_id/state/version/message`，不匹配 report 返回 API error。
- `internal/server/agent_update_test.go`
  - 新增 `TestAgentUpdateHTTPReportHandlerUsesUpdateID`。
  - 新增 `TestAgentUpdateHTTPReportHandlerRejectsMissingUpdateID`，缺 `update_id` 返回 409 且 pending update 不被清掉。
  - 新增 `TestAgentUpdateGRPCRoundTripUsesUpdateID`，用 `bufconn` 覆盖真实 gRPC client/server + GobCodec 往返。
- `internal/agent/agent_update_test.go`
  - 新增 `TestFromRPCUpdateInstructionPreservesUpdateID`，覆盖 agent 侧 RPC config response 到本地 update instruction 的 ID 映射。

### MAGI 提升

- Handler 级字段名必须直接测试，不能只测下层 API。
- 对手写 gob RPC，direct handler 测试不等于 wire 测试；关键协议字段需要至少一条真实 client/server roundtrip。
- 缺 `update_id` 是协议错误，应保持明确失败，不提供旧格式兼容。

### 验证记录

- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentUpdate(HTTPReportHandlerUsesUpdateID|HTTPReportHandlerRejectsMissingUpdateID|RPCInstructionPreservesID|RPCReportUsesUpdateID|GRPCRoundTripUsesUpdateID)' -count=1 -v`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'Test(FetchRemoteConfigPreservesUpdateID|PostAgentUpdateReportSendsUpdateID|FromRPCUpdateInstructionPreservesUpdateID)' -count=1 -v`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agentrpc ./internal/agent ./internal/server ./internal/updater -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`

## 2026-06-08 / Agent update ID wire coverage

### MAGI 审视

- 上一轮已经把 update instruction identity 贯通到 server、agent、HTTP 和 gRPC。
- 剩余风险是 wire 层没有直接测试：HTTP config 是否能反序列化 update ID、HTTP report 是否发送 `update_id`、gRPC config/report 是否保留 ID。
- 这类问题不需要新增兼容逻辑；直接用协议层测试锁住即可。

### MAGI 执行

- `internal/agent/agent_update_test.go`
  - 新增 `TestFetchRemoteConfigPreservesUpdateID`。
  - 新增 `TestPostAgentUpdateReportSendsUpdateID`。
  - 用 `httptest` 验证 agent HTTP config/report payload 保留 `id` / `update_id`。
- `internal/server/agent_update_test.go`
  - 新增 `TestAgentUpdateRPCInstructionPreservesID`。
  - 新增 `TestAgentUpdateRPCReportUsesUpdateID`。
  - 覆盖 gRPC config 下发 ID、stale `UpdateID` 返回 `FailedPrecondition`、matching `UpdateID` 能正确收口。

### MAGI 提升

- 状态机字段一旦成为协议边界，必须分别锁住 Store、HTTP、gRPC、agent transport 四层。
- 以后新增 agent control-plane 字段时，优先补 wire 测试，避免只在内存对象上验证。

### 验证记录

- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'Test(FetchRemoteConfigPreservesUpdateID|PostAgentUpdateReportSendsUpdateID|MaybeApplyRemoteUpdate|AgentRunnerReportsFailedAgainForSameVersionNewInstruction)' -count=1 -v`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentUpdate(RPC|API|Report|Queue|Delivered)|TestReconcileAgentUpdate' -count=1 -v`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agentrpc ./internal/agent ./internal/server ./internal/updater -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`

## 2026-06-08 / Admin agent update workflow seam

### MAGI 审视

- admin Agent update route 仍在 `Run` 的匿名闭包里直接构造 `updater.NewClient(...).CheckLatest`。
- 这会让 handler 级测试依赖真实 GitHub release 网络，无法离线证明 `GET check`、第一次 `POST queued`、第二次 `POST in_progress` 和后续 report 收口属于同一条 instruction。
- Store 层测试已经证明 ID 不覆盖，但 admin route 的 HTTP response 和 release metadata 仍缺一条可控工作流测试。

### MAGI 执行

- `internal/server/system_update.go`
  - 新增窄类型 `agentReleaseChecker`，只表达 “给定 NodeStats 返回 ReleaseInfo”。
- `internal/server/server.go`
  - 抽出 `defaultAgentReleaseChecker`，生产路径仍调用 `updater.NewClient(updater.DefaultRepo, updater.KindAgent, stats.AgentVersion).CheckLatest(ctx)`。
  - 抽出 `adminAgentUpdateHandler(store, hub, checker)`。
  - 将 GET 和 POST 分拆为 `handleAdminGetAgentUpdate` / `handleAdminPostAgentUpdate`，保留原错误码和响应。
  - `Run` 中只创建一次 `agentUpdateAdminHandler`，避免每个请求重复构造 handler。
- `internal/server/agent_update_test.go`
  - 新增 `TestAgentUpdateAdminHandlerQueuesAndReusesActiveTask`。
  - 使用 fake `agentReleaseChecker` 离线覆盖 GET release view、首次 POST `queued`、二次 POST `in_progress`、原 update ID 不变、matching report 进入 `updating`。

### MAGI 提升

- 生产网络调用应该在 handler 边界外可替换，测试才能覆盖 API 工作流而不是只测 Store。
- seam 要窄：只注入 release checker，不抽象整个 updater，不引入兼容层。
- admin trigger 的幂等保证必须有 HTTP 层证据，否则 UI 和 Store 测试之间仍可能存在断层。

### 验证记录

- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentUpdate|TestReconcileAgentUpdate' -count=1 -v`
- `node --test internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs .github/workflows/build-release.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `env GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agentrpc ./internal/agent ./internal/server ./internal/updater -count=1`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp bash scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
- `git diff --check`

## 2026-06-08 / Admin Kumo component and i18n first slice

### MAGI 审视

- Kumo 官方 registry 和 installation 文档指向的接入方式是安装 `@cloudflare/kumo`、加入 Kumo Tailwind source/styles，并按组件粒度引用。
- admin 现有 UI wrapper 已经承载大量本地 variant 和 `render` 调用，直接全量替换 Dialog、Select、Table 等 compound 组件会扩大风险。
- 当前最稳妥的第一段是迁移 Button、Badge、Input、Card、Label 这些低状态组件，再建立 i18n provider，让后续页面逐步收口。

### MAGI 执行

- `internal/server/web/admin/package.json`
  - 新增 `@cloudflare/kumo` 和 `@phosphor-icons/react`。
- `internal/server/web/admin/src/index.css`
  - 加入 Kumo Tailwind source 和 style import。
- `internal/server/web/admin/components/ui/{button,badge,input,card,label}.tsx`
  - 改为 Kumo-backed wrapper，保留现有调用方 API。
  - `Input` / `Label` wrapper 自动建立 `aria-labelledby` 关联，消除 Kumo dev 模式 accessible-name 警告。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增 `zh-CN` / `en-US` 词典、locale 解析、localStorage 持久化和插值工具。
- `internal/server/web/admin/src/App.tsx`
  - 接入 `AdminI18nProvider`，增加语言切换，并同步 `html lang` / `data-locale`。
- `internal/server/web/admin/src/pages/Login.tsx`
  - 登录页文案、错误提示、Turnstile 状态、按钮 aria 文案切到 i18n。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 服务器管理页主流程文案、toast、agent update 状态和表单提示切到 i18n。
- `internal/server/web/admin-{kumo,i18n}.test.mjs`
  - 新增 Kumo 接入约束和 i18n key parity / 页面硬编码中文检测。

### MAGI 提升

- 后续迁移 Dialog、Select、Sheet、Table 时，需要逐个核对 Kumo compound API，不能用兼容外壳一次性吞掉差异。
- i18n 后续应继续扩展到 Dashboard、BasicSettings、GroupManagement、ProbeSettings、NotificationAlert、AIProvider，并保持词典 key parity 测试。
- 浏览器验证应覆盖已登录态页面；当前只离线证明 ServerManagement 文案和构建路径，真实数据态仍需后续 smoke。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/public-assets.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- headless Chrome/CDP smoke：桌面英文、桌面中文切换、移动端中文、移动端英文登录页均无遮罩残留，Kumo button class 存在。
- headless Chrome dev smoke：登录页稳定后 `username` / `password` 输入框包含 `aria-labelledby`，Vite dev server 未再输出 Kumo Input accessible-name 警告。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp bash scripts/verify-local.sh`

## 2026-06-09 / Admin i18n page expansion

### MAGI 审视

- `GroupManagement` / `ProbeSettings` 仍保留页面内中文文案，和上一轮 `App` / `Login` / `ServerManagement` 的 i18n 方向不一致。
- 验证错误、toast、aria label、空状态和弹窗标题如果继续散落在页面里，后续切英文会出现“菜单已切换、页面内容未切换”的半成品状态。
- `GroupManagement` 的 `全部` 是业务保留值，不能通过翻译改变语义；需要保留直接比较，同时把用户可见错误提示放进词典。

### MAGI 执行

- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增 `admin.common.*`、`groupManagement.*`、`probeSettings.*` 双语词典。
  - 覆盖按钮、空状态、toast、表单校验、aria label、计数和探测间隔格式。
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - 接入 `useAdminT`。
  - `analyzeDraftTree` 改为接收 `AdminT`，校验错误全部从 typed dictionary 取值。
  - 页面标题、统计卡、拖拽 aria、删除确认、标签计数和保存反馈切到 i18n。
  - 业务保留值用 `RESERVED_GROUP_NAME = "\u5168\u90e8"` 表达，避免页面源码继续散落中文 UI 文案。
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - 接入 `useAdminT`。
  - `validateProbeForm` / `formatProbeInterval` 改为接收 `AdminT`。
  - 探测节点列表、弹窗、表单校验、toast、删除确认和 interval 文案切到 i18n。
- `internal/server/web/admin-i18n.test.mjs`
  - 将 `GroupManagement` / `ProbeSettings` 纳入无页面内中文硬编码检测。
  - 增加新页面 key 的词典 parity 断言。

### MAGI 提升

- 后续新增 admin 页面文案时，先加 `admin-i18n.tsx` key，再在页面引用；不要再把中文直接写进 React 页面。
- 对业务保留值保持单一常量，不为英文 UI 重新解释存储语义。
- 下一轮应继续收口 `BasicSettings`、`NotificationAlert`、`AIProvider`，同时关注 `AIProvider` chunk 体积偏大。

### 验证记录

- `node --test internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/public-assets.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- headless Chrome dev smoke：`http://127.0.0.1:3001/` 登录页正常渲染，DOM 包含 `data-locale`、Kumo button、`username/password` 的 `aria-labelledby`；dev server 未输出应用级 warning/error。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp bash scripts/verify-local.sh`

## 2026-06-09 / Admin Kumo i18n completion and AI chunk cleanup

### MAGI 审视

- Kumo registry API 确认 `Button`、`Badge`、`Input`、`Label`、`LayerCard` 等组件由 `@cloudflare/kumo` 提供，支持 variant、size、label、description、error 等表单语义。
- `BasicSettings`、`NotificationAlert`、`Dashboard`、`AIProvider` 仍有页面内中文文案；`admin-format.ts` 也会向页面返回中文 Agent 更新状态和相对时间。
- `AIProvider` 页面同时承载 provider draft 组装、label fallback、payload 构造和 JSX，导致 Dashboard 复制 provider label 逻辑。
- Rollup/Rolldown 会把共享 UI/工具和部分 lucide 图标落进页面 chunk，上一轮 build 中 `page-aiprovider` 约 440 KB，并被其它页面反向引用。

### MAGI 执行

- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 扩展 `dashboard.*`、`basicSettings.*`、`notificationAlert.*`、`aiProvider.*`、`admin.time.*`、`server.agentUpdate.display.*` 双语词典。
  - 保持 zh-CN/en-US key parity，动态 provider 名、模型 ID、API Key、Base URL 不翻译，只作为业务值显示。
- `internal/server/web/admin/src/pages/{Dashboard,BasicSettings,NotificationAlert,AIProvider}.tsx`
  - 接入 `useAdminT` / `useAdminI18n`，移除页面内中文硬编码。
  - 将 toast、placeholder、aria、状态 badge、空状态、表单提示和确认文案统一走 i18n。
- `internal/server/web/admin/lib/admin-ai.ts`
  - 抽出纯 TS provider helper，统一 command provider label、compatible fallback、draft 初始化、request key、selection 和保存 payload 组装。
  - `Dashboard` 和 `AIProvider` 共用该 helper，避免页面之间复制逻辑。
- `internal/server/web/admin/lib/admin-format.ts`
  - `formatDateTime` 接收 locale。
  - `formatRelativeTime` 和 `resolveAgentUpdateDisplay` 显式接收 `AdminT`，不再在纯工具层硬编码中文显示文案。
- `internal/server/web/admin/vite.config.ts`
  - 增加 `admin-shared` chunk，将本地 `components` / `lib` 共享模块从页面 chunk 中拆出。
- `internal/server/web/admin/lib/admin-icons.ts` 和 `lucide-icon-modules.d.ts`
  - 建立 admin 图标入口并给 lucide 深层 icon module 补类型声明。
  - `AIProvider` 改用独占语义图标，避免其它页面继续从 `page-aiprovider` 复用图标导出。
- `internal/server/web/admin-i18n.test.mjs` / `admin-agent-update.test.mjs`
  - 扩展 Dashboard、BasicSettings、NotificationAlert、AIProvider、admin-format、admin-ai 的 i18n 约束。
  - Agent update 测试从中文直写断言切到 i18n key 断言。

### MAGI 提升

- 当前 Kumo 迁移适合继续按 wrapper 边界推进；下一段可评估 `Select`、`Dialog`、`Tabs`、`Textarea`、`Accordion`，但每个 compound API 都应单独验证。
- `admin-shared` 仍超过 500 KB，主要是集中后的共享 UI/工具代码；后续应拆分图标、Kumo/Radix 类 UI runtime、业务 helper，而不是把共享代码塞回页面 chunk。
- i18n 新页面应默认纳入 `admin-i18n.test.mjs` 的 key parity 和页面无中文硬编码检测。

### 验证记录

- `node --test internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/public-assets.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `grep -RIn "page-aiprovider" internal/server/web/dist/admin/assets/page-dashboard-*.js internal/server/web/dist/admin/assets/page-servermanagement-*.js internal/server/web/dist/admin/assets/page-probesettings-*.js internal/server/web/dist/admin/assets/page-basicsettings-*.js internal/server/web/dist/admin/assets/page-notificationalert-*.js` 返回无命中。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp bash scripts/verify-local.sh`
- headless Chrome smoke：`http://127.0.0.1:3002/` 登录页渲染成功，截图 `/tmp/cm-admin-kumo-i18n-login.png` 非空；容器缺 CJK 字体导致中文显示为方块，Chrome stderr 的 Crashpad/DBus/fontconfig 为环境噪声。

## 2026-06-09 / Admin Kumo chunk boundary correction

### MAGI 审视

- 重新检查当前 dist 后发现上一段记录的 `page-aiprovider` 无命中结论已经过期：`ServerManagement` / `NotificationAlert` 产物仍会从 `page-aiprovider` chunk 读取共享符号。
- 原因不是源代码存在跨页面 import，而是 `manualChunks` 强制把 `/src/pages/*` 固定为页面 chunk 后，Rollup/Rolldown 会把共享 `sonner`、lucide icon 和 UI 符号放进某个页面 chunk。
- Kumo registry API 当前确认基础组件使用 `@cloudflare/kumo/components/...` 粒度路径；构建策略应把 Kumo/Base/Sonner runtime、local UI wrappers、admin lib 分开，而不是把所有 local `components` / `lib` 塞进一个 `admin-shared`。

### MAGI 执行

- `internal/server/web/admin/vite.config.ts`
  - 将 `lucide-react`、`@cloudflare/kumo`、`@dnd-kit`、`@base-ui/react`、`sonner` 的 chunk 判定提升到 `node_modules` 和 local path 之前。
  - 将 local UI wrapper 拆到 `admin-ui`，admin lib 拆到 `admin-core`，保留 generic `admin-components` 作为后续非 UI 组件兜底分组。
  - 移除 `/src/pages/` 手动分片，让 `React.lazy` 页面由 bundler 自然产出 entry chunk，避免页面 chunk 互相承载共享符号。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 chunk 策略静态回归：第三方 UI runtime 必须先于 local UI/lib 分类，`/components/ui/` 必须先于 generic `/components/`，lazy page 不得再手动分片。

### MAGI 提升

- 对 lazy page，除非有明确可测的收益，不应再手写页面级 `manualChunks`；这种做法会制造跨页面 chunk 依赖。
- 下一步如果继续优化包体，优先审视 `admin-ui` 的 Kumo/Base/compound wrapper 组合，而不是回退到把共享代码放进页面 chunk。
- Kumo wrapper 继续保持“组件级替换，调用方 API 稳定”的路径；不要引入双组件库兼容层。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `node --test internal/server/web/public-assets.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs`
- `grep -Rho 'from"\./[^"]*"' internal/server/web/dist/admin/assets/*.js` 仅显示 runtime、admin-core、admin-ui、vendor、vendor-icons、vendor-ui 依赖；页面 chunk 不再引用其它页面 chunk。
- `grep -RIn "page-aiprovider\|page-dashboard\|page-basicsettings\|page-probesettings\|page-groupmanagement" internal/server/web/dist/admin/assets internal/server/web/dist/admin/index.html` 返回无命中。
- 最新 `build:admin` 最大 JS chunk 为 `admin-ui` 419.78 kB，未再触发 500 kB chunk warning。
- Browser plugin path 阻断：`node_repl` 工具未暴露；Playwright fallback 报 `Playwright Extension not found`；Chrome DevTools fallback 报 `Could not find DevToolsActivePort`。
- `google-chrome --headless=new --no-sandbox --disable-gpu --virtual-time-budget=5000 --dump-dom http://127.0.0.1:3003/` 证明登录页 DOM 渲染，包含 `html lang="zh-CN"`、`data-locale="zh-CN"`、Kumo button marker 和 input `aria-labelledby`。
- `google-chrome --headless=new --no-sandbox --disable-gpu --window-size=1280,900 --virtual-time-budget=7000 --screenshot=/tmp/cm-admin-kumo-smoke-1280.png http://127.0.0.1:3003/` 证明登录卡片首屏可见；当前容器缺 CJK 字体，截图中文显示为方块。

## 2026-06-09 / Admin Kumo switch shim removal

### MAGI 审视

- `components/ui/switch.tsx` 仍手写 `@base-ui/react/switch` primitive 组合；这和当前 Kumo wrapper 迁移方向不一致。
- 本地安装的 `@cloudflare/kumo` 已提供 `@cloudflare/kumo/components/switch`，类型直接支持 `checked`、`onCheckedChange`、`size`、`variant`。
- 当前页面没有引用 `Switch`，因此无需保留旧 `size="default"` 等本地兼容 API；直接 re-export Kumo Switch 是更简洁路径。

### MAGI 执行

- `internal/server/web/admin/components/ui/switch.tsx`
  - 删除 Base UI primitive 拼装。
  - 改为直接 re-export Kumo `Switch` 和 `SwitchProps`。
- `internal/server/web/admin-kumo.test.mjs`
  - 将 `switch.tsx` 纳入 granular Kumo component import 约束。
  - 新增回归测试，禁止 `switch.tsx` 再引入 `@base-ui/react/switch` 或 `SwitchPrimitive`。

### MAGI 提升

- 对已存在 Kumo 组件的低状态 wrapper，优先删除本地 primitive 拼装，而不是包一层兼容外壳。
- 尚未发现 Kumo `Textarea` export；`Textarea` 不应做伪迁移。
- 后续迁移 Base UI compound 组件前，必须先核对 Kumo compound API 和真实页面用法。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `grep -RIn "@base-ui/react/switch\|SwitchPrimitive" internal/server/web/admin --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `node --test internal/server/web/public-assets.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs`

## 2026-06-09 / Admin Kumo banner, dropdown and separator simplification

### MAGI 审视

- 继续对照 Kumo component registry 和当前源码，登录页错误提示仍使用本地 `Alert` 组合，和前一轮 Kumo direct component 迁移方向不一致。
- Kumo `Banner` 支持结构化 `title` / `description`，更适合直接承载 i18n 文案和动态锁定倒计时。
- `components/ui/separator.tsx` 只包了一层 Base UI primitive，实际调用方只需要横向/纵向分隔线语义；继续依赖 Base UI 会增加无意义 runtime。
- `components/ui/dropdown-menu.tsx` 当前只有 `ServerManagement` 使用，调用面集中在 Root / Trigger / Content；Kumo 已提供同名 compound component，适合先替换本地 primitive 拼装。

### MAGI 执行

- `internal/server/web/admin/src/pages/Login.tsx`
  - 删除本地 `Alert` / `AlertTitle` / `AlertDescription` 依赖。
  - 将 invalid / expired / locked 三类登录提示改为 Kumo `Banner`。
  - 保留 `role="alert"`，并通过 i18n key 注入标题、说明和锁定倒计时。
- `internal/server/web/admin/components/ui/separator.tsx`
  - 删除 `@base-ui/react/separator` primitive。
  - 改为轻量 DOM separator，保留 `role="separator"`、`aria-orientation` 和原有横纵向样式。
- `internal/server/web/admin/components/ui/dropdown-menu.tsx`
  - 删除本地 `@base-ui/react/menu` 组合实现。
  - 改为从 Kumo `DropdownMenu` compound component 暴露同名 aliases，保持调用方 import 不变。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增登录页 Kumo `Banner` 静态回归。
  - 新增 `Separator` 不再引入 Base UI primitive 的静态回归。
  - 新增 `DropdownMenu` 不再引入 Base UI primitive 的静态回归。

### MAGI 提升

- Kumo 已覆盖且调用方 API 简单的组件，应优先直连或轻量本地 DOM，不再保留 primitive shim。
- 仍未删除 `tooltip.tsx`、`table.tsx`、`switch.tsx` 等未使用 wrapper；删除属于危险操作，需要单独确认后再清理。
- 剩余 Base UI compound wrappers 主要集中在 `dialog`、`select`、`tabs`、`sheet`、`accordion` 等文件，下一段仍应按真实用法逐个收窄，避免一次性替换 compound API 带来交互回归。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `grep -RIn 'components/ui/alert"\|components/ui/alert;' internal/server/web/admin/src internal/server/web/admin/components internal/server/web/admin/lib --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `grep -RIn 'AlertTitle\|AlertDescription' internal/server/web/admin/src --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `grep -RIn '@base-ui/react/separator\|SeparatorPrimitive' internal/server/web/admin --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `grep -RIn '@base-ui/react/menu\|MenuPrimitive' internal/server/web/admin/components/ui/dropdown-menu.tsx internal/server/web/admin/src --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `node --test internal/server/web/public-assets.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp bash scripts/verify-local.sh`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go vet ./...`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`
- headless Chrome smoke：`http://127.0.0.1:3005/` 登录页渲染成功，DOM 包含 `html lang="zh-CN"`、`data-locale="zh-CN"`、Kumo button marker、登录输入和主按钮；截图 `/tmp/cm-admin-kumo-final-1280.png` 证明登录卡片首屏可见。当前容器缺 CJK 字体，截图中文显示为方块。

## 2026-06-09 / Admin Kumo Select direct migration

### MAGI 审视

- `components/ui/select.tsx` 仍维护本地 `@base-ui/react/select` primitive 组合，但真实调用面只有 `AIProvider` 和 `ServerManagement` 两处。
- Kumo `Select` 已提供高阶组件和 `Select.Option` API，继续保留本地 `Trigger` / `Content` / `Value` 组合是冗余兼容包装。
- `AIProvider` 和 `ServerManagement` 的 Select 都是单选值，没有 group、separator、scroll button 等复杂用法，适合直接切到 Kumo API。

### MAGI 执行

- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - 改为直接 import `@cloudflare/kumo/components/select`。
  - 删除 `SelectTrigger` / `SelectContent` / `SelectValue` 结构，改用 Kumo `Select` + `Select.Option`。
  - 用 `aria-labelledby` 连接现有 visible label，保留无障碍名称。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 改为直接 import Kumo `Select`。
  - 删除旧 local select compound 结构，续费计划选项改用 `Select.Option`。
  - 增加 `RENEW_PLAN_VALUES` 边界检查，避免未知值进入 `RenewPlan`。
- `internal/server/web/admin/components/ui/select.tsx`
  - 删除本地 Base UI primitive 拼装。
  - 仅保留 Kumo `Select` / `Select.Option` / `Select.Group` / `Select.GroupLabel` / `Select.Separator` aliases，作为未迁移 import 的临时薄出口。
- `internal/server/web/admin-kumo.test.mjs`
  - 将 `select.tsx` 纳入 Kumo granular import 约束。
  - 新增页面级回归，禁止 `AIProvider` / `ServerManagement` 再使用本地 Select wrapper 或旧 `SelectTrigger` / `SelectContent` / `SelectValue`。

### MAGI 提升

- 对已有 Kumo 高阶组件且调用面简单的组件，应直接改页面结构，不应在 wrapper 内模拟旧 compound API。
- 剩余未使用 wrapper 包括 `tooltip.tsx` 和当前薄 `select.tsx`；删除需要单独确认。
- 下一段可优先把 `accordion.tsx` 从直接 `@base-ui/react` import 改成 Kumo primitive import，保留多展开语义；`dialog`、`alert-dialog`、`sheet`、`tabs` 仍应后置。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `grep -RIn '@/components/ui/select\|<SelectTrigger\|<SelectContent\|<SelectValue\|@base-ui/react/select\|SelectPrimitive' internal/server/web/admin/src internal/server/web/admin/components/ui/select.tsx --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `node --test internal/server/web/public-assets.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs`
- headless Chrome + local API proxy smoke：`http://127.0.0.1:3010/?page=ai` 渲染 AI 服务商页面成功，DOM 中 `data-kumo-component="Select"` 和 `data-kumo-part="trigger"` 各 1 个；截图 `/tmp/cm-admin-select-ai-1440.png` 证明全局 AI 策略选择控件首屏可见。
- Browser plugin path 阻断：Node REPL 执行工具未暴露；Playwright fallback 报 `Playwright Extension not found in "/root/.config/google-chrome"`。

## 2026-06-09 / Admin Kumo accordion primitive boundary

### MAGI 审视

- `components/ui/accordion.tsx` 只服务 `AIProvider` 的服务商配置详情区域，调用面集中。
- Kumo registry 当前没有高阶 `Accordion` 组件；本地 Kumo package 提供 `@cloudflare/kumo/primitives/accordion`，与 Base UI API 同形。
- 直接改成 Kumo primitive import 能去掉项目代码对 `@base-ui/react/accordion` 的直接依赖，同时保留 `multiple` 展开语义。

### MAGI 执行

- `internal/server/web/admin/components/ui/accordion.tsx`
  - 将 primitive import 从 `@base-ui/react/accordion` 改为 `@cloudflare/kumo/primitives/accordion`。
  - 将折叠箭头图标改走项目已有的 `admin-icons` 直导入口。
- `internal/server/web/admin/lib/admin-icons.ts`
  - 新增 `ChevronDown` / `ChevronUp` 的 lucide ESM 直导出。
- `internal/server/web/admin-kumo.test.mjs`
  - 将 `accordion.tsx` 纳入 Kumo granular import 约束。
  - 禁止 `accordion.tsx` 回退到直接 `@base-ui/react/accordion` import。

### MAGI 提升

- 当 Kumo registry 没有高阶组件但 Kumo package 提供 primitive export 时，优先把直接 Base UI import 收敛到 Kumo 包边界。
- 这种迁移不应伪装成高阶组件替换；行为保持是第一目标，结构性重写留给后续 phase。
- 仍剩 `tabs`、`scroll-area`、`alert-dialog`、`dialog`、`tooltip`、`sheet` 直接 Base UI import，其中 `tooltip` 无业务调用方，删除仍需单独确认。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `grep -RIn '@base-ui/react/accordion\|from "lucide-react"' internal/server/web/admin/components/ui/accordion.tsx internal/server/web/admin/lib/admin-icons.ts --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `node --test internal/server/web/public-assets.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs`
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp bash scripts/verify-local.sh`
- headless Chrome + local API proxy smoke：`http://127.0.0.1:3010/?page=ai` 渲染 AI 服务商页面成功，DOM 中 `data-kumo-component="Select"` 为 1 个、`data-slot="accordion"` 为 1 个、`data-slot="accordion-trigger"` 为 3 个，且无 Vite error overlay；截图 `/tmp/cm-admin-accordion-ai-1440.png` 证明 AI 页面首屏可见。

## 2026-06-09 / Admin Kumo tabs and primitive wrapper boundary

### MAGI 审视

- 对照 `https://kumo-ui.com/api/component-registry` 和本地 `@cloudflare/kumo@2.5.1` exports 后确认：
  - `Tabs` 是公开高阶 component，API 为 `tabs[]` / `value` / `onValueChange`。
  - `Dialog` / `Tooltip` 是公开高阶 component。
  - `ScrollArea` / `AlertDialog` 不在 component registry 中，但本地 Kumo package 提供同形 primitive export。
- 当前管理后台源码仍有 `tabs`、`scroll-area`、`alert-dialog`、`dialog`、`tooltip`、`sheet` 直接 import `@base-ui/react`。
- `BasicSettings` 是唯一 tabs 调用方，页面表单状态集中在父组件，适合改成 Kumo `Tabs` 受控导航 + 本地 `tabpanel`。
- `scroll-area` 和 overlay wrappers 仍承担既有 shadcn 风格结构，先把 primitive 边界收敛到 Kumo 包，避免一次性重写 overlay 交互。

### MAGI 执行

- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 删除本地 `@/components/ui/tabs` compound 依赖。
  - 改为直接 import `@cloudflare/kumo/components/tabs`。
  - 新增 `BasicSettingsTab` 受控状态和 `SettingsTabPanel`，用 `hidden` 控制面板可见性，保留表单状态不丢失。
- `internal/server/web/admin/components/ui/scroll-area.tsx`
  - 将 primitive import 改为 `@cloudflare/kumo/primitives/scroll-area`。
- `internal/server/web/admin/components/ui/tabs.tsx`
  - 将遗留 wrapper 的 primitive import 改为 `@cloudflare/kumo/primitives/tabs`，不再直接触达 Base UI。
- `internal/server/web/admin/components/ui/alert-dialog.tsx`
  - 将 primitive import 改为 `@cloudflare/kumo/primitives/alert-dialog`。
- `internal/server/web/admin/components/ui/dialog.tsx` / `internal/server/web/admin/components/ui/sheet.tsx`
  - 将 dialog primitive import 改为 `@cloudflare/kumo/primitives/dialog`。
- `internal/server/web/admin/components/ui/tooltip.tsx`
  - 将 primitive import 改为 `@cloudflare/kumo/primitives/tooltip`。
- `internal/server/web/admin/package.json` / `package-lock.json`
  - 移除 admin UI 对 `@base-ui/react` 的直接 dependency；Base UI 仅作为 Kumo 的传递依赖存在。
- `internal/server/web/admin/lib/admin-ui.ts`
  - 删除不再使用的本地 tabs list / trigger 样式常量。
- `internal/server/web/admin-kumo.test.mjs`
  - 扩充 Kumo granular import 约束。
  - 禁止 admin package 直接声明 `@base-ui/react`。
  - 新增 `BasicSettings` 直接使用 Kumo `Tabs` 的静态回归。

### MAGI 提升

- 管理后台源码已经不再直接 import `@base-ui/react`；后续要避免把 Kumo primitive 又包回新的本地兼容层。
- `vite.config.ts` 中保留 `@base-ui/react` 字符串是分包策略，用于把 Kumo 的传递运行时代码归入 `vendor-ui`，不是 admin 直接依赖。
- 下一阶段可继续评估 `Dialog` / `Tooltip` 的高阶 component 直连替换；这会改 overlay DOM 和 API，应按页面交互逐个做，不宜和 primitive 边界收敛混在一起。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `grep -R '@base-ui/react/scroll-area\|@base-ui/react/tabs\|@/components/ui/tabs' -n internal/server/web/admin --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `grep -R '@base-ui/react' -n internal/server/web/admin --exclude-dir=node_modules --exclude-dir=dist --exclude=package-lock.json` 仅剩 `vite.config.ts` 分包分类。
- `npm --prefix internal/server/web/admin uninstall @base-ui/react --package-lock-only`
- headless Chrome CDP + `vite preview` + local API proxy smoke：`http://127.0.0.1:3010/?page=settings` 渲染设置页成功；4 个 tab 均带 `data-kumo-component="Tabs"`；点击“备份与更新”和“站点展示”后 active tab 与 visible `tabpanel` 同步变化；无 Vite error overlay；console error/warn 为空；截图 `/tmp/cm-admin-settings-kumo-tabs-1440.png` 和 `/tmp/cm-admin-settings-kumo-tabs-mobile.png` 证明桌面与移动布局可见。
- Browser / Playwright path 阻断：Playwright MCP 报 `Playwright Extension not found in "/root/.config/google-chrome"`，因此使用 headless Chrome CDP fallback。

## 2026-06-09 / Admin Kumo Dialog direct confirmations

### MAGI 审视

- 子审视与本地核对一致：Kumo `Dialog` 高阶组件支持 `Dialog.Root role="alertdialog"`，适合简单确认流。
- `BasicSettings` 的保存确认和导入配置确认只有 title、cancel、confirm action，没有嵌套表单、description 或复杂 focus stack，是第一批低风险迁移目标。
- `Sheet` 仍是移动端侧滑导航，Kumo 当前没有公开高阶 sheet component，不应强行用居中 `Dialog` 替代。
- `ServerManagement` 的节点编辑弹窗和嵌套删除确认包含大宽度、内部滚动、嵌套 overlay 与 loading 状态，应后置单独迁移。

### MAGI 执行

- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 删除本页 `@/components/ui/alert-dialog` 依赖。
  - 直接 import `@cloudflare/kumo/components/dialog`。
  - 将保存确认改为 `Dialog.Root role="alertdialog"` + `Dialog` + `Dialog.Title` + `Dialog.Close`。
  - 将导入配置确认改为 Kumo `Dialog.Trigger` 和 `Dialog.Close`，保留文件选择触发逻辑。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 `BasicSettings` 简单确认弹层直接使用 Kumo Dialog 的静态回归。
  - 禁止本页重新引入本地 `AlertDialog` wrapper。

### MAGI 提升

- 简单确认弹层应直接使用 Kumo 高阶 `Dialog`，不再通过本地兼容式 `AlertDialog` wrapper。
- 复杂编辑弹窗、嵌套删除确认、移动端 sheet 需要按真实交互逐个迁移，不应为了“统一”牺牲行为可验证性。
- 后续可按子审视建议迁移 `App` 未保存确认、`ProbeSettings` 删除确认、`GroupManagement` 删除确认；`ServerManagement` 和 `Sheet` 后置。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `grep -n "AlertDialog\|@/components/ui/alert-dialog\|@cloudflare/kumo/components/dialog\|Dialog\.Root" internal/server/web/admin/src/pages/BasicSettings.tsx` 只剩 Kumo Dialog 命中。
- Browser / Playwright / DevTools / headless Chrome 交互验证阻断：
  - Playwright MCP 报 `Playwright Extension not found in "/root/.config/google-chrome"`。
  - Chrome DevTools MCP 报 `Could not find DevToolsActivePort`。
  - headless Chrome CDP 在 `Page.navigate` / `Runtime.evaluate` 阶段不稳定。
  - Chrome CLI screenshot 因当前容器 `/tmp` 满和 crashpad 写入失败退出；已清理本轮 `/tmp/cm-chrome-*` 临时 profile。
  - 因此本轮 runtime 只采用类型检查、构建和静态回归作为交付证据；交互 smoke 留给下一轮在浏览器环境恢复后补跑。

## 2026-06-09 / Admin Kumo Dialog simple confirmation batch

### MAGI 审视

- 继续沿上一轮 overlay 审视结论推进：简单确认弹层可以直接使用 Kumo 高阶 `Dialog.Root role="alertdialog"`。
- 本批目标限定为：
  - `App` 未保存变更确认。
  - `ProbeSettings` 删除探测项确认。
  - `GroupManagement` 删除分组确认。
- 三处都只有 title、cancel、confirm action，没有嵌套 dialog、复杂表单或内部滚动，适合直接迁移。
- `ServerManagement` 的删除确认仍嵌套在大编辑 dialog 内，存在 focus stack 和 loading 状态风险，继续后置。

### MAGI 执行

- `internal/server/web/admin/src/App.tsx`
  - 删除本页 `@/components/ui/alert-dialog` 依赖。
  - 直接 import `@cloudflare/kumo/components/dialog`。
  - 将未保存确认改为 Kumo `Dialog.Root role="alertdialog"`。
  - 保留 `open/onOpenChange` 中清理 `pendingPageNavigation` 的语义。
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - 删除删除确认对本地 `AlertDialog` wrapper 的依赖。
  - 因本页已有编辑表单 `Dialog`，Kumo 高阶 Dialog 以 `KumoDialog` 别名引入。
  - 保留删除确认的 `pendingDeleteIndex`、`handleDelete` 和 `clearPendingDelete` 语义。
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - 删除删除分组确认对本地 `AlertDialog` wrapper 的依赖。
  - 改用 Kumo `Dialog.Trigger` / `Dialog.Close`。
  - 保留 `isBusy` 禁用触发按钮和 danger action 样式。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增简单确认弹层直接使用 Kumo Dialog 的静态回归。
  - 新增本地 `AlertDialog` wrapper 使用面白名单，限制为 `ServerManagement` 嵌套删除确认。

### MAGI 提升

- 简单确认弹层已经形成直接迁移模式：`Dialog.Root role="alertdialog"` + `Dialog` + `Dialog.Title` + `Dialog.Close`。
- 后续迁移应继续避免创建新的兼容 wrapper。
- 下一批可处理 `ServerManagement` 嵌套删除确认；这需要恢复浏览器交互验证后再做，重点验证 focus、Esc、backdrop 层级、删除 loading 状态。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `grep -R "@/components/ui/alert-dialog" -n internal/server/web/admin/src internal/server/web/admin/components --exclude-dir=node_modules --exclude-dir=dist` 仅剩 `ServerManagement`。
- 浏览器交互验证未重跑：当前 `/tmp` 仍只有约 77MB 可用，上一轮 Playwright / Chrome DevTools / headless Chrome 已被环境问题阻断；为避免继续打满 `/tmp`，本轮以类型检查、构建和静态回归作为证据。

## 2026-06-09 / Admin Kumo Dialog nested server deletion

### MAGI 审视

- 继续按 Kumo component registry 暴露的高阶组件边界推进，复杂弹窗内的删除确认也应直接使用 `@cloudflare/kumo/components/dialog`。
- `ServerManagement` 顶层编辑弹窗仍保留本地 `Dialog` wrapper，因为它承担大尺寸编辑面板、内部滚动和既有样式约束。
- 嵌套删除确认本身只有 trigger、title、cancel、confirm action，不需要继续通过本地 `AlertDialog` wrapper 做兼容封装。
- 迁移后业务页应不再 import `@/components/ui/alert-dialog`；本地 wrapper 暂时只作为未删除的历史组件存在。

### MAGI 执行

- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 删除嵌套删除确认对本地 `AlertDialog` 的业务依赖。
  - 直接使用 `KumoDialog.Root role="alertdialog"` / `KumoDialog.Trigger` / `KumoDialog.Close`。
  - 保留 `deleteDialogOpen`、`setDeleteDialogOpen`、`handleDelete`、`saving || deleting` 禁用语义。
- `internal/server/web/admin-kumo.test.mjs`
  - 将旧的 `ServerManagement` AlertDialog 例外改成业务页零例外断言。
  - 新增嵌套删除确认直接使用 Kumo Dialog 的静态回归。

### MAGI 提升

- 管理后台业务源码已经完成本轮 AlertDialog 归零：简单确认和嵌套删除确认都直接走 Kumo Dialog。
- 下一轮如果要删除 `components/ui/alert-dialog.tsx`，需要先确认没有外部引用和 story/test 依赖；删除属于破坏性文件操作，应单独确认。
- 浏览器交互验证仍受当前 `/tmp` 空间和 Chrome profile 写入问题阻断；恢复环境后应补跑删除确认的 focus、Esc、backdrop 和 loading 状态 smoke。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/alert-dialog\|<AlertDialog\|AlertDialog" internal/server/web/admin/src --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Kumo Dialog probe editor direct migration

### MAGI 审视

- `ProbeSettings` 的编辑弹窗是单页表单弹层，宽度约 620px，没有 `ServerManagement` 那种 70rem 大型编辑面板和复杂内部滚动。
- Kumo 高阶 `Dialog` 支持 controlled `Root open/onOpenChange`、`Title`、`Close` 和自定义 `style`，可以承接本页编辑弹窗。
- Kumo `size="lg"` 会带无断点 `min-w-[32rem]`，移动端可能溢出；本轮改用 `style={{ width: "min(calc(100vw - 2rem), 620px)" }}` 保持响应式宽度。
- 子审视建议删除 `components/ui/alert-dialog.tsx` 死 wrapper；该动作属于文件删除，按仓库 AGENTS 规则需要单独确认，本轮不执行。

### MAGI 执行

- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - 删除对本地 `@/components/ui/dialog` 的业务依赖。
  - 编辑弹窗改为 `KumoDialog.Root` + `KumoDialog` + `KumoDialog.Title` + `KumoDialog.Close`。
  - 保留 `isDialogOpen`、`closeDialog`、`handleDialogSave`、字段校验和 i18n 文案。
  - 显式保留右上角关闭按钮，避免从 wrapper 迁移后丢失关闭入口。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 `ProbeSettings` 编辑弹窗和删除确认均直连 Kumo Dialog 的静态回归。
  - 明确禁止 `ProbeSettings` 重新 import 本地 `dialog` wrapper。

### MAGI 提升

- 本地 `dialog` wrapper 的业务调用面现在只剩 `ServerManagement` 顶层大型编辑弹窗。
- 后续要处理 `components/ui/alert-dialog.tsx`，应先按删除操作流程确认；确认后可删除文件并移除 `admin-kumo.test.mjs` 中 wrapper 清单里的 `alert-dialog.tsx` 项。
- `ServerManagement` 编辑弹窗迁移需要单独做，因为它涉及大尺寸面板、内部滚动、嵌套删除弹层和 focus stack。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/dialog" internal/server/web/admin/src internal/server/web/admin/components --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 仅剩 `ServerManagement`。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- Browser rendered smoke 未执行：Browser skill 要求通过 Node REPL `js` 工具控制 in-app browser，但当前工具发现未暴露该执行工具；按技能约束未擅自切到 standalone Playwright fallback。

## 2026-06-09 / Admin Kumo Dialog server editor direct migration

### MAGI 审视

- `ServerManagement` 顶层编辑弹窗是最后一个业务侧 `@/components/ui/dialog` 调用面。
- Kumo 高阶 `Dialog` 已在简单确认、嵌套删除确认和 `ProbeSettings` 编辑弹窗中通过类型检查与生产构建。
- 顶层编辑弹窗需要保留大面板能力：宽度 `70rem`、最大高度 `min(92vh, 960px)`、内部滚动区域、底部操作栏和右上角关闭入口。
- 内部删除确认已经是独立的 `KumoDialog.Root role="alertdialog"`；嵌套在外层 Kumo `Dialog.Root` 下仍使用内层 Provider，不需要恢复本地 wrapper。

### MAGI 执行

- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 删除业务侧对 `@/components/ui/dialog` 的 import。
  - 顶层编辑弹窗改为 `KumoDialog.Root` + `KumoDialog` + `KumoDialog.Title` + `KumoDialog.Description`。
  - 用 `style` 显式保留 `maxHeight: "min(92vh, 960px)"` 和 `width: "min(calc(100vw - 2rem), 70rem)"`。
  - 显式加入 `KumoDialog.Close` 右上角关闭按钮，避免从 wrapper 迁移后丢失关闭入口。
  - 底部操作栏改为普通 `div`，不再依赖本地 `DialogFooter`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增业务页不得 import 本地 `Dialog` wrapper 的断言。
  - 新增 `ServerManagement` 顶层编辑弹窗直连 Kumo Dialog 的静态回归。

### MAGI 提升

- 管理后台业务源码已经完成本轮 `Dialog` / `AlertDialog` wrapper 调用面归零。
- `components/ui/dialog.tsx` 与 `components/ui/alert-dialog.tsx` 现在属于待确认删除的历史 wrapper；删除文件属于破坏性操作，应单独按影响、最坏情况、回滚方法和确认流程处理。
- 浏览器交互验证仍受 Browser Node REPL 工具未暴露影响；当前阶段以类型检查、生产构建和静态回归为证据。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/dialog\|@/components/ui/alert-dialog\|AlertDialog" internal/server/web/admin/src --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Kumo InputArea prompt migration

### MAGI 审视

- `AIProvider` 的 prompt 文本框是本地 `Textarea` wrapper 的唯一业务调用面。
- Kumo `@cloudflare/kumo/components/input` 已导出 `InputArea` / `Textarea`，支持原生 textarea 属性和 `onChange`。
- 本页已经从 `admin-ui` 使用 `adminTextareaClass` 管理视觉样式，迁移到 Kumo `InputArea` 不需要再保留本地 `Textarea` wrapper。
- `Accordion` 仍涉及 `Root` / `Item` / `Header` / `Trigger` / `Panel` 组合与展开动画结构，风险高于单个文本框；本轮后置。

### MAGI 执行

- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - 删除 `@/components/ui/textarea` import。
  - 新增 `InputArea` from `@cloudflare/kumo/components/input`。
  - 将 prompt 控件从 `<Textarea>` 改为 `<InputArea>`。
  - 保留 `id="ai-prompt"`、`adminTextareaClass`、`prompt` controlled value、`markDirty()` 语义。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 `AIProvider` prompt 直连 Kumo `InputArea` 的静态回归。
  - 禁止该页重新 import 本地 `textarea` wrapper。

### MAGI 提升

- 管理后台业务源码已经不再使用本地 `Textarea` wrapper。
- `components/ui/textarea.tsx` 现在是待确认删除的历史 wrapper；删除仍属于破坏性操作，需要单独确认。
- 下一轮可评估 `AIProvider` 的 `Accordion` 或 `Separator` 调用面；它们需要比 `InputArea` 更细的 DOM/行为对齐。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/textarea\|<Textarea" internal/server/web/admin/src internal/server/web/admin/components --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Kumo Separator AI provider direct migration

### MAGI 审视

- `AIProvider` 的分隔线只是单个水平 separator，不涉及弹层、键盘交互或复杂状态。
- Kumo `@cloudflare/kumo/primitives/separator` 直接导出 Base UI separator primitive，适合替代本地 wrapper 的这一处业务调用。
- 旧 wrapper 除了 `role` / `aria-orientation` 外，主要行为是保留 `h-px w-full shrink-0 bg-border` 的水平线样式；这一轮保留视觉 class，不扩大到 `ServerManagement`。
- `AIProvider` 的 `Accordion` 仍是多子组件组合，后续迁移需要单独对齐 `Root` / `Item` / `Trigger` / `Panel` 结构。

### MAGI 执行

- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - 删除 `@/components/ui/separator` import。
  - 新增 `Separator as KumoSeparator` from `@cloudflare/kumo/primitives/separator`。
  - 将本页 `<Separator />` 改为 `<KumoSeparator className="h-px w-full shrink-0 bg-border" />`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 `AIProvider` separator 直连 Kumo primitive 的静态回归。
  - 禁止该页重新 import 本地 `separator` wrapper 或恢复 `<Separator>` JSX。

### MAGI 提升

- `AIProvider` 已不再使用本地 `Textarea` / `Separator` wrapper，降低该页对历史 shadcn-style wrapper 的依赖。
- `ServerManagement` 仍使用本地 `Separator`，因此 `components/ui/separator.tsx` 不能在这一轮删除。
- 删除 dead wrapper 文件仍属于破坏性操作，必须等用户明确确认后再处理。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/separator" internal/server/web/admin/src --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 仅剩 `ServerManagement`。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Kumo Separator business cleanup

### MAGI 审视

- 只读核对确认 `ServerManagement` 是业务侧最后一个本地 `Separator` wrapper 调用面。
- 该调用仍是单个水平分隔线，只有额外的 `bg-slate-200 dark:bg-slate-800` 样式覆盖，不涉及状态、焦点或弹层语义。
- Base UI separator 在 Kumo primitive 链路中已提供 `role="separator"` 和 `aria-orientation`，调用点只需保留水平线尺寸和颜色 class。

### MAGI 执行

- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 删除 `@/components/ui/separator` import。
  - 新增 `Separator as KumoSeparator` from `@cloudflare/kumo/primitives/separator`。
  - 将 `<Separator className="bg-slate-200 dark:bg-slate-800" />` 改为 `<KumoSeparator className="h-px w-full shrink-0 bg-slate-200 dark:bg-slate-800" />`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 `AIProvider` / `ServerManagement` 业务页都直连 Kumo separator primitive 的静态回归。
  - 禁止业务页重新 import 本地 `separator` wrapper。

### MAGI 提升

- 管理后台业务源码已经不再 import `@/components/ui/separator`。
- `components/ui/separator.tsx` 现在属于待确认删除的历史 wrapper；删除文件仍需按破坏性操作流程等待明确确认。
- `AIProvider` 的 `Accordion` 仍依赖本地组合 wrapper 提供的 Header、Trigger、Panel、图标与动画 class，不能按 separator 的方式直接低风险替换。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/separator" internal/server/web/admin/src --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Kumo Badge business direct migration

### MAGI 审视

- `Badge` 业务调用只使用 `default`、`secondary`、`outline` 这类 Kumo 原生支持的 variant。
- 本地 `components/ui/badge.tsx` 只做旧 variant 映射和透传，不再需要作为业务页面的导入层。
- `badgeVariants` 在业务源码中没有调用，本轮无需保留页面级兼容函数。

### MAGI 执行

- `internal/server/web/admin/src/pages/AIProvider.tsx`
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 将 `@/components/ui/badge` import 改为 `@cloudflare/kumo/components/badge`。
  - JSX 保持原样，继续复用 `admin-ui` 中已有的语义化 class。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增业务页直连 Kumo `Badge` 的静态回归。
  - 禁止这些业务页重新 import 本地 `badge` wrapper。

### MAGI 提升

- 管理后台业务源码已经不再 import `@/components/ui/badge`。
- `components/ui/badge.tsx` 现在属于待确认删除的历史 wrapper；删除文件仍需按破坏性操作流程等待明确确认。
- `Input` / `Label` 虽然薄，但它们当前共同承担 label/id 关联和 accessible-name fallback，不适合按 Badge 的方式直接替换。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/badge" internal/server/web/admin/src --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Kumo DropdownMenu direct migration

### MAGI 审视

- `components/ui/dropdown-menu.tsx` 是纯 alias wrapper，只把 Kumo `DropdownMenu` compound members 拆成旧命名导出。
- 业务侧只有 `ServerManagement` 的分组选择器使用 `DropdownMenu` / `DropdownMenuTrigger` / `DropdownMenuContent`。
- Kumo `DropdownMenu.Trigger` 与 `DropdownMenu.Content` 直接支持当前使用的 `render`、`align`、`sideOffset`、`className`，不需要新增兼容层。

### MAGI 执行

- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 删除 `@/components/ui/dropdown-menu` import。
  - 新增 `DropdownMenu` from `@cloudflare/kumo/components/dropdown`。
  - 将旧 `DropdownMenuTrigger` / `DropdownMenuContent` 改为 `DropdownMenu.Trigger` / `DropdownMenu.Content`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增分组选择器直连 Kumo `DropdownMenu` 的静态回归。
  - 禁止该页恢复本地 `dropdown-menu` wrapper 或旧拆分组件名。

### MAGI 提升

- 管理后台业务源码已经不再 import `@/components/ui/dropdown-menu`。
- `components/ui/dropdown-menu.tsx` 现在属于待确认删除的历史 wrapper；删除文件仍需按破坏性操作流程等待明确确认。
- `Card` / `Accordion` / `ScrollArea` / `Sheet` 都是组合 wrapper，不能按纯 alias 的方式迁移。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/dropdown-menu" internal/server/web/admin/src --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin native scroll region simplification

### MAGI 审视

- `ScrollArea` 业务调用只存在于 `App` 两处：桌面侧边栏导航和主内容区域。
- 两处都只是固定区域内的垂直滚动，不需要 Base UI scroll-area 的 Root / Viewport / Scrollbar / Thumb / Corner 组合语义。
- 将 `@cloudflare/kumo/primitives/scroll-area` 组合逻辑搬入 `App` 只会把 wrapper 变成内联 wrapper；原生 `overflow-y-auto` 更直接，运行时组件更少。

### MAGI 执行

- `internal/server/web/admin/src/App.tsx`
  - 删除 `@/components/ui/scroll-area` import。
  - 将桌面侧边栏 `<ScrollArea className="flex-1 px-5 py-8">` 改为原生 `<div className="flex-1 overflow-y-auto px-5 py-8">`。
  - 将主内容 `<ScrollArea className="flex-1">` 改为原生 `<div className="flex-1 overflow-y-auto">`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 App 不再 import 本地 `ScrollArea` wrapper 的静态回归。
  - 锁定两个滚动区域的 `overflow-y-auto` class。

### MAGI 提升

- 管理后台业务源码已经不再 import `@/components/ui/scroll-area`。
- `components/ui/scroll-area.tsx` 现在属于待确认删除的历史 wrapper；删除文件仍需按破坏性操作流程等待明确确认。
- `Toaster` 不能直接迁到 Kumo `Toasty`：Kumo toast manager 与现有全项目 `sonner` API 不兼容，本轮不应做大范围 toast 系统重写。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/scroll-area\|<ScrollArea" internal/server/web/admin/src --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Sonner Toaster direct configuration

### MAGI 审视

- `Toaster` 只有 `App` 一个业务调用面，本地 `components/ui/sonner.tsx` 只是给 `sonner` 注入图标、CSS variables 和 toast class。
- Kumo `Toasty` 使用独立 toast manager，与当前全项目 `toast.success` / `toast.error` / `toast.warning` / `toast.message` 调用不兼容。
- 本轮不应重写 toast 系统；更直接的做法是在 `App` 中显式配置 `sonner` 的 `Toaster`，移除本地 wrapper 依赖。

### MAGI 执行

- `internal/server/web/admin/lib/admin-icons.ts`
  - 新增 `Info` 和 `OctagonX` 的按图标模块导入，保持图标入口集中管理。
- `internal/server/web/admin/src/App.tsx`
  - 将 `toast` / `Toaster` 统一从 `sonner` 直连导入。
  - 删除 `@/components/ui/sonner` import。
  - 将原 wrapper 的 success / info / warning / error / loading icons、CSS variables、`cn-toast` class 配置内联到唯一 `<Toaster>` 调用。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 App 直连 `sonner` Toaster 的静态回归。
  - 禁止业务侧重新 import 本地 `sonner` wrapper。

### MAGI 提升

- 管理后台业务源码已经不再 import `@/components/ui/sonner`。
- `components/ui/sonner.tsx` 现在属于待确认删除的历史 wrapper；删除文件仍需按破坏性操作流程等待明确确认。
- 如果未来要切到 Kumo `Toasty`，应作为独立 toast manager 迁移项目，而不是在这个 phase 做局部替换。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/sonner\|<Toaster" internal/server/web/admin/src internal/server/web/admin/components --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 仅剩 `App` 中一个 `<Toaster>` 调用。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Login Kumo Input Label direct migration

### MAGI 审视

- `Login` 只有两个真实表单输入：用户名和密码；captcha 区域只是外部 Turnstile 容器说明。
- 本地 `Input` wrapper 自动补 `name || id`、`w-full min-w-0` 和 `aria-labelledby` fallback；本地 `Label` wrapper 会按 `htmlFor` 派生 label id。
- Kumo `Input` 推荐显式提供 `label`、`aria-label` 或 `aria-labelledby`。对 Login 来说，直接在两个输入上写 `aria-label` 更清晰，不需要保留自动派生 wrapper。

### MAGI 执行

- `internal/server/web/admin/src/pages/Login.tsx`
  - 将 `Input` 改为从 `@cloudflare/kumo/components/input` 直连导入。
  - 将 `Label` 改为从 `@cloudflare/kumo/components/label` 直连导入。
  - 为 username/password 输入显式补 `aria-label={t("login.username")}` / `aria-label={t("login.password")}`。
  - 将 wrapper 原本补的 `w-full min-w-0` 写入输入 class，保留登录表单宽度行为。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 Login 直连 Kumo `Input` / `Label` 的静态回归。
  - 禁止 Login 回退本地 `input` / `label` wrapper。

### MAGI 提升

- `Login` 已不再使用本地 `Input` / `Label` wrapper。
- 其他页面仍有大量 Input/Label 调用，不应和 Login 混在一个 phase 中迁移；后续应按页面逐个显式处理 `name`、宽度 class 和 accessible-name。
- `components/ui/input.tsx` 与 `components/ui/label.tsx` 仍被其他页面使用，不能删除。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/input\|@/components/ui/label" internal/server/web/admin/src/pages/Login.tsx --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin ProbeSettings Kumo Input Label direct migration

### MAGI 审视

- `ProbeSettings` 有四个真实输入字段：name、host、port、interval；type 区域是按钮组，`Label` 只是视觉标题。
- 四个输入都已经显式有 `name`，不依赖本地 `Input` wrapper 的 `name || id` fallback。
- 本地 `Input` wrapper 原来隐式补 `aria-labelledby` 和 `w-full min-w-0`；直连 Kumo 后必须在页面中显式保留 accessible-name 和宽度行为。

### MAGI 执行

- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - 将 `Input` 改为从 `@cloudflare/kumo/components/input` 直连导入。
  - 将 `Label` 改为从 `@cloudflare/kumo/components/label` 直连导入。
  - 为 `probe-name` / `probe-host` / `probe-port` / `probe-interval` 显式补 `aria-label={t("probeSettings.field.*")}`。
  - 将四个输入 class 改为 `cn("w-full min-w-0", adminInputClass)`，保留原 wrapper 的宽度行为。
  - 保留现有 `name`、`aria-invalid`、`aria-describedby`、`type`、`min`、`max`、`inputMode` 和错误消息关联。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 ProbeSettings 直连 Kumo `Input` / `Label` 的静态回归。
  - 禁止 ProbeSettings 回退本地 `input` / `label` wrapper。

### MAGI 提升

- `ProbeSettings` 已不再使用本地 `Input` / `Label` wrapper。
- 其他页面的输入拓扑不同，不能和 ProbeSettings 混在同一 phase 批量替换。
- `components/ui/input.tsx` 与 `components/ui/label.tsx` 仍被 BasicSettings、AIProvider、NotificationAlert、ServerManagement、GroupManagement 使用，不能删除。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`
- `grep -RIn "@/components/ui/input\|@/components/ui/label" internal/server/web/admin/src/pages/ProbeSettings.tsx --include='*.tsx' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist` 返回无命中。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin GroupManagement Kumo Input direct migration

### MAGI 审视

- `GroupManagement` 的输入面由两个动态模板组成：一级分组名称和二级标签名称。
- 两个输入模板都已有稳定动态 `id` 与 `name`，不依赖本地 `Input` wrapper 的 `name || id` fallback。
- 两个输入模板都已有 `aria-label` 和错误 `aria-describedby`，直连 Kumo 后主要风险是丢失 wrapper 隐式补上的 `w-full min-w-0`。
- 本 phase 只迁移 `Input`，不混入 `Button` / `Card`，避免把表单语义迁移扩大成布局重构。

### MAGI 执行

- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - 将 `Input` 改为从 `@cloudflare/kumo/components/input` 直连导入。
  - 删除 `@/components/ui/input` import。
  - 一级分组输入保留 `adminWideInputClass`，并显式补 `w-full min-w-0`。
  - 二级标签输入保留原视觉 class，并显式补 `min-w-0`。
  - 保留动态 `id`、`name`、`aria-label`、`aria-invalid`、`aria-describedby` 和错误消息 id。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 GroupManagement 直连 Kumo `Input` 的静态回归。
  - 锁定动态 group/tag 输入的 `id`、`name`、`aria-label`、宽度 class 和错误 id。

### MAGI 提升

- `GroupManagement` 已不再使用本地 `Input` wrapper。
- 当前剩余 `Input` / `Label` wrapper 调用主要集中在 BasicSettings、AIProvider、ServerManagement；它们字段更多，后续必须继续按页面审视，不能批量替换。
- 动态表单模板迁移的规则可以复用：只要 `id/name/aria` 已显式存在，wrapper 迁移的核心是把宽度与最小宽度约束写回页面。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：31 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin AIProvider Kumo Input Label direct migration

### MAGI 审视

- `AIProvider` 已经直连 Kumo `InputArea`、`Select`、`Badge` 和 separator，但普通 `Input` / `Label` 仍来自本地 wrapper。
- 普通输入字段包括 display-name、api-key、base-url、model。迁移前这些字段缺显式 `name`，依赖本地 `Input` wrapper 的 `name || id` fallback。
- 本地 `Input` wrapper 还会补 `w-full min-w-0` 和 `aria-labelledby` fallback；直连 Kumo 后需要把 `name`、accessible-name 和宽度约束全部写在页面上。
- `API Key` 和 `Base URL` 是可见硬编码 label，本轮纳入 i18n。
- `ai-command-provider-label` 是 Select 的 `aria-labelledby` 目标，不是原生 input label；Kumo `Label` 类型不接受 `id`，因此改为语义更直接的 `span id=...`。

### MAGI 执行

- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - 将 `Input` / `InputArea` 统一从 `@cloudflare/kumo/components/input` 直连导入。
  - 将 `Label` 改为从 `@cloudflare/kumo/components/label` 直连导入。
  - 删除 `@/components/ui/input` / `@/components/ui/label` import。
  - 为四个普通输入显式补动态 `name`。
  - 为 display-name、api-key、base-url、model 显式补 `aria-label={t("aiProvider.field.*")}`。
  - 将四个普通输入 class 改为 `w-full min-w-0 ${adminInputClass}`，保留原 wrapper 的宽度行为。
  - 将 prompt `InputArea` 补 `aria-label={t("aiProvider.field.prompt")}`。
  - 将 `API Key` / `Base URL` label 改为 i18n 字典文案。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增 `aiProvider.field.apiKey`。
  - 新增 `aiProvider.field.baseURL`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 AIProvider 普通输入直连 Kumo `Input` / `Label` 的静态回归。
  - 强化 prompt `InputArea` 的 `aria-label` 断言。
- `internal/server/web/admin-i18n.test.mjs`
  - 锁定新增 AIProvider 字典键。

### MAGI 提升

- `AIProvider` 已不再使用本地 `Input` / `Label` wrapper。
- 页面级表单语义不再依赖 wrapper 的隐式 name 与 label-id fallback。
- Kumo `Label` 的 prop 范围比本地 wrapper 窄。对非 label 场景应使用原生语义元素承载 id，而不是为了保持旧写法再造兼容层。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：32 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin BasicSettings Kumo Input Label direct migration

### MAGI 审视

- `BasicSettings` 有 14 个普通输入，覆盖后台路径、管理员账号、密码、防爆破策略、Turnstile、Agent、站点展示等配置。
- 这些输入已有显式 `name`，但依赖本地 `Input` wrapper 隐式补 `w-full min-w-0` 和 `aria-labelledby` fallback。
- `Site Key`、`Secret Key`、`Agent Token`、预览区 `Title` 是可见硬编码文案，本轮纳入 i18n。
- 密码提示和 Agent token 提示原本只是视觉说明，迁移时一并补稳定 id 并通过 `aria-describedby` 关联到输入。

### MAGI 执行

- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 将 `Input` 改为从 `@cloudflare/kumo/components/input` 直连导入。
  - 将 `Label` 改为从 `@cloudflare/kumo/components/label` 直连导入。
  - 删除 `@/components/ui/input` / `@/components/ui/label` import。
  - 为 14 个输入显式补 `aria-label={t("basicSettings.field.*")}`。
  - 将普通输入 class 改为 `cn("w-full min-w-0", adminInputClass)`；Agent token 保留 `font-mono`。
  - 为 admin password 和 agent token 提示补 `id`，并通过 `aria-describedby` 绑定。
  - 将 Turnstile、Agent token、预览 Title 文案改为 i18n 字典文案。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增 `basicSettings.field.turnstileSiteKey`。
  - 新增 `basicSettings.field.turnstileSecretKey`。
  - 新增 `basicSettings.field.agentToken`。
  - 新增 `basicSettings.preview.title`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 BasicSettings 直连 Kumo `Input` / `Label` 的静态回归。
  - 锁定 14 个输入的 `id`、`name`、`aria-label`、宽度 class 和 hint 描述链。
- `internal/server/web/admin-i18n.test.mjs`
  - 锁定新增 BasicSettings 字典键。

### MAGI 提升

- `BasicSettings` 已不再使用本地 `Input` / `Label` wrapper。
- 敏感字段的 autocomplete、password type、URL input mode、placeholder 和状态更新逻辑保持不变。
- 页面现在显式持有表单可访问语义，不再依赖 wrapper 生成 label id。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：33 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin ServerManagement Kumo Input Label direct migration

### MAGI 审视

- `ServerManagement` 是最后一个仍使用本地 `Input` / `Label` wrapper 的业务页面。
- 输入面包括节点搜索、节点资料编辑、TCP 探测间隔、生命周期到期时间。
- 固定输入已有稳定 `name`，但搜索输入缺 `id`，动态 TCP interval 输入缺 `id`。本地 wrapper 原本隐式补 `name || id`、`w-full min-w-0` 和 label fallback。
- `node-renew-plan-label` 是 Select 的 `aria-labelledby` 目标，不是原生 input label；Kumo `Label` 不接受 `id` prop，因此改为原生 `span id=...`。
- 页面里 `Interval` 和节点详情 `Node ID` 是可见硬编码；本轮改为 i18n 或复用已有字典键。

### MAGI 执行

- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 将 `Input` 改为从 `@cloudflare/kumo/components/input` 直连导入。
  - 将 `Label` 改为从 `@cloudflare/kumo/components/label` 直连导入。
  - 删除 `@/components/ui/input` / `@/components/ui/label` import。
  - 为搜索输入补 `id="node-search"`，保留 `name="node-search"`。
  - 为固定编辑输入显式补 `aria-label={t("server.*")}`。
  - 为动态 TCP interval 输入补动态 `id`，保留动态 `name` 和 `aria-label`。
  - 将固定输入 class 改为 `w-full min-w-0 ${formInputClass}`，搜索输入和 interval 输入也显式保留宽度与最小宽度约束。
  - 将 Select 的 renew label 改为 `<span id="node-renew-plan-label">`。
  - 将 `Node ID` 改为 `t("server.node.id")`。
  - 将 `Interval` 改为 `t("server.probe.intervalShortLabel")`。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增 `server.probe.intervalShortLabel`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 ServerManagement 直连 Kumo `Input` / `Label` 的静态回归。
  - 锁定搜索、固定编辑输入、动态 probe interval、Select label 和硬编码文案替换。
- `internal/server/web/admin-i18n.test.mjs`
  - 锁定新增 ServerManagement 字典键。

### MAGI 提升

- 管理后台业务源码已经没有 `@/components/ui/input` / `@/components/ui/label` import。
- 本地 `Input` / `Label` wrapper 仍存在于 `components/ui` 中，但已没有业务调用者；删除文件属于破坏性清理，需单独确认后执行。
- 最后一个大页面迁移验证显示：Kumo direct import 能覆盖现有场景，不需要继续保留兼容 wrapper 作为业务依赖。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：34 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin AIProvider Kumo Accordion direct migration

### MAGI 审视

- `AIProvider` 是本地 `Accordion` wrapper 的唯一业务调用者。
- 本地 wrapper 只是把 Kumo primitive 的 `Root` / `Item` / `Header` / `Trigger` / `Panel` 组合成旧命名，并额外注入默认 class 与展开图标。
- Kumo primitive 已直接暴露这些 member；本轮不需要保留本地兼容 wrapper。

### MAGI 执行

- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - 删除 `@/components/ui/accordion` import。
  - 新增 `KumoAccordion` from `@cloudflare/kumo/primitives/accordion`。
  - 将 `Accordion` / `AccordionItem` / `AccordionTrigger` / `AccordionContent` 改为 `KumoAccordion.Root` / `Item` / `Header` / `Trigger` / `Panel`。
  - 保留 `multiple`、provider item `value={item.id}`、原有 item class、trigger class、panel animation class 和内容间距。
  - 将原 wrapper 中的展开/收起图标显式放到触发器内，使用集中图标入口的 `ChevronDown` / `ChevronUp`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 AIProvider 直连 Kumo Accordion primitive 的静态回归。
  - 禁止该页回退本地 accordion wrapper 或旧拆分组件名。

### MAGI 提升

- 管理后台业务源码已经不再 import `@/components/ui/accordion`。
- 对 compound primitive 的迁移规则是：直接使用 Kumo compound members，并把必要 class 与图标写在调用点，而不是再建一层同名兼容组件。
- 剩余本地 UI import 主要是 Button、Card、Sheet 等更大布局/交互组件，应继续分 phase 处理。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：35 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Login Kumo Button direct migration

### MAGI 审视

- `Login` 有两个 icon-only 顶部操作按钮和一个表单提交按钮。
- 本地 `Button` wrapper 会把旧 `size="icon"` 映射为 Kumo `shape="square"` / `size="base"`，把旧 `variant="default"` 映射为 `variant="primary"`。
- Login 按钮不依赖本地 wrapper 的 `render` / `nativeButton` 分支，适合直接迁移到 Kumo Button。

### MAGI 执行

- `internal/server/web/admin/src/pages/Login.tsx`
  - 将 `Button` 改为从 `@cloudflare/kumo/components/button` 直连导入。
  - 删除 `@/components/ui/button` import。
  - 将语言和主题 icon-only 按钮显式设置为 `shape="square"`、`size="base"`、`variant="outline"`。
  - 将提交按钮显式设置为 `variant="primary"`，保留 `type="submit"`、disabled 状态和原 class。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 Login 直连 Kumo `Button` 的静态回归。
  - 锁定 icon-only 按钮和 submit 按钮的显式 Kumo props。

### MAGI 提升

- `Login` 已不再使用本地 `Button` wrapper。
- 对 Button 的迁移不能机械替换：旧 `size="icon"` 必须改成 Kumo 的 `shape="square"`，否则会丢 icon-only 语义和类型约束。
- 其他页面的 Button 用法包含 `variant="ghost"`、`render`、`nativeButton={false}`、danger icon 等不同分支，应继续分页面迁移。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：36 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin NotificationAlert Kumo Button direct migration

### MAGI 审视

- `NotificationAlert` 有三个普通按钮：保存配置、测试 Telegram、测试飞书。
- 这些按钮不使用本地 Button wrapper 的 `render` / `nativeButton` / icon-only 分支。
- 本地 `variant="outline"` 可以直接映射到 Kumo `variant="outline"`；保存按钮原本依赖 default variant，直迁时需要显式写 `variant="primary"`。

### MAGI 执行

- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - 将 `Button` 改为从 `@cloudflare/kumo/components/button` 直连导入。
  - 删除 `@/components/ui/button` import。
  - 保存按钮显式设置 `variant="primary"`。
  - 两个测试按钮保留 `variant="outline"`、disabled 状态、click handler 和原 class。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 NotificationAlert 直连 Kumo `Button` 的静态回归。
  - 锁定保存按钮和两个测试按钮的关键 props。

### MAGI 提升

- `NotificationAlert` 已不再使用本地 Button wrapper。
- 普通 Button 迁移必须显式写出 default 到 Kumo primary 的映射，避免依赖旧 wrapper 默认值。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：37 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin AIProvider Kumo Button direct migration

### MAGI 审视

- `AIProvider` 有保存、添加兼容服务商、获取模型、测试连接、删除兼容服务商等普通按钮。
- 这些按钮不使用本地 Button wrapper 的 `render` / `nativeButton` / icon-only 分支。
- 保存按钮原本依赖旧 wrapper default variant，直连 Kumo 时需要显式写 `variant="primary"`；其他操作按钮保留 `variant="outline"`。

### MAGI 执行

- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - 将 `Button` 改为从 `@cloudflare/kumo/components/button` 直连导入。
  - 删除 `@/components/ui/button` import。
  - 保存按钮显式设置 `variant="primary"`。
  - 其他 provider 操作按钮保留 `variant="outline"`、disabled 状态、click handler 和原 class。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 AIProvider 直连 Kumo `Button` 的静态回归。
  - 锁定保存、添加、获取模型、测试、删除按钮的关键 props。

### MAGI 提升

- `AIProvider` 已不再使用本地 Button wrapper。
- Button direct 迁移的关键是把旧 wrapper 默认值显式化，而不是新增一层映射函数。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：38 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin ProbeSettings Kumo Button direct migration

### MAGI 审视

- `ProbeSettings` 按钮包含创建、保存、编辑、删除、类型切换和弹窗提交。
- 本地 Button wrapper 的主要隐式行为是 `size="icon"` 到 Kumo `shape="square"` 的映射，以及 default variant 到 primary 的映射。
- 页面不使用 `render` / `nativeButton` 分支，可以直连 Kumo Button。

### MAGI 执行

- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - 将 `Button` 改为从 `@cloudflare/kumo/components/button` 直连导入。
  - 删除 `@/components/ui/button` import。
  - 保存类按钮显式设置 `variant="primary"`。
  - 编辑和删除 icon-only 按钮显式设置 `shape="square"`、`size="base"`。
  - 保留 outline 按钮、aria-label、disabled 状态、click handler 和原 class。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 ProbeSettings 直连 Kumo `Button` 的静态回归。
  - 锁定 primary/outline、icon-only 映射和关键 handler。

### MAGI 提升

- `ProbeSettings` 已不再使用本地 Button wrapper。
- icon-only 按钮迁移时必须显式表达 Kumo 的 shape/size，而不是继续使用旧 `size="icon"` 语义。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：39 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin GroupManagement Kumo Button direct migration

### MAGI 审视

- `GroupManagement` 按钮包含创建分组、保存、添加标签和删除标签。
- 本地 Button wrapper 的关键隐式行为是 default 到 primary、`size="icon"` 到 square icon-only 的映射。
- 删除一级分组使用 Kumo Dialog Trigger，不属于本地 Button wrapper 调用。

### MAGI 执行

- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - 将 `Button` 改为从 `@cloudflare/kumo/components/button` 直连导入。
  - 删除 `@/components/ui/button` import。
  - 保存按钮显式设置 `variant="primary"`。
  - 创建分组和添加标签按钮保留 `variant="outline"`、disabled 状态、click handler 和原 class。
  - 删除标签 icon-only 按钮显式设置 `shape="square"`、`size="base"`、`variant="ghost"`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 GroupManagement 直连 Kumo `Button` 的静态回归。
  - 锁定保存、添加、删除标签按钮的关键 props。

### MAGI 提升

- `GroupManagement` 已不再使用本地 Button wrapper。
- Button 迁移保持页面级显式映射，避免新增跨页面兼容 adapter。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：40 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin BasicSettings Kumo Button direct migration

### MAGI 审视

- `BasicSettings` 已切到 Kumo `Button` import，但 release notes 链接仍残留旧 wrapper 的 `nativeButton/render` 分支。
- 直连 Kumo 后，普通操作按钮需要显式写出 `type="button"`；保存和启动更新按钮需要显式映射为 `variant="primary"`。
- release notes 是链接语义，应该使用 Kumo `LinkButton`，而不是用 Button 包一层 render adapter。

### MAGI 执行

- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 保存、检查更新、启动更新和导出按钮改为直连 Kumo `Button` 的显式属性。
  - 保存和启动更新按钮设置 `variant="primary"`。
  - release notes 改为 Kumo `LinkButton`，删除 `nativeButton/render`。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 BasicSettings 直连 Kumo `Button/LinkButton` 的静态回归。
  - 锁定 primary/outline、button type、release notes 链接语义和关键 handler。

### MAGI 提升

- `BasicSettings` 已不再使用本地 Button wrapper。
- 链接按钮应保持 anchor 语义，避免为了迁移 Kumo 继续保留旧 wrapper 的 render 分支。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：41 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin ServerManagement Kumo Button direct migration

### MAGI 审视

- `ServerManagement` 剩余本地 Button wrapper 覆盖刷新、安装平台切换、agent update、分组触发器、删除触发器和编辑器 footer。
- 旧 wrapper 的关键行为是 default 到 Kumo `primary`、默认 `type="button"`。
- 平台切换按钮原来用 `variant="outline"` 加 primary class 表达选中态，直连 Kumo 后应把 Kumo variant 本身同步为动态 primary/outline。

### MAGI 执行

- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 将 `Button` 改为从 `@cloudflare/kumo/components/button` 直连导入。
  - 删除 `@/components/ui/button` import。
  - 刷新按钮补显式 `type="button"`。
  - 安装平台切换按钮改为动态 `primary/outline`。
  - agent update 和保存按钮显式设置 `variant="primary"`。
  - 保留 DropdownMenu/KumoDialog Trigger 的 render 结构，但内部按钮已经是 Kumo Button。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 ServerManagement 直连 Kumo `Button` 的静态回归。
  - 锁定动态平台 variant、primary/outline、button type、trigger render 和关键 handler。

### MAGI 提升

- `ServerManagement` 已不再使用本地 Button wrapper。
- wrapper default 行为迁移时必须落到组件 props，而不是继续依赖样式 class 弥补语义。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：42 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin App Kumo Button and mobile drawer direct migration

### MAGI 审视

- `App.tsx` 是最后一个本地 Button wrapper 使用点，也是移动端导航 Sheet wrapper 的唯一使用点。
- 本地 Sheet wrapper 只是包了一层 Kumo dialog primitive；继续使用会让后台 shell 仍依赖本地 facade。
- Sheet wrapper 内部有硬编码 `Close` 文案；迁移时应改为后台 i18n key。

### MAGI 执行

- `internal/server/web/admin/src/App.tsx`
  - 将 shell 按钮改为从 `@cloudflare/kumo/components/button` 直连导入。
  - icon-only 按钮显式设置 `shape="square"`、`size="base"` 和 `type="button"`。
  - 移动端导航抽屉改为 `@cloudflare/kumo/primitives/dialog` 的 `Root/Trigger/Portal/Backdrop/Popup/Close`。
  - 删除 `@/components/ui/sheet` import。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增 `app.action.closeNav` 中英文文案。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 App shell 按钮和移动端抽屉直连 Kumo 的静态回归。

### MAGI 提升

- 管理后台页面层已没有本地 Button wrapper import。
- 移动端抽屉保持 dialog primitive 语义，不再经过 Sheet facade。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：43 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin LayerCard direct migration

### MAGI 审视

- 页面层剩余的本地 UI wrapper 只剩 `@/components/ui/card`。
- Kumo `LayerCard` 只提供容器和 `Primary/Secondary` 区块，不提供本地 wrapper 中的 Header/Title/Content/Footer 子组件。
- 继续保留本地 Card facade 会让页面层仍存在 shadcn 风格组件入口，不符合本轮直连 Kumo 的目标。

### MAGI 执行

- `internal/server/web/admin/src/App.tsx` 和 `internal/server/web/admin/src/pages/*.tsx`
  - 将 Card 容器改为 `@cloudflare/kumo/components/layer-card` 的 `LayerCard`。
  - 将 Header/Title/Description/Content/Footer 改为原生 `div`，保留现有 className。
  - 删除所有页面层 `@/components/ui/card` import。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 LayerCard 直连回归。
  - 新增页面层禁止 `@/components/ui/*` import 的总闸测试。

### MAGI 提升

- 管理后台 `src` 页面层已不再依赖本地 UI wrapper。
- 本地 wrapper 文件暂不删除，避免在当前脏 worktree 中做破坏性清理；真正删除需要单独确认影响面。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：45 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`

## 2026-06-09 / Admin Kumo button type hardening and rendered smoke

### MAGI 审视

- 本地 Button wrapper 原先默认 `type="button"`。
- 页面层直连 Kumo Button 后，非 submit 按钮如果不显式写 `type`，未来放进 form 时会退回 HTML 默认 submit 行为。
- Vite 单独启动时只能可靠验证未登录入口；已登录后台数据依赖后端 API，本轮用静态回归覆盖页面层组件迁移。

### MAGI 执行

- `internal/server/web/admin/src/pages/Login.tsx`
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
- `internal/server/web/admin/src/pages/AIProvider.tsx`
- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - 为所有 Kumo Button 补齐显式 `type`。
  - 登录提交按钮保留 `type="submit"`。
- 使用 Vite dev server + headless Chrome CDP 验证未登录首屏。

### MAGI 提升

- Kumo Button direct migration 不再依赖 wrapper default。
- 未来新增后台按钮时，应显式声明 `type`，除非它明确是 form submit。

### 验证记录

- Button type 检测脚本：`missing=0`。
- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：45 pass，0 fail。
- `git diff --check`
- `npm --prefix internal/server/web/admin run lint`
- `npm --prefix internal/server/web/admin run build:admin`
- `npm --prefix internal/server/web/admin run dev -- --host=127.0.0.1 --port=3000`：实际占用端口 `http://127.0.0.1:3003/`。
- Headless Chrome CDP smoke：
  - page title：`CyberMonitor Admin`
  - login first screen：pass
  - framework overlay：none
  - locale button：state changed
  - theme button：`dark -> light`
  - mobile viewport：login first screen pass
  - console warnings/errors：none
  - screenshots：`/tmp/cm-admin-kumo-desktop-final.png`、`/tmp/cm-admin-kumo-mobile-final.png`
- 环境备注：容器 `fc-list :lang=zh` 无 CJK 字体，中文截图会显示方框；项目 CSS 已配置 `PingFang SC` / `Microsoft YaHei` / system fallback。

## 2026-06-09 / Admin Kumo and i18n global validation

### MAGI 审视

- 本轮后台迁移已覆盖页面层所有 `@/components/ui/*` import。
- Kumo registry 采用官方组件路径，例如 `@cloudflare/kumo/components/button`、`@cloudflare/kumo/components/input`、`@cloudflare/kumo/components/layer-card` 和 primitive dialog/accordion/separator。
- i18n 已覆盖后台 shell、登录页和主要管理页面，并用字典 parity 测试防止中英文 key 漏配。

### MAGI 执行

- 全局搜索确认 `internal/server/web/admin/src` 与 `internal/server/web/admin/lib` 不再 import 本地 UI wrapper。
- 执行统一本地验证入口。
- 补充 Kumo/i18n 静态测试和 Go race 目标。

### MAGI 提升

- 页面层已切到直接消费 Kumo 组件；本地 wrapper 文件暂未删除，避免在当前大 worktree 中做破坏性清理。
- 若后续要删除 `components/ui/*` wrapper，应先单独确认没有测试、storybook、历史脚本或外部引用依赖这些文件。

### 验证记录

- `scripts/verify-local.sh`：pass。
  - shell syntax checks：pass。
  - script/workflow/admin API/public asset regression：33 pass，0 fail。
  - `npm --prefix internal/server/web/admin ci --cache .cache/npm`：pass。
  - admin `tsc --noEmit`：pass。
  - admin `vite build`：pass。
  - `go vet ./...`：pass。
  - `go test ./...`：pass。
- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：45 pass，0 fail。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。
- `grep -RIn '@/components/ui/' internal/server/web/admin/src internal/server/web/admin/lib`：no matches。
- 浏览器验证：
  - Browser 插件入口缺少 `node_repl` JS tool，未能按 Browser skill 直接驱动。
  - Playwright MCP fallback 因 Chrome profile 缺少 Playwright Extension 被阻断。
  - 使用 headless Chrome CDP fallback 完成未登录入口 smoke：pass。

## 2026-06-09 / Admin direct dependency cleanup

### MAGI 审视

- 页面层已经不再使用本地 UI wrapper，继续检查 package 里的直接依赖是否仍带着迁移前残留。
- `@fontsource-variable/geist` 和 `@phosphor-icons/react` 在源码中没有 import。
- `@phosphor-icons/react` 仍会作为 Kumo peer dependency 出现在 lockfile，这是 Kumo 传递/peer 解析结果，不应作为项目直接依赖保留。
- `class-variance-authority` 仍被未删除的 `components/ui/alert.tsx` 和 `components/ui/tabs.tsx` 编译引用；当前不做删除，避免破坏 TypeScript 覆盖范围。
- `lucide-react` 仍被 `lib/admin-icons.ts` 按图标分包直接使用，不能移除。

### MAGI 执行

- `internal/server/web/admin/package.json`
  - 删除无源码引用的 `@fontsource-variable/geist`。
  - 删除无源码引用的 `@phosphor-icons/react`。
- `internal/server/web/admin/package-lock.json`
  - 通过 `npm --prefix internal/server/web/admin install --package-lock-only --cache /SourceCode/CyberMonitor/.cache/npm` 更新 lockfile。
- `internal/server/web/admin-kumo.test.mjs`
  - 将原先“必须声明 Phosphor 直接依赖”的断言改为“禁止无源码引用的直接依赖”。

### MAGI 提升

- Kumo 作为唯一组件库直接入口保留。
- 对 Kumo peer dependency 的 lockfile 解析和项目直接依赖做区分，避免把传递依赖误判成项目冗余。

### 验证记录

- `npm --prefix internal/server/web/admin install --package-lock-only --cache /SourceCode/CyberMonitor/.cache/npm`：pass，0 vulnerabilities。
- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：45 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build:admin`：pass。
- `git diff --check`：pass。

## 2026-06-09 / Admin Vite local UI chunk branch cleanup

### MAGI 审视

- 页面层已经禁止 `@/components/ui/*` import。
- `internal/server/web/admin/vite.config.ts` 仍保留 `/components/ui/ -> admin-ui` 的 manual chunk 分支。
- 这个分支已经没有当前入口会命中，继续保留属于面向旧 wrapper 的冗余兼容路径。

### MAGI 执行

- `internal/server/web/admin/vite.config.ts`
  - 删除 `/components/ui/` 特例分支。
  - 保留第三方 `node_modules` / Kumo / `components` / `lib` 的直接分类。
- `internal/server/web/admin-kumo.test.mjs`
  - 将 chunk 回归改为禁止 `admin-ui` 旧分支回归。
  - 保留 Kumo runtime 不落入 local components/lib chunks 的断言。

### MAGI 提升

- 构建分块策略和页面层直连 Kumo 的事实保持一致。
- 不再为已废弃的本地 UI wrapper 保留“未来兼容”分支。

### 验证记录

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：45 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build:admin`：pass，构建输出无 `admin-ui` chunk。
- `git diff --check`：pass。

## 2026-06-09 / Admin API fallback i18n closure

### MAGI 审视

- 子审计指出 `lib/admin-api.ts` 的中文 fallback 会绕过当前 locale。
- 实际检查确认 API helper 覆盖登录、设置、节点、更新、告警、AI 等多处 fallback，不只是单点问题。
- 纯 API 层不应 import React i18n hook；本地化文案应由调用层传入。

### MAGI 执行

- `internal/server/web/admin/lib/admin-api.ts`
  - 所有 API helper 改为接收 `fallbackMessage: string`。
  - 删除纯 API 层内置中文 fallback。
- `internal/server/web/admin/src/App.tsx`
  - 所有 API 调用传入 `t("api.error.*")`。
  - `SectionLoader` 去掉英文默认值，调用方必须传入本地化 label。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增 `api.error.*` 中英文错误 fallback 字典。
- `internal/server/web/admin-i18n.test.mjs`
  - 新增 API fallback 静态测试。
  - 将 `admin-api.ts` 纳入“纯逻辑层不得出现中文文案”检查。

### MAGI 提升

- 错误 fallback 现在由 UI locale 驱动，API helper 保持纯数据层职责。
- 新增测试会阻止后续直接在 API helper 写回中文提示。

### 验证记录

- `node --test internal/server/web/admin-i18n.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-kumo.test.mjs`：49 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `grep -RIn --exclude='admin-i18n.tsx' '[一-龥]' internal/server/web/admin/src internal/server/web/admin/lib`：no matches。
- `npm --prefix internal/server/web/admin run build:admin`：pass。

## 2026-06-09 / Admin devDependency cleanup

### MAGI 审视

- `autoprefixer`、direct `postcss`、`tsx` 在 admin 源码、脚本和配置中没有直接引用。
- 当前 admin 使用 Tailwind v4 + Vite 插件，没有 `postcss.config.*` 或 `tailwind.config.*`。
- `postcss` 仍由 Vite 传递依赖提供；项目不需要声明 direct devDependency。

### MAGI 执行

- `internal/server/web/admin/package.json`
  - 删除 direct devDependencies：`autoprefixer`、`postcss`、`tsx`。
- `internal/server/web/admin/package-lock.json`
  - 通过 npm 重算 lockfile，审计包数从 131 降到 118。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增断言，禁止这三项在无直接引用时回到 admin direct devDependencies。

### MAGI 提升

- Admin package 只保留实际直连的构建依赖。
- 本地 `node_modules` 里仍可能残留 extraneous 包；本轮不做 prune，避免删除型环境清理影响当前脏工作树。

### 验证记录

- `grep -RInE 'autoprefixer|postcss|tsx' internal/server/web/admin --exclude-dir=node_modules --exclude='package-lock.json' --exclude-dir=dist`：仅命中技术扩展名、`components.json` 旧配置和 package 变更前位置。
- `npm --prefix internal/server/web/admin install --package-lock-only --cache /SourceCode/CyberMonitor/.cache/npm`：pass，118 packages，0 vulnerabilities。
- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-api.test.mjs`：49 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build:admin`：pass。

## 2026-06-09 / Admin Kumo i18n validation refresh

### MAGI 审视

- API fallback 签名变更后，旧的删除节点静态测试仍匹配 `deleteNodeProfile(nodeID)`。
- 这属于测试断言没有跟随 API i18n 形态更新，不是删除节点业务逻辑回退。
- `scripts/verify-local.sh` 仍是主验证入口，但它会执行 `npm ci` 重建 `node_modules`；本轮未做删除型环境清理。

### MAGI 执行

- `internal/server/web/admin-delete-node.test.mjs`
  - 将断言更新为 `deleteNodeProfile(nodeID, t("api.error.deleteNode"))`。
  - 保留 partial success 不重复 success toast 的业务约束。

### MAGI 提升

- 当前验证覆盖 Kumo 直连、i18n fallback、forwarded-prefix、public assets、release workflow、installer、Go server/agent/updater。
- 若要完全复刻 `scripts/verify-local.sh`，需要允许 `npm ci` 对 admin `node_modules` 做重建。

### 验证记录

- `bash -n scripts/verify-local.sh scripts/build-local.sh scripts/install-common.sh scripts/agent.sh scripts/one-click.sh scripts/agent-uninstall.sh`：pass。
- `sh -n scripts/docker-entrypoint.sh`：pass。
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`：79 pass，0 fail。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go vet ./...`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./...`：pass。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `git diff --check`：pass。

## 2026-06-09 / Runtime dependency latest refresh

### MAGI 审视

- 继续接手时必须以当前 worktree 为准；两个 subagent sidecar 均因上游 503 失败，本轮不把 sidecar 结果作为完成证据。
- 官方实时检查显示：
  - Go latest 为 `go1.26.4`，当前 `go.mod` 和 `Dockerfile` 均已使用 `1.26.4`。
  - Node latest release 为 `v26.3.0`，当前 `Dockerfile ARG NODE_IMAGE_VERSION=26.3.0`，GitHub Actions 通过该 ARG 派生 `actions/setup-node` 版本输入。
- `npm --prefix internal/server/web/admin outdated --json --cache .cache/npm` 返回 `{}`，admin 直接 npm 依赖无可更新项。
- `npm view @types/node version` 返回 `25.9.2`，因此不强行写不存在的 26.x type 包。
- `go list -m -u` 显示 Go 直接依赖仍有新版，应直接升级，不新增兼容包装。

### MAGI 执行

- `go.mod` / `go.sum`
  - 升级 Go 直接依赖：
    - `github.com/docker/go-connections` `v0.6.0` -> `v0.7.0`
    - `github.com/prometheus/prometheus` `v0.311.2` -> `v0.312.0`
    - `golang.org/x/crypto` `v0.50.0` -> `v0.53.0`
    - `golang.org/x/net` `v0.53.0` -> `v0.55.0`
    - `golang.org/x/sys` `v0.43.0` -> `v0.46.0`
    - `google.golang.org/grpc` `v1.80.0` -> `v1.81.1`
  - 执行 `go mod tidy`，让间接依赖随直接依赖自然收敛。

### MAGI 提升

- “latest 组件”应以当前官方版本和 package manager 查询为准，不能沿用旧记忆。
- 本机 Node runtime 是 `v25.9.0`，仓库代码无法直接升级本机运行时；CI/Docker 侧已通过 `NODE_IMAGE_VERSION=26.3.0` 固定到最新 release。
- 后续继续全局验证时必须设置 `TMPDIR=/SourceCode/CyberMonitor/.tmp`；未设置时 Go 会写 `/tmp`，当前 `/tmp` 可用空间不足，容易把环境问题误判成编译问题。

### 验证记录

- `curl -fsSL https://go.dev/VERSION?m=text`：`go1.26.4`，timestamp `2026-05-29T15:26:39Z`。
- `curl -fsSL https://nodejs.org/dist/index.json`：首条 release 为 `v26.3.0`，date `2026-06-01`。
- `node --version`：`v25.9.0`。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go version`：`go version go1.26.4 linux/amd64`。
- `npm --prefix internal/server/web/admin outdated --json --cache /SourceCode/CyberMonitor/.cache/npm`：`{}`。
- `npm --prefix internal/server/web/admin view @types/node version --cache /SourceCode/CyberMonitor/.cache/npm`：`25.9.2`。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go list -m -u -f '{{if not .Indirect}}{{with .Update}}{{$.Path}} {{$.Version}} -> {{.Version}}{{end}}{{end}}' all`：直接依赖无剩余 update 输出。
- 首次局部 Go 测试因漏设 `TMPDIR` 写满 `/tmp` 失败；复跑时设置 `TMPDIR=/SourceCode/CyberMonitor/.tmp` 后通过。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/updater ./internal/server -run 'Test(Replacement|WaitReplacement|BuildReplacement|LaunchDocker|CleanupOld|RollbackCreated|SystemUpdate|DockerManaged|AgentUpdateReleaseAsset|SystemUpdateReleaseAsset)' -count=1`：pass。
- `scripts/verify-local.sh`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。
- `scripts/build-local.sh`：pass，生成 `dist/cyber-monitor-server-local` 和 `dist/cyber-monitor-agent-local`。

## 2026-06-09 / Admin local UI wrapper removal

### MAGI 审视

- `internal/server/web/admin/src` 和 `internal/server/web/admin/lib` 已经全部直接 import Kumo 组件或 primitive。
- 全仓扫描显示 `@/components/ui/*` 只剩 `components/ui` 目录内部自引用，以及 `admin-kumo.test.mjs` 对 wrapper 存在性的旧断言。
- `components.json` 仍保留 `ui: "@/components/ui"` alias，会诱导后续把旧 shadcn 风格入口生成回来。
- 这些 wrapper 已经不是业务抽象，而是未被入口引用的兼容层，继续保留不符合“简洁直接、禁止冗余兼容包装”。

### MAGI 执行

- 删除 `internal/server/web/admin/components/ui/*.tsx` 本地 UI wrapper 文件。
- `internal/server/web/admin-kumo.test.mjs`
  - 删除“wrapper 必须存在并 import Kumo”的旧断言。
  - 新增 `admin no longer keeps local UI wrapper entrypoints`，锁定 `components/ui` 下不得再有 `.ts/.tsx` wrapper 文件。
  - 保留页面层直接使用 Kumo Button/Input/Label/Dialog/Select/Badge/LayerCard/Separator 等断言。
- `internal/server/web/admin/components.json`
  - 删除旧 `ui` alias，避免新代码再次生成到 `@/components/ui`。
- `internal/server/web/admin/lib/lucide-icon-modules.d.ts`
  - 删除旧 `lucide-react/dist/esm/icons/*.mjs` ambient module 声明。
  - 当前 `admin-icons.ts` 已使用 public `lucide-react` entrypoint，该声明不再提供有效价值。

### MAGI 提升

- Admin UI 的组件边界现在变成单一路径：页面层直接消费 Kumo 和少量原生元素，不再保留本地兼容 facade。
- 未来若需要共享样式，优先放入 `lib/admin-ui.ts` 这类纯 class/helper，而不是重建同名 UI wrapper。
- 删除型收敛必须用搜索、静态测试、TypeScript 和 build 同时证明入口图没有遗漏。
- 类型声明只服务仍在使用的 import 形态；当源码已经切到 public package entrypoint，应删除旧子路径声明，避免形成隐藏兼容层。

### 验证记录

- `grep -RIn --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.gocache --exclude-dir=.gomodcache '@/components/ui/' internal/server/web/admin .github scripts || true`：no matches。
- `find internal/server/web/admin/components -maxdepth 3 -type f -print | sort`：no output。
- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs`：45 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build:admin`：pass。
- `grep -RIn --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.gocache --exclude-dir=.gomodcache 'lucide-react/dist/esm/icons\|lucide-icon-modules\|components/ui' internal/server/web/admin .github scripts || true`：no matches。
- `scripts/verify-local.sh`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。
- `scripts/build-local.sh`：pass。

## 2026-06-09 / Admin direct dependency cleanup after wrapper removal

### MAGI 审视

- 删除 `components/ui` wrapper 后，`class-variance-authority` 只剩 `package.json` / `package-lock.json` 声明。
- 源码、测试和配置扫描未发现 `class-variance-authority`、`cva(` 或 `VariantProps` 仍被使用。
- `clsx` / `tailwind-merge` 仍由 `lib/utils.ts` 使用，`tw-animate-css` 仍由 `src/index.css` 使用，`@dnd-kit/*` 仍由 `GroupManagement.tsx` 使用，`sonner`、`lucide-react`、`@cloudflare/kumo` 均仍有业务引用，不能删除。

### MAGI 执行

- `internal/server/web/admin/package.json`
  - 删除 direct dependency `class-variance-authority`。
- `internal/server/web/admin/package-lock.json`
  - 使用 `npm --prefix internal/server/web/admin install --package-lock-only --cache /SourceCode/CyberMonitor/.cache/npm` 重算，审计包数从 118 降到 117。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增断言，禁止 `class-variance-authority` 在本地 UI variant wrapper 删除后回到 direct dependencies。

### MAGI 提升

- 删除本地 UI wrapper 后，要同步清理 wrapper 专属 direct dependencies；否则 package 仍然表达了不存在的代码路径。
- direct dependency 的删除边界必须由源码引用、lockfile、TypeScript 和构建共同证明，不能只靠人工判断。

### 验证记录

- `grep -RIn --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.gocache --exclude-dir=.gomodcache -E 'class-variance-authority|cva\(|VariantProps' internal/server/web/admin .github scripts || true`：no matches。
- `npm --prefix internal/server/web/admin install --package-lock-only --cache /SourceCode/CyberMonitor/.cache/npm`：pass，117 packages，0 vulnerabilities。
- `node --test internal/server/web/admin-kumo.test.mjs`：40 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build:admin`：pass。
- `npm --prefix internal/server/web/admin outdated --json --cache /SourceCode/CyberMonitor/.cache/npm`：`{}`。
- `scripts/verify-local.sh`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。
- `scripts/build-local.sh`：pass。

## 2026-06-09 / Docker-managed update target image and cleanup bounds

### MAGI 审视

- Docker-managed update 仍是当前仓库的高风险语义路径。
- `ResolveDockerTargetImage` 原先用空字符串表达解析失败，server 和 agent 两个真实入口会把失败推迟到 helper 启动层。
- agent 侧在解析目标镜像前就上报 `updating`，当当前容器镜像是 image ID / digest 这类不可重新打 tag 的输入时，会产生无意义的 `updating -> failed` 状态噪声。
- helper start 失败后的清理、替换容器失败后的 rollback 原先存在无边界 `context.Background()` 清理路径；这类路径应脱离已取消父 context，但必须有短超时。

### MAGI 执行

- `internal/updater/docker_managed.go`
  - `ResolveDockerTargetImage` 改为返回 `(string, error)`。
  - 使用 `github.com/distribution/reference` 解析 Docker image reference，拒绝空 current image、空 target version、纯 image ID / digest 等不可打 tag 输入。
  - helper start 失败后的未启动 helper 清理改为 `context.WithTimeout(context.WithoutCancel(ctx), dockerCleanupTimeout)`。
  - 替换容器失败 rollback 同样使用 bounded cleanup context，避免无限挂住。
- `internal/server/server.go`
  - Docker-managed server update 初始化 updater 和启动 helper 共用同一个 10 分钟任务 context。
  - helper 启动前先解析目标镜像，失败时返回明确的“解析 Docker 目标镜像失败”错误。
- `internal/agent/agent.go`
  - agent Docker-managed 更新在上报 `updating` 前解析目标镜像。
  - 解析失败时只上报 `failed`，不启动 helper，不制造状态噪声。
- `internal/updater/docker_managed_test.go` / `internal/agent/agent_update_test.go` / `internal/server/update_assets_test.go`
  - 覆盖 target image 成功解析、digest repository retag、空输入、image ID / digest 拒绝。
  - 覆盖 agent target image 解析失败时不启动 detached helper。
  - 锁定 cleanup / rollback 使用 bounded independent context。

### MAGI 提升

- Docker image reference 不应再用手写字符串截断；已有标准 parser 时应使用结构化 API。
- 更新链路的错误表达要在靠近输入边界处显式失败，不能把“解析失败”伪装成下一层“缺少目标镜像”。
- 失败清理路径可以脱离父 context，但必须有固定超时；否则会在 Docker daemon 异常时把后台更新流程卡死。

### 验证记录

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater ./internal/agent ./internal/server -run 'TestResolveDockerTargetImage|TestMaybeApplyRemoteDockerUpdate|TestDockerManagedSystemUpdate|TestSystemUpdate' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater ./internal/agent ./internal/server`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。
- `git diff --check`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/build-local.sh`：pass，生成 `dist/cyber-monitor-server-local` 和 `dist/cyber-monitor-agent-local`。

## 2026-06-09 / System update in-progress error semantics

### MAGI 审视

- `systemUpdateManager.Start` 原先用 `context.Canceled` 表示“已有服务端更新任务正在执行”。
- 这是业务并发状态，不是调用方 context 被取消；继续复用 `context.Canceled` 会让调用方无法区分真正取消和更新冲突。

### MAGI 执行

- `internal/server/system_update.go`
  - 新增包内 sentinel `errSystemUpdateInProgress`。
  - `Start` 在已有任务运行时返回该 sentinel。
- `internal/server/server.go`
  - HTTP 层用 `errors.Is(err, errSystemUpdateInProgress)` 明确映射到 409。
  - 非预期 `Start` 错误不再被误报成“当前已有服务端更新任务正在执行”。
- `internal/server/system_update_test.go`
  - 并发 update 测试从断言 `context.Canceled` 改为断言业务 sentinel。

### MAGI 提升

- context 错误只用于取消、超时这类控制流；业务状态要用业务错误表达。
- 这样调用层可以继续保持现有 409 契约，同时内部语义更直接。

### 验证记录

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestSystemUpdate' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server`：pass。
- `grep -RIn --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.gocache --exclude-dir=.gomodcache "context.Canceled" internal/server 2>/dev/null`：no matches。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。

## 2026-06-09 / Explicit update version ordering semantics

### MAGI 审视

- 更新链路仍有 `CompareVersions` 直接参与 up-to-date 判断。
- `CompareVersions` 的历史行为会把不可解析版本解析成 `0.0.0`，例如 `unknown` / `dev` 这类非数字版本可能被隐式参与排序。
- 已有 `VersionsEqual` 能防止 `unknown` 和 `v0.0.0` 被当作相等，但 `HasUpdate` 和 up-to-date 判断仍需要显式区分“可比较版本”和“不可比较版本”。

### MAGI 执行

- `internal/updater/updater.go`
  - 新增 `HasVersionUpdate(current, latest)`，用于 release info 的 update availability。
  - 新增 `VersionCurrentOrNewer(current, latest)`，用于 up-to-date 跳过判断。
  - 新增 `parseComparableVersion`，只有可解析数字版本才参与排序；不可解析版本不再被隐式当成 `0.0.0`。
  - `VersionsEqual` 改为复用可比较版本解析，同时保留精确非数字版本相等。
- `internal/server/server.go`
  - system update 和 agent update 的 up-to-date 分支改用 `VersionCurrentOrNewer`。
- `internal/updater/updater_test.go`
  - 增加 `HasVersionUpdate`、`VersionCurrentOrNewer`、`buildReleaseInfo` 的 unknown/current 版本回归测试。

### MAGI 提升

- 版本比较应拆成两个问题：是否可排序、是否相等。
- “当前版本未知”不应被静默排序为 `0.0.0`；显式触发更新和跳过更新要使用不同语义函数。
- 后续若再新增更新入口，应禁止直接使用 `CompareVersions` 做业务判断，只能通过语义函数表达意图。

### 验证记录

- `grep -RIn --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.gocache --exclude-dir=.gomodcache "CompareVersions" internal/server internal/updater internal/agent 2>/dev/null`：只剩 `internal/updater/updater.go` 底层函数定义。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater ./internal/server -run 'TestVersionsEqual|TestHasVersionUpdate|TestVersionCurrentOrNewer|TestBuildReleaseInfo|TestSystemUpdate|TestAgentUpdate' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/updater ./internal/server ./internal/agent`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。

## 2026-06-09 / Agent update report state boundary

### MAGI 审视

- `agentAPI.reportUpdate` 原先只校验 node、token、update id 和版本，没有校验 Agent 上报的 update state。
- 空 state 会被内部改成 `unknown`，未知非空 state 会写进 profile，并通过 `agentUpdateLeaseForState` 获得 updating lease。
- Admin UI 只识别 `pending/updating/restarting/succeeded/failed`，未知 state 可能让后端持有未终止任务但前端显示为空闲。
- `pending` 是服务端内部排队状态，不应由 Agent report 上报。

### MAGI 执行

- `internal/server/server.go`
  - 增加 Agent update state 常量和 `normalizeAgentUpdateReportState`。
  - 允许 Agent report state 只包括 `updating`、`restarting`、`succeeded`、`failed`。
  - `pending` 保留为服务端内部状态。
  - `agentUpdateLeaseForState` 不再给未知 state 分配 updating lease。
  - Store 直调用 `ApplyAgentUpdateReport` 也不会把非法 state 写入 profile。
- `internal/server/agent_rpc.go`
  - `agentAPI.reportUpdate` 在 token 校验前后都不再接受非法 state，返回 bad request。
  - HTTP 自动映射为 400，gRPC 自动映射为 `InvalidArgument`。
- `internal/server/agent_update_test.go`
  - 覆盖 Store 直调用拒绝未知 state 和 `pending` state。
  - 覆盖 HTTP report 拒绝未知 state、缺失 state，并保持 pending update 不变。
  - 覆盖 gRPC report 拒绝未知 state，返回 `codes.InvalidArgument`。

### MAGI 提升

- 状态机必须有明确边界；不能用 `unknown` 这类无业务含义状态兜底。
- 入口拒绝非法状态比写入后再让 UI/lease 逻辑猜测更直接。
- 服务端内部状态和 Agent report 状态应分离，避免外部 report 污染队列状态。

### 验证记录

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentUpdate.*Report|TestAgentUpdate.*RPC|TestAgentUpdateQueue' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server`：pass。
- `grep -RIn --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.gocache --exclude-dir=.gomodcache -E 'AgentUpdateState = "unknown"|state = "unknown"|agentUpdateLeaseUpdating' internal/server 2>/dev/null`：只剩合法 `agentUpdateLeaseUpdating` 常量和 `updating` 分支。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。

## 2026-06-09 / Public websocket single variant path

### MAGI 审视

- `resolvePublicVariant` 无论 query 参数如何都返回 `balanced`。
- `publicVariantConservative` 没有有效入口，但 ticker 广播仍保留 `hasConservative` 和额外广播分支。
- 这是一条不可达兼容分支，会让 public websocket 广播逻辑看起来有两套模式，实际运行只有一套。

### MAGI 执行

- `internal/server/server.go`
  - 删除 `publicVariantConservative`。
  - 删除 `resolvePublicVariant`。
  - WebSocket client 统一注册为 `publicVariantBalanced`。
  - ticker 广播只检查 balanced 客户端，并保留 digest 去重广播。
- `internal/server/update_assets_test.go`
  - 新增源码级 guard，禁止 `publicVariantConservative`、`hasConservative`、`resolvePublicVariant` 回流。

### MAGI 提升

- 如果 runtime 只有一个有效模式，就不保留半截 variant 分支。
- 后续若确实需要新的 public websocket variant，应先给明确入口、行为差异和测试，再引入分支。

### 验证记录

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestPublicWebSocketUsesSingleBalancedVariant|Test.*WebSocket|TestServer.*Route|Test.*ForwardedPrefix' -count=1`：pass。
- `grep -RIn --include='*.go' --exclude='*_test.go' --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.gocache --exclude-dir=.gomodcache -E 'publicVariantConservative|hasConservative|resolvePublicVariant|variant=conservative' internal/server || true`：no matches。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server`：pass。
- `node --test internal/server/web/public-assets.test.mjs`：5 pass，0 fail。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。

## 2026-06-09 / Agent update queue explicit status

### MAGI 审视

- `QueueAgentUpdate` 原先用 bool 组合表达“节点不存在”“已有活跃任务”“新任务已排队”。
- 生成 update ID 失败时也会落到 `ok=false`，admin handler 会把内部错误误报为 `node not found`。
- 这类 bool 组合不利于后续扩展队列状态，也不符合“错误尽早明确表达”。

### MAGI 执行

- `internal/server/server.go`
  - 新增 `agentUpdateQueueStatus`，明确区分 `not_found`、`active`、`queued`。
  - `QueueAgentUpdate` 改为返回 `(NodeProfile, agentUpdateQueueStatus, error)`。
  - update ID 生成失败返回明确 error。
  - admin handler 将内部错误映射为 500，节点不存在映射为 404，活跃任务保持 `in_progress`。
  - 将 update ID 生成抽成包内 `newAgentUpdateID`，用于验证内部错误路径。
- `internal/server/agent_update_test.go`
  - 更新队列测试为枚举状态断言。
  - 新增 admin handler 内部 ID 生成失败返回 500 的回归测试。
  - 增加 `queueAgentUpdateForTest` helper，减少重复 bool 判断。

### MAGI 提升

- 多 bool 返回值只适合非常简单的二元状态；队列/状态机应使用命名状态。
- HTTP handler 不应把内部错误降级成 404，这会误导调用者和排障。
- 后续如继续扩展 Agent update queue，应优先扩展状态枚举，而不是继续堆 bool。

### 验证记录

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentUpdate' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server`：pass。
- `grep -RIn --exclude-dir=.git --exclude-dir=.cache --exclude-dir=.gocache --exclude-dir=.gomodcache "queuedNew\\|QueueAgentUpdate(.*ok" internal/server 2>/dev/null`：no matches。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。

## 2026-06-09 / Second cycle global verification

### MAGI 审视

- 本轮 Docker update、system update、version ordering、Agent report、public websocket、Agent queue 的局部修复都已落到统一验证入口。
- 当前生产源码里 `QueueAgentUpdate` 只剩枚举状态返回；`evolution_log.md` 早期段落里的 `ok/queuedNew` 是历史记录，不是当前接口。
- 项目内没有额外 `AGENTS.md` 约束；搜索到的 `AGENTS.md` 都位于 Go module cache，不覆盖本仓源码。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/build-local.sh`：pass。
- `git diff --check`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go vet ./...`：pass。
- `grep -R --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.cache --exclude-dir=.gocache --exclude-dir=.gomodcache "queuedNew\\|QueueAgentUpdate(nodeID" -n . 2>/dev/null`：生产源码只剩 `QueueAgentUpdate` 当前枚举状态实现和调用；旧 `queuedNew` 只出现在历史日志。

### MAGI 提升

- 第二轮语义收敛可以进入下一轮审视。
- 下一轮重点不再放在 update 状态机本身，而应抽查大 diff 中的前端重写、admin API path contract、public asset runtime contract 是否存在测试未覆盖的行为漂移。

## 2026-06-09 / Admin path reload contract

### MAGI 审视

- 设置保存和配置导入在 `admin_path` 变化后只调用 `history.replaceState`。
- 这只会改浏览器地址栏，不会重新拉取新的 admin HTML 和 boot payload。
- 在带 `X-Forwarded-Prefix` 的部署下，直接使用 `settings.admin_path` 还会丢失反代 prefix，例如当前页面在 `/cm/old-admin/` 时会跳到 `/new-admin`。

### MAGI 执行

- `internal/server/web/admin/lib/admin-api.ts`
  - 新增 `adminAppPath(adminPath)`，复用现有 boot base path normalization，生成带 forwarded prefix、带尾斜杠的 admin app 路径。
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 保存设置和导入配置后，如果 `admin_path` 变化，改为 `window.location.assign(adminAppPath(...))`。
  - 不再只做 `history.replaceState`，避免旧 HTML/boot payload 继续运行。
- `internal/server/web/admin/src/App.tsx`
  - 移除导入配置后的重复 `history.replaceState`。
- `internal/server/web/admin-api.test.mjs`
  - 覆盖 forwarded prefix 下 admin app path 生成。
  - 覆盖非法 admin path 返回空路径。

### MAGI 验证

- `node --test internal/server/web/admin-api.test.mjs`：3 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/build-local.sh`：pass。

### MAGI 提升

- 影响当前 HTML boot payload 的配置变更应触发 reload，而不是用 History API 伪装 URL 已切换。
- 后续抽查同类路径变更时，先区分“SPA 内部 page state”和“服务端路由/boot payload state”。

## 2026-06-09 / Public decorative background cleanup

### MAGI 审视

- public 首页仍保留 `bg-orb` / `orb-a` / `orb-b` / `orb-c` 装饰节点。
- 这些节点只提供模糊色块背景，不承载业务信息，也不符合当前前端约束中“不要使用 orb/bokeh 背景装饰”的要求。

### MAGI 执行

- `internal/server/web/public/index.html`
  - 删除三个 orb 装饰节点。
- `internal/server/web/public/assets/styles.css`
  - 删除 orb 样式、`float` keyframes 和 reduced-motion 中的 orb 引用。
- `internal/server/web/public-assets.test.mjs`
  - 新增静态测试，禁止 public HTML/CSS/JS 重新引入 `bg-orb` 或 `orb-a/b/c`。

### MAGI 验证

- `node --test internal/server/web/public-assets.test.mjs`：6 pass，0 fail。
- `grep -R --exclude-dir=node_modules --exclude-dir=dist "bg-orb\\|orb-a\\|orb-b\\|orb-c\\|@keyframes float" -n internal/server/web/public internal/server/web/admin 2>/dev/null`：no matches。
- `git diff --check`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/build-local.sh`：pass。

### MAGI 提升

- public 页背景应由页面底色、布局层次和数据卡片承担，不再依赖无语义装饰节点。
- 后续 UI 调整优先减少不可交互装饰，避免增加移动端重绘和审美噪音。

## 2026-06-09 / Rendered frontend smoke

### MAGI 审视

- Browser 专用入口未暴露可执行的 Node REPL 工具，Chrome DevTools MCP 连接用户 Chrome 失败，Playwright MCP 仍报扩展缺失。
- 继续使用既定 fallback：本地临时 server + headless Chrome CLI + DevTools Protocol。
- Chrome stderr 中的 Crashpad、DBus、fontconfig、NSS 报错来自当前容器只读系统目录，不影响页面 DOM 和截图输出。

### MAGI 执行

- 使用临时数据目录 `.tmp/browser-smoke-data` 启动 `go run ./cmd/server`，监听 `127.0.0.1:25213`。
- 使用 headless Chrome 打开 public `/` 和 admin `/admin-smoke/`。
- 使用截图验证 desktop/mobile 首屏：
  - `/tmp/cm-public-smoke-wait.png`
  - `/tmp/cm-admin-smoke-wait.png`
  - `/tmp/cm-public-smoke-mobile.png`
  - `/tmp/cm-admin-smoke-mobile.png`
- 使用 DevTools Protocol 做最小交互：
  - public theme button：`data-theme` 从 `light` 切到 `dark`。
  - admin locale button：页面 locale 从 `zh-CN` 切到 `en-US`，登录按钮文案变为 `Log in`。

### MAGI 验证

- `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:25213/api/v1/health`：200。
- `curl -s -i http://127.0.0.1:25213/`：200，public HTML 中不再有 orb 节点。
- `curl -s -i http://127.0.0.1:25213/admin-smoke/`：200，admin HTML 注入 boot payload，bundle 资源使用相对 `./assets/...`。
- `google-chrome --headless=new ... --dump-dom http://127.0.0.1:25213/`：DOM 包含 `CyberMonitor`、统计卡片和 empty state。
- `google-chrome --headless=new ... --dump-dom http://127.0.0.1:25213/admin-smoke/`：DOM 包含登录页和表单控件。
- DevTools Protocol interaction smoke：public theme toggle pass；admin locale toggle pass。
- `lsof -nP -iTCP:25213 -sTCP:LISTEN`：no listener after smoke。

### MAGI 提升

- 当前环境不能依赖 Browser/Playwright extension；渲染验证应保留 headless Chrome CLI + CDP fallback。
- 若后续需要完整表单流和 console health，应优先修复 Browser/Playwright extension 环境，再扩展交互覆盖。

## 2026-06-09 / Admin settings contract cleanup

### MAGI 审视

- 后端仍在 `Settings` / `SettingsView` / `SettingsUpdate` 暴露 `alert_all` 与 `alert_nodes`，但当前告警实际由每节点 `alert_enabled` 控制。
- 子代理只读审视确认 4 个 admin/backend 契约风险：
  - AI Provider test/models endpoint 会把空草稿字段与旧保存值合并。
  - Basic Settings 清空 `admin_path` 时前端会静默省略字段，导致保存成功但实际不变。
  - Probe Settings 会接受 `:::`、`2001:::1` 等非法 IPv6。
  - Notification Alert 前端会放行 localhost/private webhook URL，而后端会拒绝。
- `strictUnmarshalJSON` 只检查单个 JSON 值和尾随内容，没有 `DisallowUnknownFields`；旧导出或旧 state 中的 `alert_all` / `alert_nodes` 可安全忽略。

### MAGI 执行

- `internal/server/persist.go`
  - 删除 `alert_all` / `alert_nodes` 的持久化、view、update 字段和默认/merge 逻辑。
- `internal/server/server.go`
  - 删除 settings view/update/export/import 中的废弃 alert 过滤字段。
  - AI test/models request 的 `config` 改为可选指针；存在 `config` 时按草稿完整覆盖，不再把空字段合并回旧保存值。
- `internal/server/ai.go`
  - 删除 `mergeAIProviderOverride` 的非空字段合并语义。
- `internal/server/web/admin/lib/admin-types.ts`
  - 删除 `SettingsView.alert_all` / `alert_nodes` 类型。
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - `admin_path` / `admin_user` 只要相对当前 settings 发生变化就提交，包括空字符串。
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - IPv6 校验改为 URL bracket parse，拒绝 malformed IPv6 和 zone id。
- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - webhook 校验补齐 localhost、private IPv4、IPv4-mapped IPv6、`fc00::/7`、`fe80::/10`、loopback/unspecified 拒绝。
- 新增测试：
  - `internal/server/settings_contract_test.go`
  - `internal/server/ai_contract_test.go`
  - `internal/server/web/admin-frontend-contract.test.mjs`

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(SettingsContracts|ImportConfigIgnores|AIProviderOverride)' -count=1`：pass。
- `node --test internal/server/web/admin-frontend-contract.test.mjs`：3 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/build-local.sh`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go vet ./...`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater`：pass。
- `git diff --check`：pass。

### MAGI 提升

- Admin settings API 的表单 payload 应优先采用“草稿完整语义”，避免 test/save 两条路径对空值含义不同。
- 前端 validator 要么与后端边界保持等价，要么明确更严格；不能比后端更宽。
- 废弃字段删除前要先确认历史 JSON 解码策略；当前项目允许未知字段，因此可删除公开契约同时兼容旧导入。

## 2026-06-09 / Webhook callback contract tightening

### MAGI 审视

- 第五轮聚焦程序代码运行时契约，未深入 GitHub Actions 或构建脚本。
- Agent update 的 HTTP/gRPC `update_id` 主链路已闭合：server 下发 ID，agent report 回传 ID，server 以 ID + version 拒绝 stale report。
- admin/public path helper 与 server forwarded prefix 约束基本对齐，没有发现更高置信 runtime mismatch。
- 上一轮 webhook 前端校验已经覆盖 private/loopback/link-local unicast，但仍漏掉后端 `net.IP.IsLinkLocalMulticast()` 对应的 link-local multicast 边界：
  - IPv4 `224.0.0.0/24`
  - IPv4-mapped IPv6，例如 `::ffff:224.0.0.1`
  - IPv6 `ff02::/16`
- 结果是前端仍可能允许提交这类 webhook URL，后端随后拒绝，形成前后端契约不一致。
- 本轮子代理用于只读审视 agent update/path runtime contract，但两次等待均超时，已关闭；本轮结论不依赖其输出。

### MAGI 执行

- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - `isPrivateIPv4Host()` 增加 `224.0.0.0/24` 拒绝。
  - `isPrivateIPv6Host()` 增加 `ff02::/16` 拒绝。
  - IPv4-mapped IPv6 继续走 `parseIPv4MappedIPv6Host()` 后套用同一 IPv4 规则。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 增加 `224.0.0.1`、`::ffff:224.0.0.1`、`ff02::1` 前端拒绝断言。
- `internal/server/settings_contract_test.go`
  - 增加 server 侧 `validateWebhookURL()` private callback host 回归，覆盖前端同一组关键样例。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：3 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestWebhookRejects|TestSettingsContracts|TestImportConfigIgnores|TestAIProviderOverride' -count=1`：pass。
- `git diff --check`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。

### MAGI 提升

- 安全边界类前端校验必须以 server helper 为源头逐项映射，不能只覆盖常见 private IP。
- 下一轮可继续按“后端 helper -> 前端 validator -> 双侧测试”的方式审计 AI base URL、webhook、agent endpoint 等 URL 输入。

## 2026-06-09 / Agent endpoint base URL contract

### MAGI 审视

- 第六轮继续聚焦程序代码 URL/endpoint 输入契约，未深入 GitHub Actions、Dockerfile 或构建脚本。
- `agent_endpoint` 是持久化配置，会被 admin 的 Server Management 用于生成 Linux/Windows Agent 安装命令。
- 后端此前只做 `strings.TrimSpace()` 并直接保存，导致以下值可以进入配置：
  - `monitor.example.com`
  - `ftp://monitor.example.com`
  - `https://user:pass@monitor.example.com`
  - 带 query/fragment 的 URL
- 这些值会让安装命令生成不可用或含敏感/多余 URL 结构。前端输入框虽然是 `type="url"`，但这不是可依赖的业务校验。
- 注意：`agent_endpoint` 不是服务端主动回调 URL，不能套 webhook 的 private-host 拒绝规则；内网和 localhost 部署是合理场景。
- 本轮子代理因上游 403 失败，没有可用审视结果；本轮结论来自主线程 live worktree 审视。

### MAGI 执行

- `internal/server/server.go`
  - 新增 `validateAgentEndpoint()`。
  - 空值允许，表示继续由 split mode 注入 public addr 或留空。
  - 非空必须是绝对 `http` / `https` URL，必须有 host。
  - 拒绝 username/password、query、fragment，保持安装命令只接收 base URL。
  - `UpdateSettings()` 写入 `AgentEndpoint` 前先校验，失败时回滚 settings。
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 新增 `isValidAgentEndpoint()`，保存前用同一规则拦截。
  - 非法值直接 toast，不发请求。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 增加中英文校验文案。
- `internal/server/settings_contract_test.go`
  - 覆盖后端 agent endpoint 允许/拒绝样例。
  - 覆盖 `UpdateSettings()` 拒绝非法 endpoint 后不污染现有配置。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 覆盖前端 Basic Settings agent endpoint validator。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：4 pass，0 fail。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AgentEndpoint|UpdateSettingsRejects|WebhookRejects|SettingsContracts|ImportConfigIgnores|AIProviderOverride)' -count=1`：pass。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `git diff --check`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。

### MAGI 提升

- URL 字段不要混用一套校验规则；先区分字段语义：
  - webhook / callback：禁止 private、loopback、link-local。
  - agent endpoint：允许内网部署，但必须是干净 base URL。
  - AI base URL：下一轮应确认是否允许私有网关；若允许，应改成“base URL 结构校验”，不要复用 callback private-host 规则。

## 2026-06-09 / AI base URL contract split

### MAGI 审视

- 第七轮继续沿用“后端 helper -> 前端 validator -> 双侧测试”模式，聚焦程序代码，不深入构建脚本。
- `validateAIBaseURL()` 此前复用 `validateHTTPCallbackURL()`。
- 这个规则对 webhook 是正确的，因为 webhook 是 server 主动回调外部地址，必须拒绝 private/loopback/link-local。
- 对 AI base URL 则不正确：
  - OpenAI-compatible 的常见用法包括本机 Ollama、内网 LiteLLM、私有 AI gateway。
  - `http://localhost:11434/v1`、`https://10.0.0.2:8443/v1` 这类 base URL 应该允许。
- 需要拆分语义：
  - callback URL：保留 private-host 拒绝。
  - base URL：只校验结构为干净的 `http` / `https` base URL。

### MAGI 执行

- `internal/server/server.go`
  - 新增 `validateHTTPBaseURL()`。
  - 空值允许。
  - 非空必须是绝对 `http` / `https` URL，必须有 host。
  - 拒绝 username/password、query、fragment。
  - `validateAgentEndpoint()` 改为复用 `validateHTTPBaseURL()`。
  - `validateHTTPCallbackURL()` 保持原 private-host 拒绝规则。
- `internal/server/ai.go`
  - `validateAIBaseURL()` 改为复用 `validateHTTPBaseURL()`。
  - AI base URL 不再因为 localhost/private IP 被误拒。
- `internal/server/web/admin/lib/admin-ai.ts`
  - 新增 `isValidAIBaseURL()`，与后端 base URL 结构规则对齐。
- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - test provider、fetch models、save 三个入口都先校验 base URL。
  - 非法 base URL 不发请求，直接 toast。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 增加中英文 base URL 校验文案。
- `internal/server/ai_contract_test.go`
  - 覆盖 private/local AI gateway base URL 允许。
  - 覆盖无协议、非 http(s)、凭据、query、fragment 拒绝。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 覆盖前端 AI base URL validator 的同一组样例。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：5 pass，0 fail。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AIBaseURL|AIProviderOverride|AgentEndpoint|UpdateSettingsRejects|WebhookRejects)' -count=1`：pass。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- URL 校验函数要按数据流命名和分层：
  - `validateHTTPCallbackURL()` 用于 server 出站回调，保留 SSRF 风险边界。
  - `validateHTTPBaseURL()` 用于用户配置的服务 base URL，允许内网但禁止不干净 URL 结构。
- 下一轮可继续审计其他 URL 字段是否仍误用 callback 规则，或缺少 base URL 双侧测试。

## 2026-06-09 / Admin base URL validator consolidation

### MAGI 审视

- 第八轮继续审计 URL/endpoint 校验语义。
- 当前服务端已经拆清两类规则：
  - `validateHTTPCallbackURL()`：用于 webhook/callback，保留 private-host 拒绝。
  - `validateHTTPBaseURL()`：用于服务 base URL，允许内网，但禁止 credentials/query/fragment。
- 前端仍有重复实现：
  - Basic Settings 内联 `isValidAgentEndpoint()`。
  - AI Provider 在 `admin-ai.ts` 内提供 `isValidAIBaseURL()`。
- 两者规则完全相同，都是“干净 HTTP base URL”校验。
- 重复函数会让后续变更发生漂移，不符合“代码简洁直接、禁止冗余兼容包装”的目标。
- 本轮子代理已按旁路审视派出，但连续等待超时后关闭，没有可用输出；本轮依据来自主线程 live worktree 扫描与验证。

### MAGI 执行

- `internal/server/web/admin/lib/admin-url.ts`
  - 新增 `isValidHTTPBaseURL()` 共享 helper。
  - 空值允许。
  - 非空必须是 `http` / `https`，必须有 hostname。
  - 拒绝 username/password、query、fragment。
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 删除内联 `isValidAgentEndpoint()`。
  - Agent endpoint 保存前直接调用 `isValidHTTPBaseURL()`。
- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - test provider、fetch models、save 三个入口直接调用 `isValidHTTPBaseURL()`。
- `internal/server/web/admin/lib/admin-ai.ts`
  - 删除 `isValidAIBaseURL()`，AI 数据转换模块不再承载通用 URL 校验。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 契约测试改为直接验证共享 helper。
  - 同时锁定 Basic Settings 与 AI Provider 都从 `admin-url.ts` 引入 helper，避免重新复制。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：4 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- URL helper 应按语义归属放置：
  - 通用前端 base URL 规则放在 `admin-url.ts`。
  - AI provider 模块只保留 AI provider draft / payload / selection 逻辑。
  - 页面只做入口拦截和用户反馈，不复制底层解析规则。
- 下一轮可继续从重复前端 helper、状态转换函数、server/frontend 契约测试覆盖缺口中挑选高确定性问题。

## 2026-06-09 / Admin probe host validator consolidation

### MAGI 审视

- 第九轮继续聚焦前端程序代码里的重复 helper 和契约漂移风险。
- `ProbeSettings.tsx` 内联了 `isValidHost()` 与 `isValidIPv6Host()`。
- 这些函数不是页面渲染逻辑，而是测试节点 host 的输入契约。
- 同一文件已经承载 dialog、dirty state、save flow、展示格式等大量 UI 状态。
- 继续把 host parser 留在页面里，会让页面变重，也让契约测试只能从页面源码中脆弱抽取函数。
- 更直接的结构是：
  - `admin-url.ts` 负责 URL/host 类输入契约。
  - `ProbeSettings.tsx` 只负责调用 validator 并显示错误。

### MAGI 执行

- `internal/server/web/admin/lib/admin-url.ts`
  - 新增 `isValidProbeHost()`。
  - 保留和服务端 `isValidTestHost()` 对齐的核心规则：拒绝 URL、路径、空格；接受合法 IPv4/IPv6/hostname；拒绝 zone id IPv6。
  - 私有 IPv6 parser helper 保持模块内私有。
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - 删除页面内 `isValidHost()` / `isValidIPv6Host()`。
  - 表单校验改为调用 `isValidProbeHost()`。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 测试直接验证 `admin-url.ts` 的 probe host helper。
  - 同时锁定 `ProbeSettings.tsx` 只 import helper，不再复制 validator。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：4 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- 前端输入契约不要散落在页面组件里；页面应只做“调用 validator -> 聚焦错误字段 -> toast/文案”。
- `admin-url.ts` 现在承载 base URL 与 probe host 两类规则。
- 下一轮可以继续审计 notification webhook 的 private callback host validator 是否也应该从页面中抽出；但它带 SSRF 风险语义，抽取时必须保持 callback 专属命名，不能和 base URL helper 合并。

## 2026-06-09 / Admin callback URL validator consolidation

### MAGI 审视

- 第十轮继续处理前端 URL 输入契约的归属问题。
- `NotificationAlert.tsx` 内联了 webhook callback URL validator：
  - `isValidHTTPURL()`
  - `isPrivateCallbackHost()`
  - IPv4 / IPv6 private host 判断
  - IPv4-mapped IPv6 解析
- 这些逻辑属于安全边界，不属于页面渲染。
- 但它不能和 base URL helper 合并：
  - webhook callback 是 server 出站请求，必须拒绝 private/loopback/link-local/multicast。
  - AI base URL / agent endpoint 是用户配置的服务入口，需要允许内网部署。
- 因此本轮采用专属命名，避免后续误用。

### MAGI 执行

- `internal/server/web/admin/lib/admin-url.ts`
  - 新增 `isValidHTTPCallbackURL()`。
  - 保留 private callback host 判断与 IPv4-mapped IPv6 解析。
  - callback 私有判断 helper 仅在模块内私有，不暴露给页面。
- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - 删除页面内 `isValidHTTPURL()` 与 private host helper。
  - webhook 表单校验改为调用 `isValidHTTPCallbackURL()`。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 直接验证 `admin-url.ts` 的 callback URL helper。
  - 锁定 `NotificationAlert.tsx` 只 import callback helper，不再复制安全判断函数。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：4 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- URL 类前端契约已经形成清晰分层：
  - `isValidHTTPBaseURL()`：服务 base URL，允许内网，拒绝 credentials/query/fragment。
  - `isValidProbeHost()`：探测 host，拒绝 URL/path/空格，接受合法 IP/hostname。
  - `isValidHTTPCallbackURL()`：出站 callback URL，拒绝 private/loopback/link-local/multicast。
- 下一轮应继续检查 server/frontend 对这些语义的命名是否一致，避免再出现“看起来都是 URL，实际安全边界不同”的混用。

## 2026-06-09 / Malformed dotted IPv4 validator parity

### MAGI 审视

- 第十一轮检查前后端 URL/host validator 的样例契约是否一致。
- 发现高确定性差异：
  - 前端 WHATWG `URL` 与 `isValidProbeHost()` 会拒绝 `999.1.1.1` / `256.1.1.1` 这类 malformed dotted IPv4 literal。
  - 后端 `validateHTTPBaseURL()` / `validateHTTPCallbackURL()` 只检查 scheme/host/private host。
  - 后端 `isValidTestHost()` 在 `net.ParseIP(host) == nil` 后会进入 hostname 校验，可能把 `999.1.1.1` 当作 numeric hostname 接受。
- 这种值既不是合法 IPv4，也不是合理 hostname。
- 如果前端拒绝、后端接受，会产生 API 契约漂移；如果绕过前端直接调 API，则后端会保存无效探测 host 或 URL host。
- 本轮旁路子代理因上游 403 失败，没有可用输出；本轮依据来自主线程 live worktree 审视和测试。

### MAGI 执行

- `internal/server/persist.go`
  - 新增 `isMalformedDottedIPv4Host()`。
  - `isValidTestHost()` 在进入 `net.ParseIP()` / hostname fallback 前先拒绝 malformed dotted IPv4 literal。
- `internal/server/server.go`
  - `validateHTTPBaseURL()` 拒绝 malformed dotted IPv4 hostname。
  - `validateHTTPCallbackURL()` 拒绝 malformed dotted IPv4 hostname。
- `internal/server/ai_contract_test.go`
  - AI base URL 拒绝 `https://999.1.1.1/v1`。
- `internal/server/settings_contract_test.go`
  - Webhook callback 拒绝 `https://999.1.1.1/hook`。
  - Agent endpoint 拒绝 `https://999.1.1.1/cm`。
  - Test catalog 拒绝 `256.1.1.1` 和 `999.1.1.1`。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 前端 base URL、callback URL、probe host 测试加入同类样例，锁定双侧语义。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：4 pass，0 fail。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AIBaseURL|AgentEndpoint|Webhook|TestCatalog)' -count=1`：pass。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- 前后端 validator parity 不能只看“允许/拒绝大类”，还要覆盖边界样例：
  - malformed dotted IPv4
  - IPv4-mapped IPv6
  - multicast / link-local
  - URL credentials/query/fragment
- 下一轮可继续检查 server/frontend 对 IPv6 zone id、octal-like IPv4、hostname trailing dot 的处理是否一致；只修高确定性差异，避免引入兼容包装。

## 2026-06-09 / Callback trailing-dot localhost rejection

### MAGI 审视

- 第十二轮继续做 validator parity 审视，重点看 hostname trailing dot、IPv6 zone id、octal-like IPv4。
- 发现高确定性 callback 安全缺口：
  - `http://localhost./hook` 和 `http://api.localhost./hook` 是 localhost FQDN 形式。
  - 当前前端 `isPrivateCallbackHost()` 只判断 `host === "localhost"` 或 `.localhost` 后缀。
  - 当前后端 `validateHTTPCallbackURL()` 也只判断 `host == "localhost"` 或 `.localhost` 后缀。
  - trailing dot 会让 host 变成 `localhost.` / `api.localhost.`，绕过这条判断。
- 这是 callback 出站请求边界问题，不应该扩散到 base URL 规则。
- 本轮旁路子代理等待超时后关闭，没有可用输出；本轮依据来自主线程 live worktree 审视和验证。

### MAGI 执行

- `internal/server/server.go`
  - 新增 `canonicalCallbackHost()`。
  - callback host 先 lower-case、去 IPv6 方括号、再去 trailing dot。
  - `localhost.` / `api.localhost.` 会被规范化为 `localhost` / `api.localhost`，继续被 private callback 规则拒绝。
- `internal/server/web/admin/lib/admin-url.ts`
  - 前端 callback host 判断同样去 trailing dot。
  - 只作用于 `isValidHTTPCallbackURL()`，不改变 `isValidHTTPBaseURL()`。
- `internal/server/settings_contract_test.go`
  - Webhook callback 拒绝 `http://localhost./hook`、`http://api.localhost./hook`、`http://127.0.0.1./hook`。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 前端 callback URL validator 加入同样 trailing-dot 样例。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：4 pass，0 fail。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AIBaseURL|AgentEndpoint|Webhook|TestCatalog)' -count=1`：pass。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- callback URL 需要专属 canonicalization，不能复用 base URL 的宽松语义。
- trailing-dot 这类 DNS canonical form 应纳入 SSRF/private-host 测试样例。
- 下一轮可继续审视 octal-like IPv4 和 IPv6 zone id；如果前后端都已拒绝或语义一致，只记录结论，不做无效改动。

## 2026-06-09 / Ambiguous IPv4 literal validator parity

### MAGI 审视

- 第十三轮继续做前后端 URL/host validator parity。
- 发现高确定性差异：
  - 浏览器 WHATWG `URL` 会把 `0177.0.0.1` 解析为 `127.0.0.1`。
  - `0x7f.0.0.1`、`127.1`、`2130706433` 也会被浏览器解析为 IPv4 地址。
  - 后端 Go `url.Parse()` 不做这种 IPv4 literal 规范化。
  - 后端旧的 `isMalformedDottedIPv4Host()` 只覆盖四段十进制 malformed IPv4，不覆盖 octal/hex/short IPv4 形式。
- 结果是：前端可能按浏览器规则拒绝或规范化，后端可能把这些值当 hostname 接收。
- 对 callback URL，这是 SSRF/private-host 边界风险。
- 对 probe host 和 base URL，这是前后端契约漂移。
- 本轮旁路子代理等待超时后关闭，没有可用输出；本轮依据来自主线程 live worktree 审视和验证。

### MAGI 执行

- `internal/server/persist.go`
  - 将 `isMalformedDottedIPv4Host()` 替换为 `isAmbiguousIPv4LiteralHost()`。
  - 拒绝 octal-like、hex-like、short IPv4、单整数 IPv4 等容易被不同 URL parser 解释为 IP 的 host。
  - `isValidTestHost()` 进入 `net.ParseIP()` / hostname fallback 前先拒绝 ambiguous IPv4 literal。
- `internal/server/server.go`
  - `validateHTTPBaseURL()` 与 `validateHTTPCallbackURL()` 改为复用 `isAmbiguousIPv4LiteralHost()`。
- `internal/server/web/admin/lib/admin-url.ts`
  - 新增前端同名语义的 `isAmbiguousIPv4LiteralHost()`。
  - `isValidHTTPBaseURL()` / `isValidHTTPCallbackURL()` 使用 raw URL authority host 检查，避免浏览器先把 `0177.0.0.1` 规范化成 `127.0.0.1` 后丢失原始输入语义。
  - `isValidProbeHost()` 同步拒绝 ambiguous IPv4 literal。
- `internal/server/ai_contract_test.go`
  - AI base URL 拒绝 `https://0177.0.0.1/v1`。
- `internal/server/settings_contract_test.go`
  - Webhook callback 拒绝 `0177.0.0.1`、`0x7f.0.0.1`、`127.1`、`2130706433`。
  - Agent endpoint 拒绝 `https://0177.0.0.1/cm`。
  - Test catalog 拒绝同类 ambiguous IPv4 host。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 前端 base URL、callback URL、probe host 同步加入 ambiguous IPv4 拒绝样例。
  - 测试 loader 改为加载整个 `admin-url.ts` 模块源码，避免共享私有 helper 时测试只抽单个函数导致依赖缺失。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：4 pass，0 fail。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AIBaseURL|AgentEndpoint|Webhook|TestCatalog)' -count=1`：pass。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- 对 URL/host validator，不要依赖不同运行时对 host 的隐式规范化。
- 对可能被解析成 IP 的非标准 literal，要在 raw input 阶段统一拒绝。
- 下一轮应继续复核 IPv6 zone id 和 remaining raw-host parsing 边界；如果双侧已经一致拒绝，不做无意义改动。

## 2026-06-09 / IPv6 zone id validator parity

### MAGI 审视

- 第十四轮继续审视 raw-host parsing 边界。
- 发现高确定性差异：
  - 浏览器 WHATWG `URL` 会直接拒绝 `http://[fe80::1%25eth0]/hook` 和 `http://[::1%25lo0]/hook`。
  - 前端 probe host validator 也已经拒绝 `fe80::1%eth0`。
  - Go `url.Parse()` 不能作为唯一契约依据；后端需要显式拒绝含 zone id 的 URL host。
- IPv6 zone id 是本机网络接口作用域语义，不应该进入用户配置的 base URL、callback URL 或 probe host 契约。
- 本轮旁路子代理因上游 403 失败，没有可用输出；本轮依据来自主线程 live worktree 审视和验证。

### MAGI 执行

- `internal/server/server.go`
  - `validateHTTPBaseURL()` 显式拒绝 `parsed.Hostname()` 中包含 `%` 的 host。
  - `validateHTTPCallbackURL()` 在 callback host canonicalization 后显式拒绝 `%`。
- `internal/server/ai_contract_test.go`
  - AI base URL 拒绝 `https://[fe80::1%25eth0]/v1`。
- `internal/server/settings_contract_test.go`
  - Webhook callback 拒绝 `http://[fe80::1%25eth0]/hook` 与 `http://[::1%25lo0]/hook`。
  - Agent endpoint 拒绝 `https://[fe80::1%25eth0]/cm`。
  - Test catalog 拒绝 `fe80::1%eth0`。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 前端 base URL、callback URL、probe host 加入同类 zone id 拒绝样例，锁定双侧一致。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：4 pass，0 fail。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AIBaseURL|AgentEndpoint|Webhook|TestCatalog)' -count=1`：pass。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- 后端不能把 parser 可接受等同于产品契约可接受。
- URL/host 契约应显式拒绝 runtime 相关语义，例如 IPv6 zone id。
- 下一轮可从 URL/host parity 转向其他程序代码语义缺口，例如 agent update 状态、delete/import/export 契约，避免在同一层面过度打磨。

## 2026-06-09 / Import refresh contract coverage

### MAGI 审视

- 第十五轮转向非 URL 程序语义，重点审视 delete、import/export、agent update 的跨层契约。
- 删除路径已有 `NodeDeleteResponse`、partial history cleanup、pending cleanup intent、前端重复 toast 避免等测试保护。
- Agent update 路径已有 update id 不外泄、stale report 拒绝、HTTP/gRPC report、queue/re-deliver、stats success reconcile 等测试保护。
- 导入配置路径实现上会用 `agentConfigProjectionsLocked()` 对比导入前后 agent config，并通过 `reconcileAgentConfigRefreshLocked()` 标记需要 agent 拉新配置；但当前测试只覆盖 legacy alert filter，缺少“导入 profile/test catalog 后必须 refresh agent config”的 contract。
- 本轮 sidecar 子代理因上游 `503 auth_unavailable` 失败，没有可用输出；审视依据来自主线程 live worktree。

### MAGI 执行

- `internal/server/settings_contract_test.go`
  - 新增 `TestImportConfigMarksChangedAgentConfigForRefresh`。
  - 构造已有节点和 runtime `AgentAuthToken`。
  - 导入包含 `TestCatalog` 与 profile `TestSelections` 的配置。
  - 验证导入后对应节点进入 pending agent config refresh。
  - 验证 `DeliverAgentConfig()` 下发导入后的测试配置，并清除 refresh marker。
  - 验证导入过程中保留当前环境的 profile runtime token。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestImportConfigMarksChangedAgentConfigForRefresh|TestImportConfigIgnoresLegacyAlertFilterFields|TestSettingsContractsOmitLegacyAlertFilters' -count=1`：pass。
- `node --test internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-agent-update.test.mjs`：5 pass，0 fail。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(DeleteNode|ClearNodes|ImportConfig|SettingsContracts|AgentUpdate)' -count=1`：pass。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- 导入导出不只要保护 JSON schema，也要保护导入后运行态动作。
- 对 agent config 这类“状态已变，agent 需要再次拉取”的语义，测试应覆盖 refresh marker 和 delivery clearing 两端。
- 下一轮可继续审视 profile runtime token、new imported profile onboarding、stats ingest refresh_config 的端到端链路。

## 2026-06-09 / Agent refresh API round trip

### MAGI 审视

- 第十六轮接续导入配置后的运行态链路，重点审视 `ImportConfig`、profile runtime、agent `refresh_config` 和 config delivery 的端到端语义。
- 当前实现中：
  - `ImportConfig()` 和 `ReplaceProfiles()` 都会用 `agentConfigProjectionsLocked()` 计算导入前 projection。
  - 导入完成后由 `reconcileAgentConfigRefreshLocked()` 标记 agent config 已变化的节点。
  - `agentAPI.ingest()` 会在 stats 上报成功后返回 `HasPendingAgentConfigRefresh()`。
  - `agentAPI.config()` 通过 `DeliverAgentConfig()` 下发配置并清除 refresh marker。
- 第十五轮已补 Store 层 marker / delivery contract，但 API 层 `refresh_config=true -> config delivery -> refresh_config=false` 闭环仍缺测试。
- 本轮 sidecar 子代理仍因上游 `503 auth_unavailable` 失败，没有可用输出；审视依据来自主线程 live worktree。

### MAGI 执行

- `internal/server/settings_contract_test.go`
  - 新增 `TestImportedAgentConfigRefreshRoundTripThroughAgentAPI`。
  - 构造已有节点、当前 runtime `AgentAuthToken` 和导入后的 `TestCatalog` / profile `TestSelections`。
  - 验证导入后 agent 下一次 stats ingest 返回 `refreshConfig=true`。
  - 验证 agent 通过 API 拉取配置后收到导入后的 TCP probe 配置。
  - 验证 config delivery 后再次 stats ingest 返回 `refreshConfig=false`。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestImport(ConfigMarksChangedAgentConfigForRefresh|edAgentConfigRefreshRoundTripThroughAgentAPI|ConfigIgnoresLegacyAlertFilterFields)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(Import|AgentUpdate|AgentEndpoint|SettingsContracts)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'Test.*Update|Test.*Config|TestPostAgentUpdateReportSendsUpdateID' -count=1`：pass。
- `node --test internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs`：7 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- 对 agent config refresh 这类运行态契约，Store 层测试不够；API round trip 也要有测试证明。
- `refresh_config` 的关键不只是置位，还包括 agent 拉取后的清除语义。
- 下一轮可继续看新导入 profile 的 bootstrap/register/onboarding 语义，确认“预置 profile 但无 runtime token”的节点是否有清晰路径。

## 2026-06-09 / Imported profile onboarding contract

### MAGI 审视

- 第十七轮接续“预置 profile 但无 runtime token”的 onboarding 链路。
- 当前实现中：
  - 导出和新导入 profile 会通过 `redactProfileRuntimeForTransfer()` 清除 `AgentAuthToken` 与 update runtime 字段。
  - `ImportConfig()` 对已有 profile 保留当前 runtime token，对新 profile 清空导入文件里的 runtime token。
  - `agentAPI.register()` / `registerAgentAuthToken()` 会在 profile token 为空或重复时生成新的 per-agent token。
  - `agentAPI.config()` 与 `agentAPI.ingest()` 都要求专属 token 通过校验。
- 运行逻辑是直接路径，不需要加兼容包装；缺口是“新导入 profile 注册前拒绝、注册后下发预置配置”缺少后端 contract。
- 本轮 sidecar 子代理仍因上游 `503 auth_unavailable` 失败，没有可用输出；审视依据来自主线程 live worktree。

### MAGI 执行

- `internal/server/settings_contract_test.go`
  - 新增 `TestImportedNewProfileRegistersAndReceivesPresetConfig`。
  - 构造导入文件中带有伪 `AgentAuthToken` 的新 profile，验证导入不会信任迁移文件里的 runtime token。
  - 验证注册前使用 bootstrap token 拉 config 会被拒绝。
  - 验证 register 使用全局 bootstrap token 后生成新的 per-agent token。
  - 验证新 token 可以通过 ingest，并因为导入的 profile config 返回 `refreshConfig=true`。
  - 验证新 token 拉取 config 时保留导入 profile 的 alias/group/test selection，并下发新 token。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestImportedNewProfileRegistersAndReceivesPresetConfig' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(Import|Imported|AgentUpdate|AgentEndpoint|SettingsContracts)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'Test.*Token|Test.*Config|Test.*Update|TestPostAgentUpdateReportSendsUpdateID' -count=1`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-agent-update.test.mjs`：7 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- 迁移文件里的 runtime token 不能作为运行时信任来源；导入只保留配置意图，认证材料必须本机重新注册生成。
- onboarding contract 应同时覆盖拒绝路径和成功路径，否则容易只证明 happy path。
- 下一轮可继续看 register rate-limit / duplicate token / rollback 的失败路径，或转向 admin UI 对导入后 agent onboarding 状态的可见性。

## 2026-06-09 / Duplicate agent token rejection

### MAGI 审视

- 第十八轮接续 register 失败路径，重点审视重复 `AgentAuthToken` 与 onboarding 的边界。
- 发现确定性缺口：
  - `registerAgentAuthToken()` 在发现当前 profile token 为空或重复时会生成新 token。
  - 但 `validateAgentAuthToken()` 之前只校验目标 profile 上的 token 是否匹配，没有拒绝“多个 profile 共享同一个 runtime token”的状态。
  - 因此重复 token 状态下，agent 可以在 register 前通过 `config` / `ingest` 鉴权，破坏 per-agent token 唯一性边界。
- 本轮 sidecar 子代理仍因上游 `503 auth_unavailable` 失败，没有可用输出；审视依据来自主线程 live worktree 和新增失败测试。

### MAGI 执行

- `internal/server/server.go`
  - `validateAgentAuthToken()` 在 constant-time token 匹配后，继续通过 `isAgentAuthTokenDuplicateLocked()` 拒绝重复 runtime token。
  - 保持单一路径：重复 token 不能直接使用；agent 必须走 register，由 `registerAgentAuthToken()` 生成新的 per-agent token。
- `internal/server/settings_contract_test.go`
  - 新增 `TestAgentRegisterReplacesDuplicateRuntimeToken`。
  - 验证重复 token 在 register 前不能拉 config。
  - 验证 register 会换发 fresh token，且不会破坏已有节点 token。
  - 验证换发后仍保留 profile 的 alias/group/tests 并可正常下发。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentRegisterReplacesDuplicateRuntimeToken|TestImportedNewProfileRegistersAndReceivesPresetConfig|TestImportedAgentConfigRefreshRoundTripThroughAgentAPI' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AgentRegister|Import|Imported|AgentUpdate|AgentEndpoint|SettingsContracts)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'Test.*Token|Test.*Config|Test.*Update|TestPostAgentUpdateReportSendsUpdateID' -count=1`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-agent-update.test.mjs`：7 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- 校验 token 时不能只看目标 profile 是否匹配，也要确认 token 在全局 profile 集合中唯一。
- register 的“重复 token 换发”逻辑必须和 config/ingest 的“重复 token 拒绝”逻辑成对存在。
- 下一轮可继续看 token 生成失败 rollback、register rate-limit 边界，或 admin UI 对等待注册节点的呈现。

## 2026-06-09 / Idempotent agent register retry

### MAGI 审视

- 第十九轮继续审视 register 失败路径和 rate-limit 顺序。
- 发现确定性缺口：
  - agent register 成功后，如果响应在 agent 侧丢失或持久化 token 失败，agent 仍会继续拿 bootstrap token 重试 register。
  - 旧逻辑在返回已有唯一 runtime token 前先执行 register rate-limit。
  - 同一节点注册默认 1/min，这会让“服务端已成功发 token、客户端需要重取”的幂等重试被误伤。
- 新 profile / 空 token / 重复 token 仍应走 rate-limit 和换发路径；已有唯一 token 的 retry 应直接返回。
- 本轮 sidecar 子代理仍因上游 `503 auth_unavailable` 失败，没有可用输出；审视依据来自主线程 live worktree。

### MAGI 执行

- `internal/server/server.go`
  - `registerAgentAuthToken()` 在 bootstrap token 校验后，先检查目标 profile 是否已有非空且全局唯一的 runtime token。
  - 如果已有唯一 token，直接幂等返回，不消耗 register rate-limit。
  - 空 token、重复 token、新 profile 继续走原有 rate-limit 和生成 token 路径。
- `internal/server/settings_contract_test.go`
  - 新增 `TestAgentRegisterReturnsExistingUniqueTokenIdempotently`。
  - 验证已有唯一 token 的连续 register 会稳定返回同一个 token。
  - 验证幂等重试不会触发默认 per-node `1/min` register rate-limit。
  - 验证返回 token 仍能通过 `validateAgentAuthToken()`。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'TestAgentRegister(ReturnsExistingUniqueTokenIdempotently|ReplacesDuplicateRuntimeToken)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AgentRegister|Import|Imported|AgentUpdate|AgentEndpoint|SettingsContracts)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'Test.*Token|Test.*Config|Test.*Update|TestPostAgentUpdateReportSendsUpdateID' -count=1`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-agent-update.test.mjs`：7 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- Rate-limit 应保护会创建或换发 credential 的路径，不应阻断读取已存在唯一 credential 的幂等重试。
- register 的鉴权顺序应保持：先验证 bootstrap token，再判定是否可幂等返回，再进入限流和 mutation。
- 下一轮可继续看 token 生成失败 rollback，或者从 agent 端 token 持久化失败的恢复流程补充 contract。

## 2026-06-09 / Agent stale token recovery

### MAGI 审视

- 第二十轮审视 agent stale token、token file 和 register fallback 的恢复链路。
- 发现确定性缺口：
  - stale per-agent token 会导致 config / stats auth 失败；此前缺少 re-register fallback。
  - remote update report 同样走 agent token 鉴权；此前没有 stale token fallback，更新状态可能丢失。
  - `updateAgentToken()` 先更新内存再写 token file；持久化失败会造成当前进程正常但重启回旧 token。
- 本轮 sidecar 子代理可用，指出 stale token fallback、update report retry 和 token file 持久化顺序风险。

### MAGI 执行

- `internal/agent/runtime.go`
  - 新增 `registerAgentToken()`，用 bootstrap token 换回 server 当前 per-agent token。
  - `syncRemoteConfig()` 和 `reportStats()` 在 invalid agent token / gRPC `Unauthenticated` 时 re-register 并 retry 一次。
  - `reportRemoteUpdate()` 同步做 stale-token re-register retry，避免 remote update 状态上报丢失。
  - `updateAgentToken()` 改成 token file persist 成功后再切换内存 token。
  - 新增 `isAgentTokenAuthError()` 和 `isBootstrapTokenAuthError()`，集中判断 agent token 与 bootstrap token 的 auth 失败。
- `internal/agent/agent_update_test.go`
  - 新增 config / stats / update-report stale token 恢复测试。
  - 新增 token file persist 失败不切换内存 token 测试。
  - 扩展 `staleTokenRecoveryTransport`，记录 register / fetch / stats / update report 的 token 序列。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'TestAgentRunner(ReregistersStaleTokenBeforeRetrying(Config|Stats|UpdateReport)|KeepsMemoryTokenWhenTokenFilePersistFails)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'Test(AgentRunner|FetchRemoteConfig|PostAgentUpdate|FromRPC|MaybeApplyRemote).*' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AgentRegister|Import|Imported|AgentUpdate|AgentEndpoint|SettingsContracts)' -count=1`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-agent-update.test.mjs`：7 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- token recovery 需要覆盖 config、stats、update report 三条路径。
- token file persist 不能制造隐性的 memory / disk token 分裂。
- 下一轮优先把 string-based HTTP auth classifier 收敛成 typed status error，并补充真实 HTTP / gRPC classifier 测试；也可以继续看 admin UI 对 waiting-registration imported nodes 的可见性。

## 2026-06-09 / Typed agent auth status errors

### MAGI 审视

- 第二十一轮审视 agent stale-token recovery 的 auth error classifier。
- 发现确定性缺口：
  - HTTP control plane 401 之前返回普通 `fmt.Errorf`，runtime 只能靠 `"invalid agent token"` / `"register status 401"` 文本判断。
  - 第二十轮临时分出了 agent-token / bootstrap-token helper，但仍让 `operation` 字符串参与分类。
  - stats / update report 只有 fake transport 测试，没有证明真实 HTTP 401 会产出 typed error。
- 本轮 sidecar 子代理可用；它确认无高风险阻断，但指出 `operation` 字符串分类和真实 HTTP stats/update 401 覆盖不足。

### MAGI 执行

- `internal/agent/config.go`
  - 新增 `agentAPIStatusError`，把 HTTP status code、operation 和 message 作为结构化错误保留。
  - `readAgentAPIStatusError()` 统一返回 typed status error。
  - `performAgentStatusRequest()` 改用 status error 路径，不再走 action 文本拼接。
- `internal/agent/runtime.go`
  - 移除 token-specific 字符串分类 helper。
  - 新增 `isUnauthorizedStatusError()`，只判断 gRPC `Unauthenticated` 或 HTTP typed `401`。
  - config / stats / update report / register 由调用点语义决定处理方式，不再解析错误正文。
- `internal/agent/transport.go` 与 `internal/agent/agent.go`
  - stats 和 update report HTTP 失败统一走 typed status error。
- `internal/agent/auth_error_test.go`
  - 新增 status-only classifier 测试。
  - 新增 config / register / stats / update report 的真实 HTTP 401 typed error 测试。
  - 保留 plain string error 不触发 unauthorized classifier 的负例。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'Test(UnauthorizedStatusClassifierUsesTypedHTTPAndGRPCStatus|FetchRemoteConfigReturnsTypedUnauthorizedStatus|RegisterNodeTokenReturnsTypedUnauthorizedStatus|HTTPReportStatsReturnsTypedUnauthorizedStatus|PostAgentUpdateReportReturnsTypedUnauthorizedStatus|AgentRunnerReregistersStaleTokenBeforeRetrying(Config|Stats|UpdateReport)|AgentRunnerKeepsMemoryTokenWhenTokenFilePersistFails)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AgentRegister|Import|Imported|AgentUpdate|AgentEndpoint|SettingsContracts)' -count=1`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-agent-update.test.mjs`：7 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- Auth classifier 应按 transport status 分类，不能按错误正文分类。
- token 类型语义应由调用点承担；公共 helper 只回答“是否 unauthorized status”。
- 下一轮可以继续优化 HTTP error log：解析 server 的 `{"error": "..."}` 只用于日志可读性，不参与鉴权分类；或者转向 admin UI 对 waiting-registration imported nodes 的可见性。

## 2026-06-09 / Agent HTTP JSON error messages

### MAGI 审视

- 第二十二轮审视 agent HTTP error body 与日志解析边界。
- 发现确定性缺口：
  - server agent HTTP endpoint 统一用 `writeJSON(..., map[string]string{"error": err.message})` 返回错误。
  - agent 端 `readAgentAPIErrorMessage()` 之前直接把 body 原文作为 message。
  - 这会让日志显示 `{"error":"invalid agent token"}` 包装文本，不利于排查。
- 本轮 sidecar 子代理可用；它确认改进方向只应影响 `agentAPIStatusError.message`，不能让 JSON `error` 字段重新参与 auth classification。

### MAGI 执行

- `internal/agent/config.go`
  - `readAgentAPIErrorMessage()` 现在优先解析 JSON `{"error": "..."}`。
  - 解析成功且 error 非空时，只返回纯 message。
  - 非 JSON、空 error 或空 body 仍走原有 raw body / fallback status 逻辑。
- `internal/agent/auth_error_test.go`
  - `TestFetchRemoteConfigReturnsTypedUnauthorizedStatus` 改用 server 风格 JSON error response。
  - 验证 `agentAPIStatusError.message` 为纯 `"invalid agent token"`，`Error()` 不再暴露 JSON wrapper。
  - 新增纯文本 body fallback 测试。
  - 扩展 classifier 测试，明确 message-only `"invalid agent token"` 不会触发 unauthorized，HTTP 401 即使 message 无关也会触发。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -run 'Test(UnauthorizedStatusClassifierUsesTypedHTTPAndGRPCStatus|FetchRemoteConfigReturnsTypedUnauthorizedStatus|AgentAPIStatusErrorMessageKeepsPlainTextBody|RegisterNodeTokenReturnsTypedUnauthorizedStatus|HTTPReportStatsReturnsTypedUnauthorizedStatus|PostAgentUpdateReportReturnsTypedUnauthorizedStatus|AgentRunnerReregistersStaleTokenBeforeRetrying(Config|Stats|UpdateReport)|AgentRunnerKeepsMemoryTokenWhenTokenFilePersistFails)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/agent -count=1`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- HTTP response body parsing 只能改善 operator-facing message，不能承担 auth semantics。
- Auth semantics 保持在 typed status：HTTP status code 或 gRPC status code。
- 下一轮可切换到 admin UI 对 waiting-registration imported nodes 的可见性，或继续审视 agent update report conflict / retry 的产品语义。

## 2026-06-09 / Imported node waiting-registration visibility

### MAGI 审视

- 第二十三轮审视 imported profile / waiting-registration 节点在 API 与 admin UI 的可见性。
- 发现确定性缺口：
  - `Store.Snapshot()` 只遍历已上报 stats 的 `nodes`。
  - config import 后只有 profile、还没有 agent register / ingest 的节点不会出现在 admin 节点列表。
  - 直接把 profile-only 节点加入公共 snapshot 会泄露未接入配置节点，也会影响 public page / Telegram / AI summary。
  - admin websocket 之前也使用 public `balanced` snapshot，可能覆盖 admin GET 中的 profile-only rows。
- 本轮 sidecar 子代理启动成功，但上游返回 `503 system_cpu_overloaded`，没有可用 findings；本轮审视依据来自主线程 live worktree 和新增 contract。

### MAGI 执行

- `internal/server/server.go`
  - 新增 `nodeStatusWaitingRegistration = "waiting_registration"` 和 `adminVariant = "admin"`。
  - `Store.Snapshot()` 保持 public 行为，只返回真实上报节点。
  - 新增 `Store.AdminSnapshot()`，在 admin 视图中追加 profile-only waiting-registration 节点。
  - 新增 `profileOnlyNodeView()`，用 profile 构造最小 `NodeView`，保留 alias/group/tags/lifecycle/test selections。
  - 新增 `adminStoreSnapshot()`，`/api/v1/admin/nodes` 与 `/api/v1/nodes` 改用 admin snapshot。
  - admin websocket 首帧和广播使用 `adminVariant`，public websocket 继续使用 `publicVariantBalanced`。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 新增 waiting-registration badge、排序 rank 和状态提示。
  - waiting-registration 节点不显示伪造 CPU / memory / runtime 数字，改为等待首次上报占位。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增中英文 waiting-registration 状态和等待上报文案。
- `internal/server/settings_contract_test.go`
  - 新增 admin snapshot contract：public snapshot 不暴露 profile-only imported node；admin snapshot 显示 waiting-registration；register + ingest 后转为真实 online node 且不重复。
- `internal/server/web/admin-agent-update.test.mjs` 与 `internal/server/update_assets_test.go`
  - 固定 admin UI waiting-registration 展示 contract。
  - 固定 public/admin websocket variant 分离 contract。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AdminSnapshotIncludesImportedProfileWaitingRegistration|ImportedNewProfileRegistersAndReceivesPresetConfig|WebSocketUsesBalancedPublicAndAdminVariants)' -count=1`：pass。
- `node --test internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs`：8 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- admin-only operational state 不应通过 public snapshot 传播。
- profile-only rows 需要从 server API 明确输出，不能让前端猜测导入状态。
- websocket snapshot 必须和 audience 对齐；否则 admin-only rows 会被 public snapshot 覆盖。
- 下一轮可继续审视 delete / save / websocket delta 对 waiting-registration rows 的交互边界，或转向 agent update report conflict / retry 的产品语义。

## 2026-06-09 / Waiting-registration node delta transition

### MAGI 审视

- 第二十四轮审视 waiting-registration rows 的首次 ingest / websocket / save-delete 边界。
- 发现确定性缺口：
  - admin snapshot 已能显示 profile-only waiting-registration rows。
  - 但首次 ingest 后的 real node delta 之前只面向 public `balanced` variant 推送。
  - admin websocket 可能停留在 waiting-registration row，直到下一次 full admin snapshot 才更新。
  - 前端 `upsertNodeView()` 只按 freshness / last_seen 决定替换，没有明确“真实节点替换 waiting-registration row”的状态转换规则。
- 本轮 sidecar 子代理启动后 120 秒未返回结果，随后关闭；本轮结论来自主线程 live worktree、server delta 路径和 admin upsert contract。

### MAGI 执行

- `internal/server/agent_rpc.go`
  - 将 ingest 后的 delta 广播收敛为 `broadcastNodeDelta()`。
  - real node delta 同时推送 `publicVariantBalanced` 与 `adminVariant`。
  - `PublicNodeDelta()` 仍只产出真实节点 delta，profile-only waiting rows 继续只存在于 admin snapshot。
- `internal/server/web/admin/lib/admin-format.ts`
  - `shouldReplaceNodeView()` 明确允许 non-waiting candidate 替换 existing waiting-registration row。
  - 首次上报产生的 node delta 可以确定性替换 onboarding row，不依赖 timestamp 巧合。
- `internal/server/update_assets_test.go` 与 `internal/server/web/admin-agent-update.test.mjs`
  - 固定 server real node delta 的 public/admin 双播 contract。
  - 固定 admin upsert 对 waiting-registration -> real node 的替换 contract。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(WebSocketUsesBalancedPublicAndAdminVariants|AdminSnapshotIncludesImportedProfileWaitingRegistration)' -count=1`：pass。
- `node --test internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs`：8 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- waiting-registration -> real node 是状态转换事件，不能只依赖下一次 full snapshot。
- admin audience 需要接收同一条 real node delta，否则 UI 首次接入体验存在延迟和不一致。
- 前端 upsert 需要表达状态迁移语义；timestamp 只能做 freshness 判定，不能替代 lifecycle rule。
- 下一轮可继续审视 admin save/delete 后的 full admin snapshot refresh、多 admin 会话同步，或 agent update report conflict/retry 的产品语义。

## 2026-06-09 / Admin profile patch snapshot broadcast

### MAGI 审视

- 第二十五轮审视 admin save/delete node profile 后的 websocket / admin snapshot / 多会话一致性。
- 发现确定性缺口：
  - delete / clear / agent update 成功后都会调用 `broadcastStoreSnapshot()`。
  - profile PATCH 成功后只返回 `{"status":"ok"}`，没有广播 snapshot。
  - 发起保存的浏览器会主动 `fetchNodes()`，所以单会话看起来正常。
  - 其他 admin 会话不会收到 alias / groups / lifecycle / test selections 等 profile 变更，只能等手动刷新或下一次其它广播。
- 本轮 sidecar 子代理启动后 120 秒未返回结果，随后关闭；本轮结论来自主线程 live worktree、handler 控制流和新增 contract。

### MAGI 执行

- `internal/server/server.go`
  - admin node PATCH / PUT 路由把 `hub` 传入 `handleAdminUpdateNodeProfileRequest()`。
  - profile 更新成功后复用已有 `broadcastStoreSnapshot(hub, store, false)`。
  - 不改变 status-only HTTP response，不新增前端轮询或兼容 fallback。
- `internal/server/agent_update_test.go`
  - 更新现有 redaction contract 的 handler 调用。
  - 新增 `TestAdminProfilePatchBroadcastsAdminSnapshot`，用 `Hub` admin variant 队列验证 PATCH 后广播的 admin snapshot 含最新 alias。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AdminProfilePatchBroadcastsAdminSnapshot|AgentUpdateAdminProfilePatchRedactsInstructionID|WebSocketUsesBalancedPublicAndAdminVariants)' -count=1`：pass。
- `node --test internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs`：9 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass。
- `git diff --check`：pass。

### MAGI 提升

- admin profile mutation 是跨会话状态变更，server 必须负责广播。
- 发起端 refresh 只能修正本地视图，不能证明多 admin 会话一致性。
- 继续保持单一机制：成功 mutation 后发 full audience-aware snapshot，不新增并行兼容协议。
- 下一轮可继续审视 import/settings mutation 后的 websocket 同步，或 agent update report conflict/retry 的用户可见语义。

## 2026-06-09 / Admin websocket session revocation and settings snapshot sync

### MAGI 审视

- 第二十六轮审视 admin settings/import mutation 后的 websocket / admin snapshot / 多会话同步边界。
- 主线程发现：
  - settings/import 成功后 server 已广播 audience-aware snapshot。
  - admin 前端 websocket snapshot handler 只处理 `nodes`，忽略 snapshot 里的 public `settings`。
  - 非发起 admin 会话的品牌、标题、公共首页文案会滞后。
- Sidecar 子代理补充了更高优先级的安全缺口：
  - admin credential 变更会轮换 `TokenSalt`，REST 会拒绝旧 cookie。
  - 但旧 admin websocket 只在握手时校验，广播时只按 `adminVariant` 推送。
  - 旧 admin websocket 可能继续收到 admin snapshot / node delta，直到连接自然断开。
  - `snapshot.settings` 是 public-safe shape，不能强转成完整 `SettingsView`。

### MAGI 执行

- `internal/server/server.go`
  - `hubClient` 记录 admin websocket 建立时的 `adminTokenSalt`。
  - admin websocket 握手改为 `validateAdminJWT()`，与 REST 一样校验 token salt。
  - 新增 `Hub.BroadcastAdmin(payload, tokenSalt)`，发送前剔除 salt 不匹配的旧 admin client。
  - `broadcastStoreSnapshot()` 的 admin 分支改用 `BroadcastAdmin()`。
- `internal/server/agent_rpc.go`
  - agent ingest 后的 admin node delta 也改用 `BroadcastAdmin()`。
  - 旧 admin session 不再能通过 node delta 绕过 snapshot revocation。
- `internal/server/web/admin/src/App.tsx`
  - websocket snapshot handler 继续更新 `nodes`。
  - 新增 public settings 同步：消费 snapshot 的 public `settings`，更新 `publicSettings`，并同步当前 `settings` 的公共字段。
  - 不把 snapshot public settings 强转成完整 `SettingsView`，避免误用或误发敏感字段。
- Tests
  - `TestAdminBroadcastDropsStaleSession` 覆盖旧 admin client 被关闭且不接收 admin broadcast。
  - `update_assets_test.go` 固定 `BroadcastAdmin()` contract。
  - `admin-api.test.mjs` 固定 admin websocket snapshot 会同步 public settings。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AdminBroadcastDropsStaleSession|AdminProfilePatchBroadcastsAdminSnapshot|WebSocketUsesBalancedPublicAndAdminVariants)' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(AdminBroadcastDropsStaleSession|AdminProfilePatchBroadcastsAdminSnapshot|WebSocketUsesBalancedPublicAndAdminVariants|AdminSnapshotIncludesImportedProfileWaitingRegistration|ImportedNewProfileRegistersAndReceivesPresetConfig|Settings|ImportConfig|UpdateSettings)' -count=1`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-agent-update.test.mjs`：9 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass，Node contract 36 pass，admin build pass，`go test ./...` pass。
- `git diff --check`：pass。

### MAGI 提升

- Admin websocket 不能只在握手时鉴权；credential revocation 必须作用到后续 admin broadcast。
- Admin snapshot 的 public `settings` 可以驱动公共品牌同步，但不能承载完整后台配置。
- 继续保持单一广播机制：server mutation 成功后发 audience-aware snapshot，admin client 按 payload shape 更新对应状态。
- 下一轮可继续审视完整 `SettingsView` 跨会话同步是否需要显式 invalidation，以及本地未保存表单与远端 settings 推送的冲突处理。

## 2026-06-09 / Admin revocation closure and settings dirty guard

### MAGI 审视

- 第二十七轮按用户新要求启动 10 个并行 sidecar 做只读分区审视：
  - A auth/websocket/session revocation。
  - B agent update/report/config delivery。
  - C node lifecycle/delete/waiting-registration/import。
  - D admin frontend state/dirty guard。
  - E public frontend/API/base path/ws。
  - F docker-managed updater/system update。
  - G installer/uninstaller scripts。
  - H AI provider/test/model endpoints。
  - I persistence/history/delete intent。
  - J tests/verify-local contract。
- Runtime 结果：
  - A / D 两个 sidecar 返回有效 findings。
  - 其余 8 个在后续 `wait_agent` 时返回 `not_found`，没有可用 findings；本轮不把不可访问结果当证据。
- A 分区发现 3 个确定性 auth/revocation 缺口：
  - legacy `/api/v1/nodes` 仍用普通 JWT，绕过 admin `TokenSalt` revocation。
  - unified/mixed `/ws` 对带失效 admin token 的请求降级成 public websocket，而不是 fail-closed。
  - logout 只清浏览器 cookie，不轮换 server-side token salt，也不关闭已建立 admin websocket。
- D 分区发现第 26 轮前端同步存在 dirty guard 风险：
  - websocket public snapshot 写回完整 `settings` 会触发 BasicSettings / Alert / AI 页面 `[settings]` effect。
  - `refreshSystemUpdate()` 只为了版本号也写 `settings.version`，会重置未保存表单。
  - 因此第 26 轮“同步当前 settings 公共字段”的做法需要收窄。

### MAGI 执行

- `internal/server/server.go`
  - legacy `/api/v1/nodes` 改用 `requireAdminJWT(store, cfg.JWTSecret, ...)`，并增加 GET method guard。
  - `wsAuthMixed` 分支改为：
    - 无 token：保持 public websocket。
    - 有 token：必须 same-origin 且通过 `validateAdminJWT()`；失败直接 401，不再降级 public。
  - 新增 `Store.RotateAdminTokenSalt()`，logout 对有效 same-origin admin session 轮换 `TokenSalt` 并持久化。
  - 新增 `Hub.CloseAdminClients()`，logout 后关闭所有 admin websocket。
- `internal/server/web/admin/src/App.tsx`
  - websocket snapshot 只更新 `publicSettings`。
  - 移除 `mergeSettingsPublicFields()` 和 snapshot -> `setSettings()` 路径，避免远端 public snapshot 重置本地编辑表单。
  - `refreshSystemUpdate()` 只更新 `systemUpdateInfo` 和 `publicSettings.version`，不再写 `settings.version`。
- Tests
  - `TestLegacyNodesEndpointRejectsRevokedAdminJWT` 覆盖 legacy nodes revocation。
  - `TestMixedWebSocketRejectsRevokedAdminCookie` 覆盖 mixed websocket fail-closed。
  - `TestLogoutRevokesAdminSessionAndSocket` 覆盖 logout 轮换 salt、REST 失效和 websocket 关闭。
  - `admin-api.test.mjs` 固定 websocket snapshot 只更新 public settings，不写完整 `settings`。

### MAGI 验证

- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(LegacyNodesEndpointRejectsRevokedAdminJWT|MixedWebSocketRejectsRevokedAdminCookie|LogoutRevokesAdminSessionAndSocket|AdminBroadcastDropsStaleSession)$' -count=1`：pass。
- `env TMPDIR=/SourceCode/CyberMonitor/.tmp GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build go test ./internal/server -run 'Test(LegacyNodesEndpointRejectsRevokedAdminJWT|MixedWebSocketRejectsRevokedAdminCookie|LogoutRevokesAdminSessionAndSocket|AdminBroadcastDropsStaleSession|SplitServerSeparatesPublicAndAdminRuntime|UnifiedServerServesAdminAPI|WebSocketUsesBalancedPublicAndAdminVariants)$' -count=1`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-frontend-contract.test.mjs`：8 pass，0 fail。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-agent-update.test.mjs`：13 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `scripts/verify-local.sh`：pass，Node contract 36 pass，admin build pass，`go test ./...` pass。
- `git diff --check`：pass。

### MAGI 提升

- Revocation 不能只依赖 REST middleware；legacy routes、mixed websocket 和 logout 都必须使用同一 admin session epoch。
- 带失效 admin token 的 websocket 请求应 fail closed，不能隐式降级为 public 数据流。
- Public snapshot 只能更新 public-facing state；不要把它写回驱动编辑表单的完整 `SettingsView`。
- 下一轮优先处理 ServerManagement 编辑表单未接入 dirty guard，以及完整 `SettingsView` 跨会话同步的显式 invalidation 方案。

## 2026-06-09 / ServerManagement dirty guard closure

### MAGI 审视

- 第二十八轮继续按 10+ 并行 sidecar 做 ServerManagement dirty guard / frontend contract / verify-local 覆盖审视。
- Sidecar 共启动 12 个：
  - Helmholtz / Averroes / Avicenna / Chandrasekhar / Peirce / Wegener / Hilbert / McClintock / Russell / Bohr 返回有效 findings。
  - Copernicus / Linnaeus 因 capacity error 未返回有效结果。
- 主要缺陷：
  - `ServerManagement` 已有 `onDirtyChange` prop 和 `formDirty` 计算，但 `App` 的 servers case 未传 `onDirtyChange={setHasUnsavedPageChanges}`，全局导航、back/forward、beforeunload guard 对节点编辑器失效。
  - 编辑器本地关闭入口仍直连 `closeEditor()`，点击 X、ESC/backdrop、footer cancel 可以绕过 dirty confirm。
  - 保存请求发出后表单仍可继续输入；保存成功会关闭编辑器，可能丢掉点击保存之后的新输入。
  - `scripts/verify-local.sh` 未纳入 `admin-frontend-contract.test.mjs`、`admin-i18n.test.mjs`、`admin-kumo.test.mjs`，统一入口不能证明这些前端契约。

### MAGI 执行

- `internal/server/web/admin/src/App.tsx`
  - servers page 接入 `onDirtyChange={setHasUnsavedPageChanges}`，和 groups/probes/settings/alerts/ai 保持同一全局 dirty guard 协议。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 保留 baseline signature dirty 计算，不退回简单布尔兼容路径。
  - 新增 `formLocked = saving || deleting`，保存/删除期间禁止表单 mutation。
  - `patchForm()` 在 locked 状态下直接返回，所有可编辑 Input、Select、checkbox、group/tag 操作按钮增加 locked disabled。
  - 主编辑 dialog 的 `onOpenChange`、右上角关闭、footer cancel 统一进入 `requestCloseEditor()`。
  - dirty 时打开本地 discard confirm，用户确认后才调用 `closeEditor()`；`closeEditor()` 只作为保存成功、删除成功、明确放弃后的终态路径。
  - 保存按钮只在 dirty 且非 locked 时可点，减少无变更保存请求。
  - 删除确认按钮改为普通 Kumo `Button`，异步删除成功后再显式关闭确认框，避免 `Dialog.Close` 包裹 async delete。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 新增 ServerManagement 全局 dirty guard 接线契约。
  - 新增本地 dirty discard confirm 契约。
  - 新增保存/删除期间表单锁定契约。
  - 新增 `verify-local.sh` 必须覆盖 frontend contract / i18n / Kumo tests 的契约。
- `scripts/verify-local.sh`
  - Node test list 加入 `internal/server/web/admin-frontend-contract.test.mjs`、`internal/server/web/admin-i18n.test.mjs`、`internal/server/web/admin-kumo.test.mjs`。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-kumo.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-delete-node.test.mjs`：63 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `git diff --check`：pass。
- `scripts/verify-local.sh`：pass。
  - Node contract tests：89 pass，0 fail。
  - `npm ci`：pass，0 vulnerabilities。
  - admin `tsc --noEmit`：pass。
  - admin `vite build`：pass。
  - `go vet ./...`：pass。
  - `go test ./...`：pass。

### MAGI 提升

- Dirty guard 不能只定义子组件 prop；父级必须实际接线，否则 global guard 是空转。
- Modal editor 有同页内关闭入口，必须有自己的 discard confirm；全局页面跳转 guard 不会覆盖本地 modal close。
- 保存请求开始后要锁定待保存 draft，避免 payload 构造后继续输入造成“看似保存、实际丢失”的错觉。
- 统一验证入口必须覆盖前端源码契约；单独绿灯不能替代 `verify-local.sh` 的主路径证明。
- 下一轮优先继续处理 ServerManagement clean form 与 websocket node snapshot/delta 的 rebaseline 语义，以及保存成功但刷新失败时 mutation ack 与 refresh warning 的拆分。

## 2026-06-09 / ServerManagement rebaseline and mutation ack split

### MAGI 审视

- 第二十九轮延续上一轮尾项，聚焦两个语义缺口：
  - `ServerManagement` 打开编辑器后，同节点 websocket snapshot / delta 推来新的可编辑 profile 时，clean form 不应继续持有旧 baseline。
  - `App` 的节点保存/删除 mutation 已成功，但后续 refresh 失败时，不应把已成功写入显示成保存/删除失败。
- 本轮按要求启动 10 个 sidecar 分区审视：
  - A clean form rebaseline。
  - B dirty form 远端更新冲突策略。
  - C save mutation ack / refresh warning。
  - D delete mutation ack / refresh warning。
  - E frontend contract。
  - F i18n/toast key。
  - G websocket snapshot/delta 数据流。
  - H 其他 dirty guard 页面模式对比。
  - I Kumo Dialog/Button 边界。
  - J 验证矩阵。
- `wait_agent` 返回结果全部为 `not_found`，本轮没有可用 sidecar findings；不把该结果当完成证据。
- 主线程 live 审视确认：
  - 现有 `formInitializationKeyRef` 只看 `editingNodeId::testCatalogSignature`，同节点可编辑 profile 变化会被跳过。
  - 保存/删除路径把 mutation ack 和 `handleRefreshNodes()` 放进同一 `try`，refresh 失败会向 `ServerManagement` 抛错并触发失败 toast。

### MAGI 执行

- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 新增 `formSourceSignatureRef`，记录当前表单 baseline 对应的权威节点可编辑 profile signature。
  - 新增 `remoteProfileNoticeSignatureRef`，避免同一远端 profile 变更对 dirty draft 重复 toast。
  - form 初始化 effect 改为：
    - 同 key 且同 source signature：直接返回。
    - 同 key 且本地 dirty：保留本地 draft，并提示远端资料已更新。
    - clean 或首次打开：用最新 `editingNode` 重建 form、baseline 和 source signature。
  - 只用 `buildFormState()` / `formSignature()` 的可编辑字段做 source signature，避免运行态心跳、CPU、内存等指标刷新重建编辑器。
- `internal/server/web/admin/src/App.tsx`
  - `handleSaveNode()` 拆成 mutation `try/catch` 和 refresh `try/catch`。
  - `saveNodeProfile()` 成功后即视为保存成功；refresh 失败只显示 warning，不再向子组件抛保存失败。
  - `handleDeleteNode()` 同样拆分；`deleteNodeProfile()` 成功后返回 `NodeDeleteResponse`，refresh 失败只 warning。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增中英文 key：
    - `app.toast.nodeSaveRefreshFailed`
    - `app.toast.nodeDeleteRefreshFailed`
    - `server.toast.remoteProfileUpdated`
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 新增 clean rebaseline / dirty draft 不覆盖契约。
  - 新增 mutation ack 先于 refresh warning 的契约。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs`：20 pass，0 fail。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `git diff --check`：pass。
- `scripts/verify-local.sh`：pass。
  - Node contract tests：91 pass，0 fail。
  - `npm ci`：pass，0 vulnerabilities。
  - admin `tsc --noEmit`：pass。
  - admin `vite build`：pass。
  - `go vet ./...`：pass。
  - `go test ./...`：pass。

### MAGI 提升

- 复杂编辑器的 baseline 不应只绑定对象 id；还要绑定“可编辑来源”的 signature。
- Dirty draft 收到远端 profile 更新时，默认保留本地草稿比自动覆盖更安全；提示一次即可，避免 toast 噪音。
- Mutation 成功和刷新列表成功是两个状态。写入成功不能被后续刷新失败改写成失败。
- 下一轮优先继续审视 admin settings/import mutation 的跨会话 invalidation，以及 GroupManagement / ProbeSettings 在保存中继续编辑或远端更新时的相同语义缺口。

## 2026-06-09 / Settings-backed draft rebaseline and conflict guard

### MAGI 审视

- 第三十轮按要求启动 10 个 sidecar，聚焦 Group / Probe / BasicSettings / NotificationAlert / AIProvider / App mutation refresh / i18n / Kumo / verification。
- Sidecar 全部返回可用 findings。共识问题：
  - `BasicSettings`、`NotificationAlert`、`AIProvider` 在 `settings` prop 变化时会无条件回填表单并清 dirty，父级全局 dirty guard 无法保护这种组件内部覆盖。
  - 保存或测试请求 pending 期间仍可继续编辑，保存成功后可能把请求发出后的新草稿错误清为 clean。
  - `App.updateSettings()` / config import 成功后，节点刷新失败不应污染保存/导入结果。
  - `GroupManagement` / `ProbeSettings` 已有 source signature 模式，但还缺少“incoming 已等于当前 dirty draft 时直接 rebaseline”和保存前远端冲突阻断。
  - `AIProvider` 的 test/fetch models 异步返回必须校验 row signature，不能把旧配置的验证/模型结果盖到新草稿上。

### MAGI 执行

- `internal/server/web/admin/src/App.tsx`
  - `updateSettings()` 和 `handleImport()` 复用 `refreshNodesAfterMutation()`，保存/导入成功后节点刷新失败只 warning，不 rethrow。
  - `handleSaveNode()` / `handleDeleteNode()` 也复用同一 helper，消除重复 refresh 降级逻辑。
  - `NotificationAlert` / `AIProvider` 的 `onSave` 改为返回 canonical `SettingsView`，子组件用服务端回包 rebase。
  - 顶部部署版本优先使用 `systemUpdateInfo.current_version`，避免系统更新轮询后版本显示滞后。
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 新增 `hydrateSettingsDraft()`、`settingsDraftSignature()`、`sourceSignature`、`remoteUpdateNoticeSignatureRef`。
  - clean props 更新会 rebase；dirty draft 或远端冲突时保留本地草稿并提示。
  - 保存前检查当前 settings source 是否仍等于本地 source，阻止旧基线覆盖新 settings。
  - 保存和导入成功后使用返回的 canonical settings 重建 draft 和 source signature。
  - 保存/导入期间锁定所有表单输入和 backup action，保存确认改为普通 `Button` 执行 async 提交，取消才使用 `Dialog.Close`。
- `internal/server/web/admin/src/pages/NotificationAlert.tsx`
  - 新增 alert draft hydrate/signature，dirty 从 normalized 保存 payload 语义推导。
  - clean props 更新 rebase；dirty draft 保留并 warning；保存前检查远端冲突。
  - 保存成功用返回的 `SettingsView` 重新定基线。
  - 保存或测试 pending 期间锁定输入、保存和测试按钮，避免“测试的是旧值，屏幕显示新值”。
- `internal/server/web/admin/src/pages/AIProvider.tsx`
  - 新增 AI provider draft signature 和 runtime row signature。
  - 移除 `t` 驱动的草稿重建，避免语言切换重置用户输入。
  - clean props 更新 rebase；dirty draft 保留并 warning；保存前检查远端冲突。
  - 保存成功用返回的 canonical settings 重建 provider/prompt/source。
  - test/fetch models 记录提交时 row signature，返回时若当前 row 已变化则跳过写入并提示重新测试/获取模型。
  - 保存、测试、获取模型期间锁定 draft mutation。
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - incoming signature 已等于当前 dirty draft 时直接更新 source signature，避免保存回包或远端等值更新造成误 dirty。
  - 保存前如果发现远端 source 已变化且不等于当前 draft，阻止直接覆盖并提示。
  - `handleSave()` 增加 busy guard。
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - incoming catalog 已等于当前 draft 时直接 rebaseline。
  - 保存前阻止旧 source 上的 dirty draft 覆盖新远端 catalog。
  - 删除确认在 submitting 中禁止关闭/确认，避免“点了确认但 no-op”的错觉。
- `internal/server/web/admin/lib/admin-i18n.tsx`
  - 新增 BasicSettings / NotificationAlert / AIProvider remote update toast。
  - 新增 AI provider stale row toast。
  - Webhook validation 文案改为明确公开 URL 约束，匹配现有 localhost/private IP 拒绝逻辑。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 更新 refresh helper 契约，锁定 mutation ack 和 refresh warning 拆分。
  - 新增 settings-backed 页面全局 dirty guard、clean rebase / dirty 保留、保存冲突 guard、busy lock、AI async row signature 契约。
- `internal/server/web/admin-kumo.test.mjs`
  - 更新 BasicSettings 确认弹窗契约，锁定 async 保存使用普通 Kumo `Button`，取消使用 `Dialog.Close`。

### MAGI 验证

- `npm --prefix internal/server/web/admin run lint`：pass。
- `node --test internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs`：60 pass，0 fail。
- `git diff --check`：pass。

### MAGI 提升

- settings-backed 页面应统一使用 source signature，而不是用 `useEffect([settings])` 无条件回填表单。
- 保存成功、导入成功、节点刷新成功是不同事实；前两个不应被刷新失败改写成失败。
- Dirty draft 收到远端 settings 变化时，只保留草稿还不够；保存前必须显式阻止旧基线覆盖，除非用户选择覆盖策略。
- Async row action 必须校验提交时快照；UI disabled 只能降低竞态概率，不能代替返回时的签名校验。
- 下一轮建议继续处理显式冲突 UX：为 settings-backed dirty draft 提供“加载远端 / 覆盖保存”二选一，而不是只用 toast 阻断保存。

## 2026-06-09 / Group and probe canonical save rebase

### MAGI 审视

- 第三十一轮继续 repo-wide 自主迭代。按要求发起 10 个 sidecar 分区审视：
  - Server settings handlers、persistence、agent runtime、updater、admin libs、admin pages、public assets、test gaps、agent config、AI backend。
  - 当前环境连续返回 429，多个 sidecar 超过 retry limit；本轮不把 sidecar 失败当作完成证据，也不继续无意义补发重复 agent。
- 主线程 live 审视确认上轮已把 BasicSettings / NotificationAlert / AIProvider 改为保存成功后使用 canonical `SettingsView` 回包 rebase。
- `GroupManagement` 和 `ProbeSettings` 仍使用提交 payload 作为保存后的本地 source baseline：
  - 如果服务端 canonicalize `group_tree` 或 `test_catalog`，页面会短暂或持续以 request payload 标记 clean。
  - 这和上轮 settings-backed 页面统一策略不一致，也会削弱远端更新 / 保存回包等值 rebaseline 的准确性。

### MAGI 执行

- `internal/server/web/admin/src/App.tsx`
  - groups page 的 `onSave` 不再丢弃 `updateSettings()` 返回值，直接把 canonical `SettingsView` 传回子组件。
- `internal/server/web/admin/src/pages/GroupManagement.tsx`
  - `onSave` 合同从 `Promise<void>` 改为 `Promise<SettingsView>`。
  - `finishSave()` 改为接收 canonical `SettingsView`，使用 `next.group_tree || []` 重建 draft 和 source signature。
  - 保存成功后不再用请求前的 `nextTree` 当最终 baseline。
- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - `onSave` 合同从 `Promise<unknown>` 改为 `Promise<SettingsView>`。
  - 保存成功后使用 `next.test_catalog || []` normalize 后更新 `drafts` 和 `sourceSignature`。
  - 不再用提交 payload 的 `serializeCatalog(payload)` 作为最终 source baseline。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 新增 `group and probe saves rebase from canonical settings responses` 契约，锁定 Group / Probe 保存路径必须使用服务端回包 rebase。

### MAGI 验证

- `npm --prefix internal/server/web/admin run lint`：pass。
- `node --test internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs`：61 pass，0 fail。

### MAGI 提升

- 同类 settings-backed 页面必须统一保存合同：保存成功后的 baseline 来自服务端 canonical response，而不是 request payload。
- Toast 级冲突提示只能说明“有变化”；真正避免 lost update 仍需要前端显式冲突状态或后端 revision/etag。
- 下一轮建议继续审视 Go `SettingsUpdate` / `ImportConfig` canonicalization 与前端回包是否完全一致，避免前后端签名模型漂移。

## 2026-06-17 / Agent disk capacity and remote update hardening

### MAGI 审视

- 本轮继续按原目标推进，重新以当前 worktree 为准审视 Agent 硬盘统计异常和 Server->Agent 可执行边界。
- 硬盘 40G 显示 256 TB 的根因在 Agent 采集端：
  - Docker/hostRoot 场景下 `collectHostDiskUsage()` 先用 `statfs` 得到真实文件系统容量。
  - 旧逻辑又读取 `/sys/class/block/<device>/size`，只要块设备声明容量更大就覆盖 `Total`。
  - 云厂商、虚拟化或 thin-provisioned 设备可能把底层块设备声明成 256 TiB，导致上报 payload 被源头污染。
- Server->Agent 边界没有发现通用 shell/RPC 命令下发接口；可执行高影响路径主要是 Agent remote update / Docker managed update。
- 对照 Nezha GHSA-5c25-7vpj-9mqh 的风险模式，本项目需要防止“控制面或主控被接管后，把 Agent 更新链路放大成任意二进制执行”。

### MAGI 执行

- `internal/metrics/metrics.go`
  - `collectHostDiskUsage()` 改为只使用挂载点 `statFilesystemUsage(hostPath)` 的文件系统容量。
  - 删除 `applyDeviceTotal()`、`readBlockDeviceTotal()`、`blockDeviceCandidates()`，不再用 block device 声明容量覆盖 filesystem total。
- `internal/metrics/metrics_test.go`
  - 新增 `TestCollectHostDiskUsageUsesFilesystemCapacity`。
  - 模拟 host mount 和 256 TiB block device size，锁定采集结果必须等于 filesystem total。
- `internal/updater/updater.go`
  - `ApplyAsset()` 收敛为 `ApplyReleaseAsset(expectedVersion, downloadURL, checksumURL)`。
  - Agent/Server 二进制自更新下载前强制校验 GitHub release asset URL：
    - 必须是 `https://github.com/crazy0x70/CyberMonitor/releases/download/<tag>/<asset>`。
    - download asset 必须匹配当前 kind 的 asset name。
    - checksum 必须是同一 tag 下的 `SHA256SUMS`。
    - URL 禁止 query / fragment，tag 必须和目标版本语义一致。
- `internal/updater/updater_test.go`
  - 新增 `TestValidateReleaseAssetURLs`，覆盖官方 URL、任意 host、错误 repo、tag mismatch、target mismatch、query string。
- `internal/agent/agent.go`
  - Agent remote update 增加两道执行前拒绝：
    - 目标版本必须是可验证的新版本，拒绝降级或无法排序的目标。
    - `ServerURL` 必须是 HTTPS 控制面，否则拒绝执行远程更新。
  - Agent 二进制更新改为调用 `ApplyReleaseAsset()`，不再信任任意 `download_url/checksum_url`。
- `internal/agent/runtime.go`
  - 非 HTTPS 控制面下，Agent 上报 `agent_update_disabled=true`，避免管理端误判可安全远程更新。
- `internal/agent/agent_update_test.go`
  - 新增 `TestMaybeApplyRemoteUpdateRejectsInsecureControlPlane`。
  - 新增 `TestMaybeApplyRemoteUpdateRejectsDowngrade`。
  - 触发真实 update 的既有测试改为显式 HTTPS 控制面。
- `internal/server/server.go`
  - Server 自更新二进制路径同步调用 `ApplyReleaseAsset()`，复用同一套 URL/tag/asset 校验。

### MAGI 验证

- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/metrics -run TestCollectHostDiskUsageUsesFilesystemCapacity -count=1`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/metrics -count=1`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -run TestValidateReleaseAssetURLs -count=1`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/agent -run TestMaybeApplyRemoteUpdateRejectsDowngrade -count=1`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/agent -run 'TestMaybeApplyRemote(UpdateRejectsInsecureControlPlane|UpdateRejectsDowngrade|DockerUpdateLaunchesDetachedHelperBeforeRestartingReport|DockerUpdateReportsDetachedHelperLaunchFailure|DockerUpdateReportsTargetImageResolutionFailure|UpdateDoesNotTreatUnknownAsZeroVersion)' -count=1`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -run 'TestValidateReleaseAssetURLs|TestBuildReleaseInfoDoesNotTreatUnknownCurrentAsZeroVersion|TestHasVersionUpdate|TestVersionCurrentOrNewer' -count=1`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/agent -count=1`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/updater -count=1`：pass。
- `env GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build GOTMPDIR=/SourceCode/CyberMonitor/.cache/go-tmp go test ./internal/server -run 'Test(AgentUpdate|SystemUpdate|UpdateSettings|Route|Admin|Forwarded|PublicIndex|Delete|Clear)' -count=1`：pass。
- `scripts/verify-local.sh`：pass，覆盖 shell syntax、97 个 Node regression、`npm ci`、admin `tsc --noEmit`、admin `vite build`、`go vet ./...`、`go test ./...`；`npm ci` 报告 0 vulnerabilities。

### MAGI 提升

- 资源容量展示应在采集源头修正，不应在 server/frontend 用猜测式上限兜底。
- Agent 能执行的远程能力必须 fail closed：不信任任意 URL、不接受降级、不在明文控制面执行更新。
- 当前仍建议后续继续推进 release manifest 签名、Docker image digest/cosign 校验、bootstrap token 恢复语义收紧、legacy `NodeProfileUpdate.Tests` 校验收敛。

## 2026-06-17 / Agent control-plane fail-closed follow-up

### MAGI 审视

- 继续沿用当前 worktree 证据，不把前一轮测试通过等同于长期目标完成。
- 一个子代理审计 bootstrap token 语义时返回平台侧 400 HTML，未产出代码结论。
- 另一个子代理确认 legacy `NodeProfileUpdate.Tests` / `profile.Tests` 可绕过 `TestCatalog/TestSelections`，主线程复核后结论一致。
- 现有风险点：
  - `/api/v1/agent/register` 对已有唯一 `AgentAuthToken` 的节点，会在调用者只持有共享 bootstrap token 时返还专属 token。
  - 管理端 legacy `tests` 字段和 import `profiles[*].tests` 仍可能写入 raw `profile.Tests`。
  - `resolveTestsLocked()` 在没有 selections 时会把 raw tests 直接下发给 Agent。
  - Agent TCP 网络测试执行前没有统一 host 校验；远程控制面可把 Agent 变成内网探测执行点。

### MAGI 执行

- `internal/server/server.go`
  - `registerAgentAuthToken()` 对已有唯一专属 token 的节点改为拒绝 bootstrap 恢复，不再返还 token。
  - `NodeProfileUpdate` 删除 legacy `tests` 字段；管理 API 因 `DisallowUnknownFields()` 会对旧字段返回 400。
  - `UpdateProfile()` 只接受 `test_selections` 写入测试配置。
  - `normalizeProfilesForImportLocked()` 对 `profiles[*].tests` 明确返回错误，避免静默保留或静默丢弃 raw tests。
  - `resolveTestsLocked()` 只从 `TestSelections` 解析 catalog，下发路径不再读取 `profile.Tests`。
- `internal/agent/runtime.go`
  - `registerAgentToken()` 只在当前 token 仍等于 bootstrap token 时允许注册。
  - stale dedicated token 收到 401 后不再用共享 bootstrap token 自动重注册。
- `internal/metrics/metrics.go`
  - `NetworkTestConfig` 新增内部字段 `PublicOnly bool json:"-"`，不改变 API / 持久化 JSON。
- `internal/agent/config.go`
  - 远程下发的 tests 默认标记为 `PublicOnly`。
  - 本地 `AllowPrivateRemoteTests` 开启时，远程 tests 不标记 public-only。
- `cmd/agent/main.go`
  - 新增 `--allow-private-remote-tests` / `CM_ALLOW_PRIVATE_REMOTE_TESTS`，由 Agent 本地 operator 显式授权远程内网测试。
- `internal/agent/nettest.go`
  - TCP/ICMP 执行前统一校验 host。
  - public-only 测试拒绝 loopback/private/link-local/multicast/unspecified IP。
  - public-only hostname 必须是 FQDN，并先解析；若任一解析 IP 落入本地/内网范围则拒绝。
- `internal/server/settings_contract_test.go`
  - 更新注册 token 测试，锁定已有唯一 token 不可通过 bootstrap 恢复。
  - 新增 raw profile tests 下发忽略、管理 API 拒绝 legacy `tests`、import 拒绝 raw `profiles[*].tests` 的回归。
- `internal/agent/agent_update_test.go`
  - 更新 stale token 测试，锁定 dedicated token 401 后 fail closed。
- `internal/agent/nettest_test.go`
  - 新增 public-only 远程测试拒绝私网 TCP、允许本地私网 TCP、拒绝解析到私网 IP、runtime 默认标记 remote tests 的回归。

### MAGI 验证

- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/server -run 'Test(AgentRegister|AgentConfigIgnoresRawProfileTests|AdminUpdateNodeProfileRejectsLegacyTestsField|ImportConfigRejectsRawProfileTests|Imported)' -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/agent -run 'TestAgentRunnerDoesNotReregisterStaleDedicatedToken|TestMaybeApplyRemoteUpdate' -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/agent -run 'Test(RunSingleNetworkTest|ValidatePublicProbeHost|RuntimeConfig|AgentRunnerDoesNotReregisterStaleDedicatedToken|MaybeApplyRemoteUpdate)' -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/agent ./internal/server ./internal/metrics ./internal/updater -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./cmd/agent -count=1`：pass。
- `git diff --check`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./... -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go vet ./...`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`：pass。

### MAGI 提升

- Agent remote update、remote tests、bootstrap registration 都应按“远程控制面不可信”建模。
- 共享 bootstrap token 只能用于首次 enrollment 或空/重复 token 修复，不能作为专属 token 恢复通道。
- 远程 tests 如果确实需要内网探测，应由 Agent 本地显式授权，而不是由 Server 单方面扩大 Agent 执行面。
- 下一轮建议继续审视 Docker socket 暴露、Agent transport replay/lease、update report state machine 与 public/admin 对外展示的一致性。

## 2026-06-17 / Profile tests cleanup and public-only probe hardening

### MAGI 审视

- 继续当前长期目标，不把上一轮 green tests 当成完成证据。
- 两个只读子代理按 `gpt-5.5 / xhigh` 派发：
  - 一个审计 `NodeProfile.Tests` / `NodeView.Tests` 是否可从运行时模型移除。
  - 一个审计 Agent 远程 network tests public-only 策略。
- 审视结论：
  - `NodeProfile.Tests` / `NodeView.Tests` 已不在真实 agent 配置生成路径中，只是 legacy 残留输出。
  - `AgentConfig.Tests` / `agentrpc.ConfigResponse.Tests` 仍是当前 Agent 下发协议，不能删除。
  - `persist.go` 的 `legacyPersistedProfile.Tests`、`migrateLegacyProfileTests()`、`readLegacyProfileTests()` 必须保留，用于旧 state 文件迁移。
  - public-only 网络测试存在 DNS TOCTOU：校验阶段解析 hostname，通过后 TCP/ICMP 执行阶段又可能重新解析。
  - public-only IP 校验只做基础 deny-list，未覆盖 CGNAT、benchmark、documentation、reserved 等 special-use 地址。
  - trailing-dot FQDN 在 public-only 路径会被普通 host 校验提前误拒。

### MAGI 执行

- `internal/server/server.go`
  - 从 `NodeProfile` 删除 legacy `Tests` 字段。
  - 从 `NodeView` 删除 legacy `Tests` 字段。
  - 删除 waiting / online node view 中对 `profile.Tests` 的透传。
  - 删除 import/profile update normalize 路径里对 `profile.Tests` 的残留清理。
- `internal/server/persist.go`
  - 保留旧持久化迁移结构和函数。
  - 删除迁移完成后对 runtime `profile.Tests` 的清空赋值。
  - 删除 `cloneNodeProfileValue()` 中对 legacy tests 的 clone。
- `internal/server/settings_contract_test.go`
  - `TestImportConfigRejectsRawProfileTests` 改为走 JSON decoder，锁定 config import 中 nested legacy `tests` 会作为 unknown field 被拒绝。
  - `TestLoadPersistedDataMigratesLegacyProfileTests` 增强：
    - 旧 state 文件 `profiles.*.tests` 仍迁移到 catalog + selections。
    - 迁移后的 profile JSON 不再包含 legacy `"tests"`。
    - 迁移后的 selections 仍能通过 `DeliverAgentConfig()` 下发为 `AgentConfig.Tests`。
  - `TestAdminUpdateNodeProfileRejectsLegacyTestsField` 改为断言 selections 不变。
- `internal/agent/nettest.go`
  - public-only hostname 校验改成返回已验证探测目标。
  - TCP/ICMP 执行时使用已验证 IP，结果仍保留原始 host，避免 DNS rebinding / TOCTOU。
  - public-only hostname 先规范化单个 trailing dot，再做语法和 localhost 校验。
  - IP 校验改用 `net/netip` 和 explicit special-use prefix blocklist。
  - 拒绝 CGNAT、benchmark、documentation、reserved、multicast、loopback、private、link-local、unspecified、IPv4-mapped 等非公网可路由地址。
- `internal/agent/nettest_test.go`
  - 新增 public-only ICMP 私网目标执行前拒绝。
  - 新增 hostname 固定到已验证 IP 的 DNS TOCTOU 回归。
  - 新增 trailing-dot FQDN 允许、localhost 变体拒绝。
  - 新增 special-use IP 表驱动拒绝和公网 IP 允许测试。

### MAGI 验证

- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/agent -run 'Test(RunSingleNetworkTest|ValidatePublicProbeHost|RuntimeConfig)' -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/server -run 'Test(ImportConfigRejectsRawProfileTests|LoadPersistedDataMigratesLegacyProfileTests|AdminUpdateNodeProfileRejectsLegacyTestsField|Imported|AgentRegister)' -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/agent ./internal/server ./internal/metrics ./internal/updater ./cmd/agent -count=1`：pass。
- `git diff --check`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./... -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go vet ./...`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`：pass。

### MAGI 提升

- 运行时模型不应保留“禁用但仍能序列化输出”的 legacy 执行配置字段。
- 旧数据兼容应收敛在加载迁移层，不应扩散到当前 API / runtime model。
- 任何 remote-controlled hostname 安全策略都不能只做预解析校验；实际执行必须绑定到已验证目标，避免 DNS rebinding。
- 下一轮建议继续审计 admin import/export contract、Agent update report lease、防重放和 Docker socket 暴露路径。

## 2026-06-17 / Agent update report replay and Docker socket audit

### MAGI 审视

- 本轮继续以当前 worktree 为准，不把上轮全绿验证视作目标完成。
- 主线程审计 Agent update report 状态机：
  - report 已校验 Agent token。
  - report 已绑定 `update_id` 和目标版本。
  - 但同一 `update_id` 的非终态 report 仍可回退状态，例如 `restarting -> updating`。
  - 这会让旧 report/replay 扰乱 lease 和 UI 状态，不是任意命令执行，但属于控制面状态机弱约束。
- 只读子代理 `gpt-5.5 / xhigh` 审计 Docker-managed update / Docker socket：
  - 未发现远程主控可单方面把 Agent 扩大到 Docker socket 执行的路径。
  - Docker-managed update 需要 Agent 本地同时满足：未禁用远程更新、HTTPS 控制面、`CM_ENABLE_DOCKER_UPDATE=1`、可访问已挂载 Docker socket。
  - `CM_ENABLE_DOCKER_UPDATE=1` 已是类似 `AllowPrivateRemoteTests` 的本地显式授权，不建议再加重复开关。
  - 剩余部署面建议是 README 默认 Server Docker 示例不应默认挂载 `/var/run/docker.sock`，后续可单独修正文档/静态测试。

### MAGI 执行

- `internal/server/server.go`
  - 新增 `agentUpdateReportAllowedForCurrentState()`。
  - `applyAgentUpdateReportNodeLocked()` 在匹配 pending instruction 后继续校验状态转移。
  - 允许：
    - `pending -> updating`
    - `pending/updating/restarting -> terminal`
    - `updating -> updating/restarting`
    - `restarting -> restarting`
  - 拒绝：
    - `pending -> restarting`
    - `restarting -> updating`
    - unknown/current terminal 后的非终态 replay。
- `internal/server/agent_update_test.go`
  - 新增 `TestAgentUpdateReportRejectsOutOfOrderStateTransitions`。
  - 新增 `TestAgentUpdateAPIRejectsOutOfOrderStateTransition`。
  - 覆盖 out-of-order report 不改写 message/lease/state，并在 API 层返回 conflict。

### MAGI 验证

- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/server -run 'TestAgentUpdate(Report|API|RPC|GRPC|Queue|Delivered)' -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/server ./internal/agent ./internal/updater -count=1`：pass。
- `git diff --check`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./... -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go vet ./...`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`：pass。

### MAGI 提升

- Agent update report 不只要绑定 token/id/version，还要约束状态转移方向。
- Docker socket 能力当前已有本地 opt-in，不应加重复兼容开关；后续应把部署示例和静态测试收敛到“默认不挂 socket”。
- 下一轮建议继续审计 admin import/export contract 和 Server Docker README/部署默认值，避免敏感运行时字段或高危 socket 暴露成为默认路径。

## 2026-06-17 / Config import DTO and Docker socket default closure

### MAGI 审视

- 本轮只收口上轮明确留下的两个风险点，不继续展开新任务。
- README 的 Server Docker 默认示例仍挂载 `/var/run/docker.sock`，这会把 Docker daemon 权限变成默认部署暴露面。
- admin config import/export 复用了完整 `NodeProfile`：
  - export 已清理 `agent_auth_token` 和 `agent_update*` 字段。
  - 但 `server_id`、`updated_at` 仍会随配置导出。
  - HTTP import 的 `decodeJSON` 会拒绝 unknown fields，但 `agent_auth_token`、`agent_update*`、`server_id`、`updated_at` 在 `NodeProfile` 中是 known fields，因此旧实现会先接受再清理或保留。
- 结论：配置迁移边界应只接受可迁移配置字段，不应复用运行时 profile 结构。

### MAGI 执行

- `README.md`、`README_zh-CN.md`
  - Server Docker 默认命令移除 `/var/run/docker.sock`。
  - 一键更新 Docker Server 改为显式 opt-in：设置 `CM_ENABLE_DOCKER_UPDATE=1` 并手动挂载 Docker socket。
  - Agent Docker 默认命令继续保留 `CM_DISABLE_UPDATE="1"`，Docker Agent 一键更新仍需 `CM_DISABLE_UPDATE=0` 和 `CM_ENABLE_DOCKER_UPDATE=1`。
- `scripts/readme-docker-security.test.mjs`
  - 新增 README 静态护栏。
  - 断言中英文 Server Docker 默认示例不挂载 Docker socket。
  - 断言中英文 Agent Docker 默认示例禁用远程更新且不挂载 Docker socket。
  - 断言 Docker socket 只出现在显式 opt-in 说明中。
- `scripts/verify-local.sh`
  - 将 README Docker security 静态测试纳入本地统一验证入口。
- `internal/server/persist.go`
  - 新增 `ConfigTransferProfile`，只包含可迁移配置字段。
  - `ConfigTransferData.Profiles` 从 `map[string]*NodeProfile` 改为 `map[string]*ConfigTransferProfile`。
  - 新增 `configTransferProfilesFromNodeProfiles()` 和 `configTransferProfilesToNodeProfiles()`。
- `internal/server/server.go`
  - `ExportConfig()` 从 runtime `NodeProfile` 映射为 transfer DTO，避免导出 `server_id`、`updated_at` 和 agent update/runtime token。
  - `ImportConfig()` 先把 transfer DTO 转回 clean `NodeProfile`，再复用现有 normalize / preserve runtime 流程。
- `internal/server/settings_contract_test.go`
  - 新增 runtime profile fields 导入拒绝测试。
  - 新增 top-level runtime state 导入拒绝测试。
  - 新增 export 不包含 profile runtime fields 测试。
  - 既有 config import 测试改为使用 `ConfigTransferProfile`。

### MAGI 验证

- `node --test scripts/readme-docker-security.test.mjs`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/server -run 'Test.*Config|TestImportedNewProfile|TestAdminSnapshotIncludesImportedProfile' -count=1`：pass。
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/admin-kumo.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`：pass，101 tests。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./... -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go vet ./...`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server -run 'TestImportConfigRejectsProfileRuntimeFields|TestExportConfigRedactsProfileRuntimeFields|TestImportConfigRejectsTopLevelRuntimeState' -count=1`：pass。
- `git diff --check`：pass。

### MAGI 提升

- 本轮按用户要求停止新增优化任务。
- 当前交付重点转为本地 demo：绑定 `0.0.0.0`，便于内网其它主机访问和开发查看。

## 2026-06-25 / Admin Kumo polish continuation

### MAGI 审视

- 全页首屏复验覆盖 dashboard、servers、groups、probes、settings、alerts、ai 的 desktop `1440x1000` 与 mobile `390x844`。
- 当前没有发现页面横向溢出、Vite overlay 或 runtime exception。
- `ProbeSettings` 移动端页头仍强制竖排两个 action，导致首屏 header 高度达到 `149px`，和已经收敛后的 `GroupManagement` / `BasicSettings` action rail 节奏不一致。

### MAGI 执行

- `internal/server/web/admin/src/pages/ProbeSettings.tsx`
  - 移除 `adminPageActionsClass` 上的移动端竖排 override。
  - 改为直接复用共享 action rail，让“新增探测节点”和“保存更改”在 390px 手机宽度下同排展示，需要时仍可由共享 `flex-wrap` 换行。
- `internal/server/web/admin-kumo.test.mjs`
  - 将 ProbeSettings 断言从“保持竖排”改为“复用共享 compact action rail”。

### MAGI 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`：pass，75 tests。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build`：pass。
- Headless Chrome/CDP 复验：
  - `mobile-probes` 页头从 `350x149 @ 20,100` 收敛为 `350x101 @ 20,100`。
  - `mobile-probes` 无横向溢出，两个 action 分别为 `148x40 @ 20,144` 与 `110x40 @ 176,144`。
  - desktop/mobile 全页批量首屏复验无 console error、无 runtime exception。

### MAGI 提升

- 后续继续打磨时优先处理跨页密度一致性，而不是再为单页添加局部 override。
- Dashboard mobile 的“核心配置”首屏仍偏重，但需要结合空数据和真实节点数据状态评估，不在本轮扩大改动。

## 2026-06-25 / Dashboard mobile density polish

### MAGI 审视

- 延续上轮全页首屏复验结论，Dashboard mobile 的“核心配置”仍偏重。
- 问题不在文案或数据语义，而在 summary row 的移动端几何：行容器用 `flex-col`，操作按钮落到第二行，导致三个配置项占用过多首屏高度。
- 本轮目标是收敛移动端密度，同时保持桌面端工作台布局和 Kumo 组件直连约束。

### MAGI 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - `adminSummaryRowClass` / `adminSummaryWarningRowClass` 改为全断点横向对齐。
  - summary icon chip 从 `p-2.5` 收到 `p-2`，保留 8px radius 和 tone 色块。
- `internal/server/web/admin/src/pages/Dashboard.tsx`
  - 核心配置与快捷入口 panel body 从移动端 `p-6 space-y-4` 收到 `p-4 space-y-3`，桌面仍保留 `sm:p-6 sm:space-y-4`。
  - summary 行操作按钮改为 `shrink-0`，避免移动端回落到第二行。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 Dashboard compact mobile Kumo rhythm 回归断言。

### MAGI 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`：pass，76 tests。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build`：pass。
- Headless Chrome/CDP 复验：
  - `mobile-dashboard` 无横向溢出、无 Vite overlay、无 runtime exception、无 console error。
  - `mobile-dashboard` 整页高度从上轮约 `1474px` 收敛到 `1266px`。
  - `mobile-dashboard` 核心配置面板约 `350px` 高，summary action 均未文本溢出。
  - `desktop-dashboard` 保持四列指标卡与双栏工作台布局，截图目检无压缩异常。

### MAGI 提升

- 后续继续看真实节点数据态下的 Dashboard 与 ServerManagement，尤其是列表密度、空态到有数据态的过渡，以及暗色模式。

## 2026-06-25 / Admin node meta rhythm polish

### MAGI 审视

- ServerManagement 节点卡片的身份信息已经 chip 化，但下方 4 个 meta 卡仍有两处粗糙点：移动端间距偏松，value/hint 文案层级由页面硬编码维护。
- 这类样式属于管理后台通用 meta pattern，不适合继续在页面内堆局部 class。

### MAGI 执行

- `internal/server/web/admin/lib/admin-ui.ts`
  - `adminWorkspaceMetaGridClass` 收紧移动端 gap，并保留桌面多列布局。
  - `adminWorkspaceMetaCardClass` 改为移动端更紧凑的 padding，桌面恢复原先呼吸感。
  - 新增 `adminWorkspaceMetaValueClass` / `adminWorkspaceMetaHintClass`，统一 meta value 与 hint 的 Kumo 文案节奏。
- `internal/server/web/admin/src/pages/ServerManagement.tsx`
  - 节点列表的 4 个 meta 卡改用共享 value/hint class。
  - 编辑抽屉顶部摘要和 profile 辅助 meta 卡同步改用共享 value class。
- `internal/server/web/admin-kumo.test.mjs`
  - 新增 ServerManagement meta 卡紧凑节奏回归断言，防止重新散落硬编码灰色小字 class。

### MAGI 验证

- `node --test internal/server/web/admin-kumo.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`：pass，79 tests。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build`：pass。
- Headless Chrome/CDP 复验：
  - `desktop-servers` 无横向溢出、无 runtime exception、无 console error；节点 meta 卡 4 个，保持单行布局。
  - `mobile-servers` 无横向溢出、无 runtime exception、无 console error；节点 meta 卡 4 个，按 390px 视口纵向堆叠。
  - 首次截图捕获到进入动画中间帧，已调整验证脚本等待动画结束后再判定稳定状态。

### MAGI 提升

- 下一步继续看 ServerManagement 编辑抽屉内部表单密度，以及 Group picker 在移动端的菜单宽度与空态。

## 2026-07-06 / Admin published-style contract cleanup

### MAGI 审视

- 管理后台已回到 GitHub 已发布版本的中文直写、shadcn 本地组件与 `admin-ui` 共享样式 token 形态。
- 遗留的 `admin-agent-update.test.mjs`、`admin-frontend-contract.test.mjs`、`admin-i18n.test.mjs` 仍按旧 Kumo/i18n 实验架构断言，引用了当前树中不存在的 `admin-i18n.tsx`、`admin-url.ts` 和 `admin-kumo.test.mjs`。
- 风险不是产品代码退化，而是验证边界被旧测试污染，后续会误导恢复已经移除的实验实现。

### MAGI 执行

- `internal/server/web/admin-agent-update.test.mjs`
  - 改为锁定当前发布版 Agent 更新合同：`NodeView.agent_update_*` 平铺字段、API 最小响应、页面内联中文状态文案、timestamp/last_seen freshness 合并。
  - 移除旧 `resolveAgentUpdateDisplay`、`AdminT`、`waiting_registration` 和 i18n key 断言。
- `internal/server/web/admin-frontend-contract.test.mjs`
  - 改为锁定当前发布版前端合同：本地 shadcn 组件、`admin-ui` 样式 token、配置型页面 dirty guard、boot base path API。
  - 明确排除 `admin-kumo.test.mjs` 这类已移除实验入口。
- `internal/server/web/admin-i18n.test.mjs`
  - 保留文件但改变语义，改为断言当前中文后台不依赖已移除 i18n 层，并保留关键中文文案与 helper fallback。
- `scripts/verify-local.sh`
  - 将三个改写后的 admin 合同测试纳入统一 Node test 列表。

### MAGI 验证

- `node --test internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs`：pass，11 tests。
- `node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`：pass，46 tests。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build:admin`：pass。
- `go vet ./...`：pass。
- `go test ./...`：pass。
- `bash scripts/verify-local.sh`：pass，包含 Node tests、`npm ci`、admin lint/build、`go vet ./...`、`go test ./...`。
- `git diff --check`：pass。

### MAGI 提升

- 后续如果要重新做多语言或 Kumo 风格，需要作为明确新目标重新设计，不应通过旧测试“隐式恢复”。
- 当前后台验证重点应放在发布版中文 UI 的行为稳定性：base path、WebSocket snapshot、节点删除部分成功、Agent 更新状态和配置页 dirty guard。

## 2026-07-06 / Published admin style follow-up hardening

### MAGI 审视

- GitHub latest release API 确认当前已发布版本是 `v0.6.3`，发布时间为 `2026-06-01T08:52:24Z`。
- 管理后台继续保持发布版中文直写、local shadcn components 与 `admin-ui` style token 合同；本轮不再引入 Kumo/i18n 样式实验。
- 继续审视时发现两个与样式无关但影响后台安全边界的问题：
  - `site_icon` 只在部分前端路径防御，服务端写入、导入和 public/admin 输出边界需要统一 allowlist。
  - release tag 比较已支持 prerelease，但无效 tag 如 `nightly` 仍可能绕过 `HasUpdate=false` 后进入更新触发路径。

### MAGI 执行

- `internal/server/server.go`
  - `UpdateSettings` 继续对 `site_icon` 走 `normalizeSiteIconURL`。
  - `PublicSettings()` / `SettingsView()` 输出改为 `safeSiteIconURL`，避免旧配置中的危险 URL 泄给 public/admin。
  - `site_icon` allowlist 限定为空、同源相对路径或 `http/https` URL；拒绝 protocol-relative URL、userinfo、fragment、控制字符、反斜杠、路径穿越、畸形 IPv4/zone host 和非 HTTP scheme。
  - 服务端更新与 Agent 更新 POST 在进入 up-to-date 判断、asset 校验和队列前统一调用 `validateReleaseTargetVersion`。
- `internal/updater/updater.go`
  - 新增 `ValidReleaseVersion`。
  - `ApplyLatest` 在真实替换前拒绝无效目标版本。
  - prerelease numeric identifier 按 SemVer 规则拒绝前导零，如 `v1.2.3-01`。
- `internal/server/web/admin/src/App.tsx`
  - admin brand icon 渲染前走 `normalizePublicIconURL`。
  - 外链图标使用 `referrerPolicy="no-referrer"`。
- `internal/server/web/public/assets/monitor.js`
  - public brand icon 与服务端策略对齐，拒绝 `data:` / `javascript:` 等 active-content URL。
- 测试覆盖同步补齐：
  - updater 版本合法性、prerelease precedence、release asset URL。
  - settings 写入/导入/旧配置输出的 `site_icon` allowlist。
  - Agent 更新无效 latest version 不入队。
  - system update target version helper。
  - public/admin 图标 URL 静态合约。

### MAGI 验证

- `node --test internal/server/web/public-assets.test.mjs internal/server/web/admin-frontend-contract.test.mjs`：pass，12 tests。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build:admin`：pass。
- `go test ./internal/updater ./internal/server -run 'TestVersionsEqual|TestHasVersionUpdate|TestVersionCurrentOrNewer|TestValidReleaseVersion|TestCompareVersions|TestValidateReleaseAssetURLs|TestSiteIcon|TestUpdateSettingsRejectsInvalidSiteIconURL|TestImportConfigRejectsInvalidSiteIconURL|TestSettingsViewsOmitUnsafeLegacySiteIconURL|TestAgentUpdateAdminHandlerRejectsInvalidLatestVersion|TestValidateReleaseTargetVersion|TestSystemUpdate' -count=1`：pass。
- `go test ./internal/updater ./internal/server ./internal/agent -count=1`：pass。
- `go test ./... -count=1`：pass。
- `go vet ./...`：pass。
- `git diff --check`：pass。
- `lsof -nP -iTCP:25213 -sTCP:LISTEN`：无输出，确认本地 demo listener 已关闭。

### MAGI 提升

- 后台视觉风格已按 `v0.6.3` 发布版合同冻结；后续默认只做行为、安全和验证补强。
- 若要再次改视觉体系，应先明确新 UI 目标与迁移边界，避免和“还原发布版样式”目标冲突。

## 2026-07-06 / Latest admin deps and control-plane validation hardening

### MAGI 审视

- admin 子项目没有根级 `package.json`，真实依赖入口是 `internal/server/web/admin/package.json`。
- `npm outdated --json` 显示 admin direct dependencies 中 `vite`、`react`、`lucide-react`、`@base-ui/react`、Tailwind/Vite/TypeScript 相关包落后。
- `npm audit --json` 指出 direct `vite@8.0.8` 命中 high severity advisory，范围为 `8.0.0 - 8.0.15`。
- `autoprefixer`、direct `postcss`、`tsx` 在 admin 源码、脚本和配置中没有直接引用；当前 Tailwind v4 通过 `@tailwindcss/vite` 集成。
- 并行 reviewer 指出：
  - `saveSettings()` / `importConfig()` 成功后，后续 `fetchNodes()` 失败会把已提交 mutation 误报成失败。
  - `BasicSettings` 会因无关 `settings.version` 刷新重建草稿并清掉 dirty 状态。
  - admin path 更新会丢失当前 `?page=...` 和 hash。
  - 控制面排队/启动 binary update 前只做非空资产检查，真正 release asset URL 绑定校验被推迟到执行端。
  - Agent Docker-managed 更新能力在 runner 启动时缓存，后续不会刷新。
  - `AgentUpdateReport.ID` JSON tag 与 HTTP wire contract 的 `update_id` 不一致。

### MAGI 执行

- `internal/server/web/admin/package.json` / `package-lock.json`
  - 删除未使用 direct devDependencies：`autoprefixer`、`postcss`、`tsx`。
  - 升级 direct dependencies 到当前 npm latest：
    - `@base-ui/react@1.6.0`
    - `@fontsource-variable/geist@5.2.9`
    - `@tailwindcss/vite@4.3.2`
    - `@types/node@26.1.0`
    - `@types/react@19.2.17`
    - `@vitejs/plugin-react@6.0.3`
    - `lucide-react@1.23.0`
    - `react@19.2.7`
    - `react-dom@19.2.7`
    - `tailwind-merge@3.6.0`
    - `tailwindcss@4.3.2`
    - `typescript@6.0.3`
    - `vite@8.1.3`
- `internal/server/web/admin/lib/admin-api.ts`
  - 新增 `adminAppLocation()`，基于 `adminAppPath()` 保留当前 `search/hash`。
- `internal/server/web/admin/src/App.tsx`
  - `updateSettings()` / `handleImport()` 在 mutation 成功后立即返回 canonical response。
  - 后续节点刷新改成 warning-only，不再把已成功保存/导入改写成失败。
  - 导入后 admin path 跳转改用 `adminAppLocation()`。
- `internal/server/web/admin/src/pages/BasicSettings.tsx`
  - 新增基础设置页字段级 source signature。
  - 只有本页 canonical 字段变化时才 rebase draft；无关 `version/commit` 刷新不再覆盖未保存输入。
  - dirty 状态下收到远端基础设置变化时保留草稿并提示用户。
  - admin path 保存后跳转保留 query/hash。
- `internal/updater/updater.go`
  - 导出 `ValidateReleaseAssetURLs()`，让控制面和执行端共用同一条 GitHub release asset URL/tag/asset 绑定校验。
- `internal/server/system_update.go`
  - `agentUpdateReleaseAssetError()` / `systemUpdateReleaseAssetError()` 从非空检查升级为非空 + URL/tag/asset 绑定校验。
- `internal/agent/runtime.go`
  - 删除 `agentRunner.dockerManagedUpdate` 启动期缓存，每次 stats 上报重新读取 `canDockerManagedUpdate()`。
- `internal/server/server.go`
  - `AgentUpdateReport.ID` JSON tag 对齐为 `update_id`。
- 测试同步补齐：
  - admin path location 保留 query/hash。
  - settings mutation 成功与节点刷新失败拆分。
  - BasicSettings 只按本页 source signature rebase。
  - binary release asset mismatch 不入队/不启动。
  - AgentUpdateReport JSON 使用 `update_id`。

### MAGI 验证

- `npm --prefix internal/server/web/admin ci --cache /SourceCode/CyberMonitor/.cache/npm`：pass，0 vulnerabilities。
- `npm outdated --json --cache /SourceCode/CyberMonitor/.cache/npm`：pass，返回 `{}`。
- `npm audit --json --cache /SourceCode/CyberMonitor/.cache/npm`：pass，0 vulnerabilities。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build:admin`：pass，Vite `8.1.3`。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs`：pass，26 tests。
- `go test ./internal/updater ./internal/server -run 'TestValidateReleaseAssetURLs|TestAgentUpdateReleaseAssetError|TestSystemUpdateReleaseAssetError|TestAgentUpdateAdminHandler|TestAgentUpdateReportJSONUsesUpdateID|TestAgentUpdateHTTPReportHandlerUsesUpdateID|TestAgentUpdateAPIRejectsStaleReport|TestSystemUpdate' -count=1`：pass。
- `go test ./internal/agent -count=1`：pass。
- `go test ./... -count=1`：pass。
- `go vet ./...`：pass。
- `go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`：pass。
- `git diff --check`：pass。

### MAGI 提升

- `systemUpdateManager.Start()` 仍是测试使用的第二入口，生产路径走 `ReserveStart().Start()`；后续可以把测试迁到 reservation 入口后删除该方法。
- Docker daemon recreate smoke 仍需要真实 Docker daemon 和显式环境变量，当前本地全量测试只覆盖单元路径。
- ServerManagement 同一节点外部 profile 变化后的 dirty conflict/rebase 仍是后续优先项。

## 2026-07-06 / Admin published-style restore after demo shutdown

### MAGI 审视

- 当前环境没有监听中的本地 demo TCP 服务，`lsof -nP -iTCP -sTCP:LISTEN` 未返回监听项。
- GitHub latest release API 确认当前已发布版本是 `v0.6.3`，发布时间 `2026-06-01T08:52:24Z`；本地 `v0.6.3` tag 可作为后台样式基线。
- `internal/server/web/admin/components`、`src/index.css`、`src/styles` 与 `v0.6.3` 无 diff。
- `Login`、`Dashboard`、`AIProvider`、`NotificationAlert`、`ProbeSettings`、`GroupManagement` 与 `v0.6.3` 无 diff。
- `Kumo`、`admin-kumo`、`AdminI18nProvider` 在 admin 源码中无残留。
- 样式偏离点来自 `ServerManagement` 新增的“放弃未保存的节点配置修改”弹窗；该弹窗不是 `v0.6.3` 发布版视觉结构。

### MAGI 执行

- 移除 `ServerManagement` 新增的节点编辑 dirty tracking 和 discard dialog。
- 移除 `App.tsx` 向 `ServerManagementPage` 传入 `onDirtyChange` 的改动。
- 更新 `admin-frontend-contract.test.mjs`，明确节点管理页保持发布版视觉结构，不引入新增未保存弹窗。
- 保留不改变视觉结构的行为修复：
  - 设置保存/导入成功与后续节点刷新失败解耦。
  - 基础设置页按字段 source signature rebase。
  - admin path 更新保留 query/hash。
  - 删除节点时区分 profile 删除成功与历史清理失败。

### MAGI 验证

- `git diff v0.6.3 -- internal/server/web/admin/components internal/server/web/admin/src/index.css internal/server/web/admin/src/styles internal/server/web/admin/components.json`：无 diff。
- `git diff v0.6.3 -- internal/server/web/admin/src/pages/Login.tsx internal/server/web/admin/src/pages/Dashboard.tsx internal/server/web/admin/src/pages/AIProvider.tsx internal/server/web/admin/src/pages/NotificationAlert.tsx internal/server/web/admin/src/pages/ProbeSettings.tsx internal/server/web/admin/src/pages/GroupManagement.tsx`：无 diff。
- `grep -RIn "kumo\|Kumo\|@cloudflare" internal/server/web/admin --exclude-dir=node_modules --exclude-dir=dist`：无匹配。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `npm --prefix internal/server/web/admin run build:admin`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs`：pass，26 tests。
- `git diff v0.6.3 -- internal/server/web/admin/src/App.tsx internal/server/web/admin/src/pages/BasicSettings.tsx internal/server/web/admin/src/pages/ServerManagement.tsx | grep -n "^[+-].*\(className\|style=\|放弃未保存的节点\|Kumo\|admin-kumo\)"`：无匹配。
- `git diff --check`：pass。
- `curl -s https://api.github.com/repos/crazy0x70/CyberMonitor/releases/latest`：latest tag 为 `v0.6.3`，`published_at` 为 `2026-06-01T08:52:24Z`。

## 2026-07-06 / System update start entrypoint consolidation

### MAGI 审视

- `systemUpdateManager.Start()` 是测试专用的第二启动入口；生产 `/api/v1/admin/system/update` 已经走 `ReserveStart()` -> release check -> `reservation.Start()`。
- 该第二入口会让测试绕过生产 reservation 语义，和“代码简洁直接高效、不要冗余兼容路径”的要求不一致。
- 并行 backend reviewer 复核后确认：删除 direct `Start()` 不影响生产路径；真实风险是 `ReserveStart()` 成功后的 early return 必须 `Cancel()`。
- 并行 frontend/style reviewer 复核后确认：本轮只改 `internal/server/system_update.go` 和 `internal/server/system_update_test.go`，不影响后台 `v0.6.3` 样式还原。

### MAGI 执行

- 删除 `systemUpdateManager.Start()` direct launch 方法。
- 将 `internal/server/system_update_test.go` 的启动路径统一迁移到 `startSystemUpdate()` helper。
- `startSystemUpdate()` 内部只走 `ReserveStart()` + `reservation.Start()`，让测试覆盖生产一致的单入口。
- 并发 reservation 测试从“reserved 后 direct Start 被拒绝”改为“reserved 后第二次 ReserveStart 被拒绝”。

### MAGI 验证

- `grep -RIn "func (m \\*systemUpdateManager) Start\|manager\.Start\|systemUpdater\.Start" --exclude-dir=.git --exclude-dir=.gocache --exclude-dir=.cache --exclude-dir=.tmp --exclude-dir=.gomodcache --exclude-dir=node_modules --exclude-dir=dist --exclude=evolution_log.md internal cmd scripts .github`：无匹配。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache GOTMPDIR=/SourceCode/CyberMonitor/.tmp TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/server -run 'TestSystemUpdate|TestDockerManagedSystemUpdateLaunchesDetachedHelper|TestSystemUpdateHandlerReservesStartBeforeReleaseCheck' -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache GOTMPDIR=/SourceCode/CyberMonitor/.tmp TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/server -count=1`：pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go-path GOMODCACHE=/SourceCode/CyberMonitor/.gomodcache GOCACHE=/SourceCode/CyberMonitor/.gocache GOTMPDIR=/SourceCode/CyberMonitor/.tmp TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/server -run 'TestServerServesStaticAssetsAndAdminBoot|TestAdminPathRedirectHonorsForwardedPrefix|TestAdminBootPayloadHonorsForwardedPrefix|TestSystemUpdate' -count=1`：pass。
- `git diff v0.6.3 -- internal/server/web/admin/components internal/server/web/admin/src/index.css internal/server/web/admin/src/styles internal/server/web/admin/components.json internal/server/web/admin/src/main.tsx internal/server/web/admin/vite.config.ts internal/server/web/admin/index.html`：无 diff。
- `git diff v0.6.3 -- internal/server/web/admin/src/pages/Login.tsx internal/server/web/admin/src/pages/Dashboard.tsx internal/server/web/admin/src/pages/AIProvider.tsx internal/server/web/admin/src/pages/NotificationAlert.tsx internal/server/web/admin/src/pages/ProbeSettings.tsx internal/server/web/admin/src/pages/GroupManagement.tsx`：无 diff。
- `git diff v0.6.3 -- internal/server/web/admin/src/App.tsx internal/server/web/admin/src/pages/BasicSettings.tsx internal/server/web/admin/src/pages/ServerManagement.tsx | grep -n "^[+-].*\(className\|style=\|Kumo\|admin-kumo\|放弃未保存的节点\)"`：无匹配。
- `grep -RIn "kumo\|Kumo\|admin-kumo\|@cloudflare" internal/server/web/admin/src internal/server/web/admin/lib internal/server/web/admin/components internal/server/web/admin/package.json internal/server/web/admin/components.json`：无匹配。

## 2026-07-06 / ServerManagement same-node source rebase

### MAGI 审视

- `ServerManagement` 旧逻辑只用 `editingNodeId::testCatalogSignature` 作为初始化 key。
- 同一节点 profile 更新但 catalog 不变时，之前新增的 source signature 能保留 dirty 草稿并 toast。
- 同一节点 `test_catalog` 更新时，初始化 key 会变化，旧逻辑会在 dirty 判断前直接 `setForm(nextForm)`，覆盖用户正在编辑的草稿。
- 并行 rebase reviewer 指出：`test_catalog` 是 source 的一部分，但不是用户草稿字段本身；需要拆分 draft signature 和 source signature。
- 并行 style reviewer 指出：行为修复方向正确，但需要额外锁住 `ServerManagement` 编辑器 chrome，避免借 rebase 修复引入样式偏移。

### MAGI 执行

- 将 `formSourceSignature(form)` 拆成：
  - `formDraftSignature(form)`：只描述当前表单草稿，用于 dirty 判断。
  - `formSourceSignature(form, testCatalogSignature)`：描述 canonical source，纳入 `testCatalogSignature`。
- 新增 `formBaselineSignatureRef`，让 baseline 与 source signature 分离。
- `formInitializationKeyRef` 只使用 `editingNodeId`；catalog 变化不再触发强制初始化，而是走同节点 source-change 流程。
- 同节点 source 更新时：
  - clean draft：自动 rebase 到 `nextForm`。
  - dirty draft：更新 baseline/source signature，保留用户草稿，并显示 `服务端节点配置已更新，当前未保存修改已保留。`
  - saving/deleting 中：保持 busy lock，不中途重建表单。
- `admin-frontend-contract.test.mjs` 增加两类守护：
  - source/baseline 分离、catalog source 参与签名、dirty 分支在 clean rebase 前。
  - `ServerManagement` 编辑器 chrome、节点卡片、Dialog header/footer、5 个详情卡片继续保持 `v0.6.3` 发布版结构。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：pass，9 tests。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs`：pass，28 tests。
- `npm --prefix internal/server/web/admin run build:admin`：pass，Vite `8.1.3`。
- `git diff v0.6.3 -- internal/server/web/admin/src/App.tsx internal/server/web/admin/src/pages/BasicSettings.tsx internal/server/web/admin/src/pages/ServerManagement.tsx | grep -n "^[+-].*\(className\|style=\|Kumo\|admin-kumo\|放弃未保存的节点\)"`：无匹配。
- `git diff --check`：pass。

## 2026-07-06 / BasicSettings equal-source dirty rebaseline

### MAGI 审视

- `BasicSettings` 的 dirty 状态是 latch，而不是从当前 draft 与 source signature 推导。
- 旧流程中，用户把 draft 改成 `B` 后，如果服务端 incoming canonical 也变成 `B`，effect 会推进 `sourceSignature` 并提示“当前未保存修改已保留”，但不会清 `isDirty`。
- 下一轮 effect 因 `sourceSignature === nextSourceSignature` 直接返回，页面会残留“有未保存的修改”、保存按钮和离开页面 guard。
- 并行状态 reviewer 复核确认该 false dirty 场景成立，并指出 `adminPass` 是 write-only 字段，非空时不能因为其它 canonical 字段等值而清 dirty。
- 并行样式 reviewer 复核确认：本轮限定在 BasicSettings 状态逻辑与静态 contract，不触碰 className/style/CSS/Vite/package/dist 时，不会破坏后台 `v0.6.3` 发布版样式。

### MAGI 执行

- 新增 `BasicSettingsDraft` 类型和 `basicSettingsDraftSignature()`，让 source signature 与当前 draft signature 共用同一字段序列。
- 新增渲染期派生的 `currentDraftSignature`。
- rebase effect 调整为：
  - 先判断 `isDirty && !adminPass.trim() && currentDraftSignature === nextSourceSignature`。
  - 等值时更新 `sourceSignature`、清 `isDirty`、关闭确认弹窗并返回。
  - 再判断 `nextSourceSignature === sourceSignature`。
  - dirty 且不等值时继续保留草稿并显示远端更新 toast。
- `admin-frontend-contract.test.mjs` 补充：
  - BasicSettings 当前 draft signature 参与 rebaseline。
  - 等值清 dirty 必须发生在远端更新 toast 之前。
  - `adminPass.trim()` 非空时不能自动清 dirty。
  - rebaseline 状态逻辑块不得夹带 `className`、`style`、`<Card`、`<Dialog`。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：pass，9 tests。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs`：pass，28 tests。
- `npm --prefix internal/server/web/admin run build:admin`：pass，Vite `8.1.3`。
- `git diff v0.6.3 -- internal/server/web/admin/src/App.tsx internal/server/web/admin/src/pages/BasicSettings.tsx internal/server/web/admin/src/pages/ServerManagement.tsx | grep -n "^[+-].*\(className\|style=\|Kumo\|admin-kumo\|放弃未保存的节点\)"`：无匹配。
- `git diff --check`：pass。

## 2026-07-06 / Settings pages canonical rebase sweep

### MAGI 审视

- 并行状态 reviewer 指出 `AIProvider`、`NotificationAlert`、`GroupManagement` 仍存在 settings props 更新直接覆盖 dirty 草稿的问题。
- 并行样式 reviewer 指出：后台样式已回到 `v0.6.3` 发布版基线，后续状态修复必须用 contract test 锁住“状态逻辑块不夹带 className/style/Kumo 变更”。
- 主线程复查确认：
  - `ProbeSettings` 已有 `sourceSignature`，但 source 更新时仍会直接覆盖 dirty 草稿。
  - `AIProvider`、`NotificationAlert` 的 `onSave` 仍返回 `Promise<void>`，父级 `App.tsx` 用 `.then(() => undefined)` 丢掉 canonical `SettingsView`。
  - `GroupManagement` 保存后仍把 request payload 当 baseline，`incomingSignature` 变化也会直接覆盖本地草稿。
  - `BasicSettings` 与 `ProbeSettings` 保存/导入过程中仍有部分输入入口可继续改草稿。

### MAGI 执行

- `ProbeSettings`：
  - 将 `onSave` 改为返回 canonical `SettingsView`。
  - 新增 `draftSignature` 与 `isBusy`。
  - source 更新时先判断 dirty draft 是否等于 incoming canonical；等值则清 dirty，不等则保留草稿并 warning。
  - 保存成功后用 `savedSettings.test_catalog` 回写 draft/source signature。
  - create/edit/delete/dialog input/dialog save/delete confirm 接入 busy lock。
- `AIProvider`：
  - 新增 `AISettingsDraft`、`makeAISettingsDraft()`、`aiSettingsDraftSignature()`、`aiSettingsSourceSignature()`。
  - `onSave` 改为返回 canonical `SettingsView`，父级不再丢弃 `updateSettings("ai", payload)` 的返回值。
  - dirty draft 遇到 incoming canonical 等值时清 dirty；不等值时保留草稿并 warning。
  - 保存成功后用 `savedSettings.ai_settings` 重建 providers、commandProvider、prompt 和 source signature。
- `NotificationAlert`：
  - 新增 `AlertSettingsDraft`、`makeAlertSettingsDraft()`、`alertSettingsDraftSignature()`、`alertSettingsSourceSignature()`。
  - `onSave` 改为返回 canonical `SettingsView`，父级不再丢弃 `updateSettings("alerts", payload)` 的返回值。
  - dirty rebase 逻辑改为等值清 dirty，不等值保留草稿并 warning。
  - 保存成功后用 canonical alert 字段回写表单和 source signature。
- `GroupManagement`：
  - `onSave` 改为返回 canonical `SettingsView`，父级不再丢弃 `updateSettings("groups", { group_tree })` 的返回值。
  - 新增 `sourceSignature`，让 `isDirty` 从 `sourceSignature !== draftSignature` 派生。
  - `incomingSignature` 变化时，dirty 等值清 dirty，dirty 不等值保留草稿并 warning，clean 状态才 rebase。
  - 保存成功后用 `savedSettings.group_tree` 回写 draft/source signature；如果响应缺字段才使用提交 payload 作为 fallback。
  - 分组增删、标签增删、拖拽、输入、保存入口接入 `isBusy` 短路/disabled。
- `BasicSettings`：
  - 新增 `isBusy = isSaving || isImporting`。
  - 文本输入 change handler、保存、导入和文件选择回调在 busy 时短路。
  - 基础设置所有输入在 busy 时 disabled。
- `admin-frontend-contract.test.mjs`：
  - 新增 Probe/AI/Alert/Group canonical rebase contract。
  - 扩展 Basic/Probe/Group busy lock contract。
  - 对 rebase/source-signature 状态逻辑块继续断言不得夹带 `className`、`style`、`<Card`、`<Dialog`。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：pass，13 tests。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs`：pass，32 tests。
- `npm --prefix internal/server/web/admin run build:admin`：pass，Vite `8.1.3`。
- `git diff v0.6.3 -- internal/server/web/admin/src/App.tsx internal/server/web/admin/src/pages/BasicSettings.tsx internal/server/web/admin/src/pages/ProbeSettings.tsx internal/server/web/admin/src/pages/NotificationAlert.tsx internal/server/web/admin/src/pages/AIProvider.tsx internal/server/web/admin/src/pages/GroupManagement.tsx internal/server/web/admin/src/pages/ServerManagement.tsx | grep -n "^[+-].*\(className\|style=\|Kumo\|admin-kumo\|@kumo\)"`：无匹配。
- `git diff --check`：pass。

## 2026-07-07 / Admin async busy lock and style guard closeout

### MAGI 审视

- 当前没有发现 demo 进程仍在运行；`ps` 对 `go run ./cmd/server`、`cmd/server`、`npm dev/preview`、`vite` 的匹配无输出。
- 并行状态 reviewer 指出：
  - `AIProvider` 保存、测试、拉模型期间仍可修改同一份草稿，异步成功会覆盖或误标新输入。
  - `NotificationAlert` 保存/测试期间仍可输入，canonical rebase 会覆盖保存中输入。
  - `ServerManagement` 保存/删除/Agent 更新/刷新与编辑器输入可以交错，且同节点 source 更新时 dirty baseline 处理可能产生 false warning 或远端字段回退。
- 主线程复核确认：这些问题属于行为一致性，不需要改视觉 token；本轮必须继续保持 GitHub 发布版 `v0.6.3` 的后台 `className/style/Kumo` 差异守门为无输出。

### MAGI 执行

- `AIProvider`：
  - 增加父级 `saving={savingPage === "ai"}` 传递。
  - 统一 `isBusy = isSaving || externalSaving || testingId !== null || fetchingModelsId !== null`。
  - 草稿输入、新增/删除兼容服务商、测试、拉模型、保存入口全部增加 busy guard。
  - 所有会改草稿的控件在 busy 时 disabled，避免异步返回覆盖保存中/测试中输入。
- `NotificationAlert`：
  - `isBusy` 纳入 `testingChannel !== null`。
  - 输入 handler、保存、测试入口全部增加 busy guard。
  - 离线阈值、Telegram、飞书输入与测试按钮在 busy 时 disabled。
- `ProbeSettings`：
  - `handleSave` 增加 `isBusy` guard，覆盖非 UI 入口和极快重复触发。
- `ServerManagement`：
  - 新增 `sourceConflict`、`editorBusy`、`editorInputDisabled`。
  - 表单 mutation 统一经过 `patchForm` busy guard。
  - 保存、删除、刷新、Agent 检查、Agent 更新入口增加 guard。
  - 同节点 source 更新时先处理 `currentDraftMatchesIncoming`；dirty 且不等值时设置 conflict，保留草稿但禁用继续保存，要求取消后重开，避免完整 payload 覆盖远端新字段。
  - 节点切换时清空 `agentUpdateInfo`。
  - Agent 更新异步回包绑定 `requestSeq + requestNodeID`，避免旧节点回包污染新打开的节点。
  - 编辑器 busy 时阻止 Dialog 关闭；保存/删除成功后使用强制关闭路径。
- `admin-frontend-contract.test.mjs`：
  - 扩展 AI/告警/探测/节点编辑器的 busy lock 和 canonical rebase contract。
  - 扩展 ServerManagement source conflict、Agent 更新回包隔离、控件 disabled 和“状态逻辑不夹带样式改动”断言。

### MAGI 验证

- `node --test internal/server/web/admin-frontend-contract.test.mjs`：pass，13 tests。
- `npm --prefix internal/server/web/admin run lint`：pass。
- `node --test internal/server/web/admin-api.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/public-assets.test.mjs`：pass，32 tests。
- `npm --prefix internal/server/web/admin run build:admin`：pass，Vite `8.1.3`。
- `git diff v0.6.3 -- internal/server/web/admin/src/App.tsx internal/server/web/admin/src/pages/BasicSettings.tsx internal/server/web/admin/src/pages/ProbeSettings.tsx internal/server/web/admin/src/pages/NotificationAlert.tsx internal/server/web/admin/src/pages/AIProvider.tsx internal/server/web/admin/src/pages/GroupManagement.tsx internal/server/web/admin/src/pages/ServerManagement.tsx | grep -n "^[+-].*\(className\|style=\|Kumo\|admin-kumo\|@kumo\)"`：无匹配。
- `grep -RIn $'\t' internal/server/web/admin/src/pages/AIProvider.tsx internal/server/web/admin/src/pages/NotificationAlert.tsx internal/server/web/admin/src/pages/ServerManagement.tsx`：无匹配。
- `git diff --check`：pass。

## 2026-07-08 / Agent update protocol boundary and callback SSRF sweep

### MAGI 审视

- 以当前 worktree 重新复核，旧 summary 只作为线索；当前 dirty diff 仍覆盖 Go server/agent/updater、admin frontend、public assets、scripts、Docker/release 与 `evolution_log.md`。
- 版本复核：
  - Go 官方 `VERSION?m=text`：`go1.26.4`，timestamp `2026-05-29T15:26:39Z`。
  - Node 官方 dist index 当前首条：`v26.4.0`，date `2026-06-24`。
  - GitHub release API：`actions/checkout@v7.0.0`、`actions/setup-go@v6.5.0`、`actions/setup-node@v6.4.0`、`actions/cache@v6.1.0`、`actions/upload-artifact@v7.0.1`、`actions/download-artifact@v8.0.1`、`docker/setup-qemu-action@v4.2.0`、`docker/build-push-action@v7.3.0`。
- 并行 Go reviewer 指出两个必须处理的问题：
  - `remote-update` capability 被复用，但 update report 已要求 `update_id`，新 server 无法区分旧 agent 和新协议 agent。
  - Webhook/callback DNS 解析后的 IP 拦截只覆盖 private/loopback/link-local/multicast，未覆盖 `100.64/10`、`198.18/15`、文档网段和 IPv6 special-use 段。
- 并行 admin reviewer 未发现 blocker，但指出 `normalizeBasePath()` 可直接拒绝 `?`、`#` 和 control chars，避免前端路径约束弱于服务端。
- scripts/public/Docker reviewer 未发现 blocker；其只读验证通过。
- 本地 `/tmp` 被旧审计缓存占满，导致 sandbox 命令启动失败；已删除 `/tmp/cm-review-go-build`、`/tmp/cm-review-gopath`、`/tmp/cybermonitor-go-mod`、`/tmp/cm-clean-index` 这 4 个临时缓存目录，释放后 `/tmp` 从 100% 降到约 3%。

### MAGI 执行

- Agent update capability：
  - `AgentCapabilityRemoteUpdate` 的 wire value 从旧 `remote-update` 改为 `remote-update-v2`。
  - 新 agent 只上报 `remote-update-v2`；server 只把该 capability 当作支持带 `update_id` report 的新协议。
  - 增加 HTTP/gRPC 回归：旧字面量 `remote-update` 不触发 update 下发，也不刷新 update lease。
- Callback SSRF：
  - 新增 `internal/netguard`，集中维护 public-only IP 判定和 special-use prefix blocklist。
  - agent 远程探测与 server webhook/callback 共用同一 blocklist，避免两套策略漂移。
  - Webhook 直接 URL 和 DNS 解析路径新增 `100.64.0.1`、`198.18.0.1`、`192.0.2.1`、`198.51.100.1`、`203.0.113.1`、`64:ff9b::1`、`100::1`、`2001:db8::1` 等拒绝用例。
- Admin base path：
  - `normalizeBasePath()` 直接拒绝 `?`、`#`、C0 control chars 和 DEL。
  - 新增多轮编码的 `?`、`#`、反斜杠与 `%00` 回归。

### MAGI 验证

- `npm exec --yes --cache /SourceCode/CyberMonitor/.cache/npm --package=node@26.4.0 -- node --version`
  - `v26.4.0`。
- `npm --prefix internal/server/web/admin ls --depth=0`
  - package tree 与 `package.json` 一致。
- `npm --prefix internal/server/web/admin --cache /SourceCode/CyberMonitor/.cache/npm outdated --json`
  - `{}`。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go list -m -u -f '{{if and .Update (not .Indirect)}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all`
  - 无输出，当前 direct Go dependencies 无可用更新；transitive updates 未盲目提升。
- `npm exec --yes --cache /SourceCode/CyberMonitor/.cache/npm --package=node@26.4.0 -- node --test scripts/agent-ps1.test.mjs scripts/one-click.test.mjs scripts/build-local.test.mjs scripts/readme-docker-security.test.mjs internal/server/web/admin-agent-update.test.mjs internal/server/web/admin-api.test.mjs internal/server/web/admin-delete-node.test.mjs internal/server/web/admin-frontend-contract.test.mjs internal/server/web/admin-i18n.test.mjs internal/server/web/go-vuln-surface.test.mjs internal/server/web/public-assets.test.mjs .github/workflows/build-release.test.mjs`
  - pass，64 tests。
- `npm exec --yes --cache /SourceCode/CyberMonitor/.cache/npm --package=node@26.4.0 -- node ./node_modules/typescript/bin/tsc --noEmit`
  - pass。
- `npm exec --yes --cache /SourceCode/CyberMonitor/.cache/npm --package=node@26.4.0 -- node ./node_modules/vite/bin/vite.js build`
  - pass，Vite `8.1.3`。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/agent ./internal/server ./internal/updater ./cmd/agent ./cmd/server -run 'Test.*(AgentUpdate|RemoteUpdate|Capability|Webhook|Callback|Docker|SystemUpdate)' -count=1`
  - pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./internal/agent ./internal/server -run 'Test.*(PublicProbe|Webhook|Callback)' -count=1`
  - pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go vet ./...`
  - pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test ./...`
  - pass。
- `GOPATH=/SourceCode/CyberMonitor/.cache/go GOMODCACHE=/SourceCode/CyberMonitor/.cache/go-mod GOCACHE=/SourceCode/CyberMonitor/.cache/go-build TMPDIR=/SourceCode/CyberMonitor/.tmp go test -race ./internal/server ./internal/server/history ./internal/agent ./internal/updater -count=1`
  - pass。
- `bash scripts/verify-local.sh`
  - pass；64 Node tests、`npm ci` audit 0 vulnerabilities、admin lint/build、`go vet ./...`、`go test ./...` 全部通过。
- `bash scripts/build-local.sh`
  - pass；复用 `verify-local.sh` 后成功生成 `dist/cyber-monitor-server-local` 和 `dist/cyber-monitor-agent-local`。
- `git diff --check`
  - pass。

### MAGI 提升方向

- `remote-update-v2` 现在是明确协议边界；后续如再改变 report/instruction 合同，继续 bump capability，而不是复用旧 wire value。
- Webhook 与 agent public probe 已共享 special-use IP blocklist；后续新增 SSRF/egress surface 应优先复用 `internal/netguard`。
- 当前仍未做真实 GitHub Actions run、真实 Docker daemon build/push、浏览器交互 smoke；这些属于运行环境验证，不应由本地静态/单测结论替代。
