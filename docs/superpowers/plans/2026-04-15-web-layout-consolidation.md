# Web Layout Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将前端源码、前端产物和服务端嵌入路径收敛为单一目录体系，并删除旧的管理页兼容层。

**Architecture:** 管理端源码统一放在 `internal/server/web/admin/`，构建产物统一放在 `internal/server/web/dist/admin/`，公开页继续保留在 `internal/server/web/public/`。服务端仅依赖新目录，删除 `legacy`、`admin-app`、`admin-assets` 路由和相关兼容代码。

**Tech Stack:** Go, `go:embed`, React, Vite, npm, GitHub Actions

---

### Task 1: 收敛前端目录

**Files:**
- Modify: `internal/server/web/`
- Remove: `internal/server/web-src/`, `internal/server/web/admin-app/`, `internal/server/web/admin-assets/`, `internal/server/web/legacy/`

- [ ] 将 `internal/server/web/admin/` 移动到 `internal/server/web/admin/`。
- [ ] 创建或重命名管理端产物目录为 `internal/server/web/dist/admin/`。
- [ ] 删除旧的源码与产物目录。

### Task 2: 收敛服务端嵌入与路由

**Files:**
- Modify: `internal/server/server.go`
- Test: `internal/server/server_admin_routes_test.go`

- [ ] 更新 `go:embed` 路径，只保留 `web/public/*` 与 `web/dist/admin/*`。
- [ ] 更新管理端 HTML 读取路径到 `web/dist/admin/index.html`。
- [ ] 删除 `/legacy`、`/admin-assets/` 等旧兼容路由与处理器。
- [ ] 更新路由测试为新路径。

### Task 3: 收敛前端构建链路

**Files:**
- Modify: `Dockerfile`
- Modify: `.github/workflows/build-release.yml`
- Modify: `.github/workflows/README.md`
- Modify: `internal/server/web/admin/scripts/sync-admin.mjs`

- [ ] 将所有 npm 构建输入目录改为 `internal/server/web/admin/`。
- [ ] 将所有产物输出和打包目录改为 `internal/server/web/dist/admin/`。
- [ ] 删除历史产物同步说明。

### Task 4: 更新测试与说明

**Files:**
- Modify: `internal/server/ui_guidelines_test.go`
- Modify: `README.md`

- [ ] 将所有前端源码路径引用改到 `internal/server/web/admin/`。
- [ ] 将所有嵌入产物路径引用改到 `internal/server/web/dist/admin/`。
- [ ] 更新 README 中的目录说明和前端构建命令。

### Task 5: 清理与验证

**Files:**
- Remove: 所有失效空目录与 `.DS_Store`

- [ ] 删除空目录与遗留系统文件。
- [ ] 运行 `npm --prefix internal/server/web/admin ci`。
- [ ] 运行 `npm --prefix internal/server/web/admin run lint`。
- [ ] 运行 `npm --prefix internal/server/web/admin run build:admin`。
- [ ] 运行 `go test ./...`。
