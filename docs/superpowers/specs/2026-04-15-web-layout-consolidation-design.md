# Web Layout Consolidation Design

**目标**

将 `internal/server/web/admin`、`internal/server/web/admin-app`、`internal/server/web/admin-assets`、`internal/server/web/legacy` 收敛为单一前端目录体系，保留唯一的公开页目录与唯一的管理端源码／产物目录，删除冗余兼容层。

**背景**

当前仓库前端相关文件分散在两套顶层目录和多套运行时产物目录中。`Dockerfile`、`GitHub Actions`、`go:embed`、服务端路由和 UI 测试都依赖这些历史路径，导致每次前端改动都需要同步处理多套目录与兼容逻辑。

**设计原则**

1. 单一事实来源：管理端源码只保留一份，构建产物只保留一份。
2. 直接路径：服务端只读取当前正式目录，不保留过渡性分支。
3. 运行时最小化：删除 `legacy` 管理页和旧产物路由。

**目标目录**

- `internal/server/web/admin/`：管理端源码。
- `internal/server/web/dist/admin/`：管理端构建产物。
- `internal/server/web/public/`：公开监控页静态文件。

**服务端行为**

- `go:embed` 仅嵌入 `web/public/*` 与 `web/dist/admin/*`。
- 管理端 HTML 从 `web/dist/admin/index.html` 提供。
- 管理端静态资源从单一路径提供，不再保留 `/legacy`、`/admin-assets/`、`/admin-app/` 兼容输出。

**构建行为**

- `Dockerfile` 与 `GitHub Actions` 统一从 `internal/server/web/admin/` 构建。
- 构建产物输出到 `internal/server/web/dist/admin/`。
- 不再额外同步到历史目录。

**测试与文档**

- 更新 `internal/server/ui_guidelines_test.go`、`internal/server/server_admin_routes_test.go` 等所有前端路径断言。
- 更新 `README.md`、`.github/workflows/README.md` 与构建说明。

**非目标**

- 不重写公开监控页实现。
- 不引入新的前端工具链。
- 不保留为历史结构服务的双写、双读或回退逻辑。
