# CyberMonitor Admin UI

这个目录是 CyberMonitor 管理后台的 React 前端源码。

## 常用命令

1. 安装依赖
   `npm ci`
2. 本地开发
   `npm run dev`
3. 类型检查
   `npm run lint`
4. 构建并同步到 Go 服务静态目录
   `npm run build:admin`

## 目录职责

- `src/`：页面入口与管理后台页面
- `components/`：共享 UI 组件
- `lib/`：API、类型和共享样式 token
- `scripts/sync-admin.mjs`：将构建产物同步到 `internal/server/web/`
