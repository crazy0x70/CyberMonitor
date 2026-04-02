<div align="center">
  <h1>CyberMonitor</h1>
  <p>极简、美观、轻量级的自托管服务器探针与监控系统</p>

  <p>
    <a href="https://github.com/crazy0x70/CyberMonitor/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
    <img src="https://img.shields.io/badge/Go-1.24-blue" alt="Go Version">
    <img src="https://img.shields.io/badge/React-19-61dafb" alt="React">
  </p>
</div>

## ✨ 核心特性

- **极简资源占用**：采用 Go 单文件二进制与 Docker 部署，无微服务包袱。
- **全方位指标**：实时监控 CPU、内存、磁盘、网速，以及 TCP/ICMP 连通性。
- **灵活部署**：支持前后端一体化部署，也可将展示页完全静态化部署至 Cloudflare Pages 等 CDN 节点（硬隔离）。
- **AI 智能运维**：集成 OpenAI / Gemini 等大模型 API，一键获取故障排查建议。
- **多渠道告警**：内置 Telegram Bot 与飞书 Webhook，按节点精细化配置离线规则。

## 🚀 快速上手

### 1. 一键安装 (推荐)
自动配置 systemd 服务（按提示可选择安装主控 Server 或探针 Agent）：
```bash
bash -c "$(curl -L https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/one-click.sh)" @ install
```

### 2. Docker 部署主控
```bash
mkdir -p ./data
docker run -d -p 25012:25012 -e CM_DATA_DIR=/data -v "$(pwd)/data:/data" --name cyber-monitor-server --restart=always ghcr.io/crazy0x70/cyber-monitor-server:latest
```
*(部署后，通过 `docker logs cyber-monitor-server` 获取初始后台路径与 Agent Token)*

### 3. Docker 部署探针 (Agent)
```bash
docker run -d \
  --name cyber-monitor-agent \
  --network host \
  --restart always \
  --cap-add NET_RAW \
  -e CM_SERVER_URL="http://<主控IP>:25012" \
  -e CM_AGENT_TOKEN="<你的Token>" \
  -v /:/host:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  ghcr.io/crazy0x70/cyber-monitor-agent:latest
```

如果该 Agent 需要拒绝后台下发的远程更新任务，可额外追加：

```bash
-e CM_DISABLE_UPDATE=1
```

这会让节点继续正常上报监控数据，但后台会把它识别为“已禁用远程更新”的节点。

### 4. 安装探针 (Agent)
`Node ID` 现在默认会在首次安装时随机生成，并持久化到本地；如果你希望和现有资产命名、自动化编排或迁移策略对齐，也可以在安装时显式指定。

**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.sh -o /tmp/agent.sh && bash /tmp/agent.sh --server-url http://<主控IP>:25012 --agent-token <你的Token>
```
**Windows**
```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.ps1 -OutFile ($env:TEMP + '\agent.ps1'); & ($env:TEMP + '\agent.ps1') -ServerUrl 'http://<主控IP>:25012' -AgentToken '<你的Token>'"
```

如果需要手动指定 `Node ID`：

**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.sh -o /tmp/agent.sh && bash /tmp/agent.sh --server-url http://<主控IP>:25012 --agent-token <你的Token> --node-id my-node-id
```

**Windows**
```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.ps1 -OutFile ($env:TEMP + '\agent.ps1'); & ($env:TEMP + '\agent.ps1') -ServerUrl 'http://<主控IP>:25012' -AgentToken '<你的Token>' -NodeId 'my-node-id'"
```

如果你希望该节点拒绝服务端下发的远程更新，可以在部署时显式追加 `disable-update`：

**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.sh -o /tmp/agent.sh && bash /tmp/agent.sh --server-url http://<主控IP>:25012 --agent-token <你的Token> --disable-update
```

**Windows**
```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.ps1 -OutFile ($env:TEMP + '\agent.ps1'); & ($env:TEMP + '\agent.ps1') -ServerUrl 'http://<主控IP>:25012' -AgentToken '<你的Token>' -DisableUpdate"
```

手工运行二进制时，也可以使用：

```bash
./cyber-monitor-agent --server-url http://<主控IP>:25012 --agent-token <你的Token> --disable-update
```

或环境变量：

```bash
CM_DISABLE_UPDATE=1 ./cyber-monitor-agent --server-url http://<主控IP>:25012 --agent-token <你的Token>
```

注意：Docker 部署的 Agent 同样不适合容器内自更新。正确方式是拉取新镜像并重建容器；如果你还希望该容器明确拒绝服务端更新任务，可同时追加 `--disable-update` 或设置 `CM_DISABLE_UPDATE=1`。

### 5. 卸载探针 (Agent)
**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent-uninstall.sh -o /tmp/agent-uninstall.sh && sudo bash /tmp/agent-uninstall.sh
```

**Windows**
```powershell
powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent-uninstall.ps1 -OutFile ($env:TEMP + '\agent-uninstall.ps1'); & ($env:TEMP + '\agent-uninstall.ps1')"
```

Unix 卸载脚本会清理以下内容：
- `cyber-monitor-agent` 服务
- `INSTALL_DIR` 默认路径 `/opt/CyberMonitor` 下的 Agent 二进制
- `CONF_DIR` 默认路径 `/etc/cybermonitor/agent.conf`

其中 Linux 会移除 `systemd` 服务文件；macOS 会尝试移除常见的 `launchd plist` 安装项。

## 📖 灵活部署与架构拓扑

CyberMonitor 采用 `Agent 采集 -> Server 聚合 -> HTTP + WebSocket 展示` 的标准架构，支持两种典型部署模式：

### 1. 直接部署（一体化架构）
默认 `:25012` 端口同时负责前台展示、后台管理与 Agent 上报，配置最简单，适合绝大多数自托管场景。

![直接部署](images/architecture-direct.svg)

### 2. 前后端分离部署（硬隔离架构）
如果你希望将前台状态页完全公开，但不暴露管理后台，可以使用 `CM_PUBLIC_LISTEN` 环境变量（例如设为 `25013`）分离展示接口与管理端口。

同时，你可以提取前端静态文件（位于 `internal/server/web/` 下），将其纯静态化托管至 Cloudflare Pages / Vercel 等 CDN 服务，隐藏真实后端 IP。

![分离部署](images/architecture-separated.svg)

**CDN 节点静态配置示例 (`config.json`)**
部署到静态托管服务时，只需在静态文件根目录新建一个 `config.json` 指定后端接口：
```json
{
  "socket": "wss://api.example.com:25013/ws",
  "apiURL": "https://api.example.com:25013"
}
```


## 💻 本地源码开发

由于项目包含 React 管理界面，在编译 Go 后端之前需要先构建前端产物：
```bash
npm --prefix admin-ui ci
./scripts/build-admin.sh
go build ./cmd/server
```

---

<div align="center">
  如果 CyberMonitor 对你有帮助，欢迎点亮 ⭐️ <b>Star</b> 予以支持！
</div>
