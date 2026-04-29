<div align="center">
  <h1>CyberMonitor</h1>
  <p>一个极简、优雅且轻量级的自托管服务器监控系统。</p>

  <p>
    <a href="https://github.com/crazy0x70/CyberMonitor/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
    <img src="https://img.shields.io/badge/Go-1.25-blue" alt="Go Version">
    <img src="https://img.shields.io/badge/React-19-61dafb" alt="React">
  </p>
</div>

## 🚀 快速上手

### 1. 快速安装

如需自动配置 systemd 服务或交互式选择安装类型（Server 或 Agent），请执行：

```bash
bash -c "$(curl -L https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh)" @ install
```

### 2. Docker 部署主控 (Server)

```bash
mkdir -p ./data
docker run -d \
  -p 25012:25012 \
  -e CM_DATA_DIR=/data \
  -v "$(pwd)/data:/data" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --name cyber-monitor-server \
  --restart=always \
  ghcr.io/crazy0x70/cyber-monitor-server:latest
```

### 3. Docker 部署探针 (Agent)

```bash
docker run -d \
  --name cyber-monitor-agent \
  --network host \
  --restart always \
  --cap-add NET_RAW \
  -e CM_SERVER_URL="http://<主控IP>:25012" \
  -e CM_AGENT_TOKEN="<你的Token>" \
  -e CM_NODE_ID="my-node-id" \
  -v /:/host:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/crazy0x70/cyber-monitor-agent:latest
```

**配置说明**：`CM_SERVER_URL` 是探针的统一接入地址。Agent 启动后会优先尝试建立 `gRPC` 控制链路；若环境（如反向代理或 CDN）仅支持 `HTTP/1.1`，Agent 会自动回退至 `HTTP` 模式。若需长期保持 `gRPC` 模式，请确保 Agent 直连 Server 或使用支持 `HTTP/2` / `h2c` 的代理。此外，若服务端启用了 `CM_PUBLIC_LISTEN` 分离接口，请务必填写该公网端口。

若需在宿主机持久化节点身份，可挂载本地目录：

```bash
-v ./agent-home:/home/cm
```

此操作将容器内的 `~/.cybermonitor-node-id` 映射至宿主机，防止容器重建导致 ID 变化。

Agent 同时兼容历史版本环境变量（如 `server-url`、`agent-token`），但推荐优先使用 `CM_*` 前缀的新写法。若需禁止后台远程更新，请添加配置 `-e CM_DISABLE_UPDATE=1`，该节点将继续上报数据，但会在管理后台被标记为已禁用更新。

### 4. 安装探针 (Agent)

初次安装时，系统会自动生成并持久化 `Node ID`。如需统一资产管理，也可在安装时手动指定。探针的握手过程使用 `HTTP` 完成，随后运行态优先尝试 `gRPC`。

**Linux / macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.sh -o /tmp/agent.sh && bash /tmp/agent.sh --server-url http://<主控IP>:25012 --agent-token <你的Token>
```

**Windows**

```powershell
$script = Join-Path $env:TEMP 'agent.ps1'
Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.ps1' -OutFile $script
& $script -ServerUrl 'http://<主控IP>:25012' -AgentToken '<你的Token>'
```

如需传入 `--node-id` 或 `--disable-update` 等自定义参数，直接追加至上述命令结尾即可。

### 5. 卸载探针 (Agent)

**Linux / macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent-uninstall.sh -o /tmp/agent-uninstall.sh && sudo bash /tmp/agent-uninstall.sh
```

**Windows**

```powershell
$script = Join-Path $env:TEMP 'agent-uninstall.ps1'
Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent-uninstall.ps1' -OutFile $script
& $script
```

该操作将自动清理 Agent 二进制文件、配置文件及系统服务，恢复系统环境。

## 📖 架构说明

CyberMonitor 采用“探针采集 -> 服务端聚合”的架构模式，支持一体化部署与前后端分离部署。

### 混合模式与协议支持

- **一体化架构**：默认 `25012` 端口同时负载前台展示、管理后台及 Agent 上报。
- **前后端分离**：利用 `CM_PUBLIC_LISTEN` 环境变量（如 `25013`）可以将展示接口与管理端口隔离。你可以将前端静态部署于 Cloudflare Pages 等托管服务，并通过 `config.json` 指定 API 入口：

```json
{
  "socket": "wss://api.example.com:25013/ws",
  "apiURL": "https://api.example.com:25013"
}
```

<div align="center">
  如果 CyberMonitor 对你有帮助，欢迎点亮 ⭐️ <b>Star</b> 支持！
</div>
