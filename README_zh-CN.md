<div align="center">
  <h1>CyberMonitor</h1>
  <p>一个极简、优雅且轻量级的自托管服务器监控系统。</p>

  <p>
    <a href="https://github.com/crazy0x70/CyberMonitor/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
    <img src="https://img.shields.io/badge/Go-1.26.2-blue" alt="Go Version">
    <img src="https://img.shields.io/badge/React-19-61dafb" alt="React">
  </p>
</div>

## 🚀 快速上手

### 1. 快速安装

如需自动配置 systemd 服务或交互式选择安装类型（Server 或 Agent），请执行：

```bash
tmp="$(mktemp -d)"
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/install-common.sh -o "$tmp/install-common.sh"
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o "$tmp/one-click.sh"
sudo bash "$tmp/one-click.sh" install
rm -rf "$tmp"
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
mkdir -p ./agent-state
docker run -d \
  --name cyber-monitor-agent \
  --network host \
  --restart always \
  --cap-add NET_RAW \
  -e CM_SERVER_URL="http://<主控IP>:25012" \
  -e CM_AGENT_TOKEN="<你的Token>" \
  -e CM_NODE_ID_FILE="/state/.cybermonitor-node-id" \
  -e CM_AGENT_TOKEN_FILE="/state/.cybermonitor-agent-token" \
  -e CM_INTERVAL="5s" \
  -e CM_DISABLE_UPDATE="1" \
  -v "$(pwd)/agent-state:/state" \
  -v /:/host:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  ghcr.io/crazy0x70/cyber-monitor-agent:latest
```

**配置说明**：`CM_SERVER_URL` 是探针的统一接入地址。Agent 启动后会优先尝试建立 `gRPC` 控制链路；若环境（如反向代理或 CDN）仅支持 `HTTP/1.1`，Agent 会自动回退至 `HTTP` 模式。若需长期保持 `gRPC` 模式，请确保 Agent 直连 Server 或使用支持 `HTTP/2` / `h2c` 的代理。此外，若服务端启用了 `CM_PUBLIC_LISTEN` 分离接口，请务必填写该公网端口。

Docker 部署应持久化 `/state`。`CM_NODE_ID_FILE` 保存节点身份，`CM_AGENT_TOKEN_FILE` 保存注册后的专属凭据。不要在多台服务器上复用同一个 `CM_NODE_ID`。

HTTPS 地址未显式写端口时，Agent 的 gRPC 连接会使用 `443`；HTTP 地址会使用 `80`。反向代理 gRPC 时不要改写为 `/grpc/`，应转发真实服务前缀：

```nginx
location /cyber_monitor.agentrpc.AgentService/ {
    grpc_pass grpc://127.0.0.1:25013;
}
```

如果节点到 CDN 的 IPv6 路由异常，HTTP/gRPC 都可能超时。此时应优先修复宿主机 IPv6；临时方案是在 `docker run` 中添加 `--add-host <域名>:<可用IPv4>`，让该节点固定走 IPv4。

上面的默认命令已禁用后台远程更新。若确实需要后台一键更新 Docker Agent，请同时设置 `CM_DISABLE_UPDATE=0`、`CM_ENABLE_DOCKER_UPDATE=1`，并挂载 `/var/run/docker.sock`。

### 4. 安装探针 (Agent)

初次安装时，系统会自动生成并持久化 `Node ID`。如需统一资产管理，也可在安装时手动指定。探针的握手过程使用 `HTTP` 完成，随后运行态优先尝试 `gRPC`。

**Linux（systemd）**

```bash
tmp="$(mktemp -d)"
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/install-common.sh -o "$tmp/install-common.sh"
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.sh -o "$tmp/agent.sh"
sudo bash "$tmp/agent.sh" --server-url http://<主控IP>:25012 --agent-token <你的Token>
rm -rf "$tmp"
```

**Windows**

```powershell
$script = Join-Path $env:TEMP 'agent.ps1'
Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.ps1' -OutFile $script
& $script -ServerUrl 'http://<主控IP>:25012' -AgentToken '<你的Token>'
```

Linux 自定义参数使用 `--node-id`、`--disable-update` 等 shell 参数。Windows 自定义参数使用 `-NodeId`、`-DisableUpdate` 等 PowerShell 参数。

### 5. 卸载探针 (Agent)

**Linux（systemd）**

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
