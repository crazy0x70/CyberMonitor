<div align="center">
  <h1>CyberMonitor</h1>
  <p>A minimalist, elegant, and lightweight self-hosted server monitoring system.</p>

  <p><strong>English</strong> · <a href="./README_zh-CN.md">简体中文</a></p>

  <p>
    <a href="https://github.com/crazy0x70/CyberMonitor/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
    <img src="https://img.shields.io/badge/Go-1.27.1-blue" alt="Go Version">
    <img src="https://img.shields.io/badge/React-19-61dafb" alt="React">
  </p>
</div>

## 🚀 Getting Started

### 1. Quick Installation

To automatically configure the systemd service and interactively choose between installing the Server or Agent, run:

```bash
tmp="$(mktemp -d)"
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/install-common.sh -o "$tmp/install-common.sh"
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o "$tmp/one-click.sh"
sudo bash "$tmp/one-click.sh" install
rm -rf "$tmp"
```

### 2. Deploying the Server via Docker

```bash
mkdir -p ./data
docker run -d \
  -p 25012:25012 \
  -e CM_DATA_DIR=/data \
  -v "$(pwd)/data:/data" \
  --name cyber-monitor-server \
  --restart=always \
  ghcr.io/crazy0x70/cyber-monitor-server:latest
```

The default Server command does not mount the Docker socket. To enable one-click updates for Docker Server deployments from the management panel, set `CM_ENABLE_DOCKER_UPDATE=1` and mount `/var/run/docker.sock`; otherwise, pull the latest image and recreate the container manually.

### 3. Deploying the Agent via Docker

```bash
mkdir -p ./agent-state
docker run -d \
  --name cyber-monitor-agent \
  --network host \
  --restart always \
  --cap-add NET_RAW \
  -e CM_SERVER_URL="http://<server-ip>:25012" \
  -e CM_AGENT_TOKEN="<your-token>" \
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

Configuration notes:
The `CM_SERVER_URL` serves as the unified entry point for the Agent. Upon startup, the Agent attempts to establish a gRPC control link. If your environment, such as a reverse proxy or CDN, only supports HTTP/1.1, the Agent will automatically fall back to HTTP. For persistent gRPC connectivity, ensure the Agent has a direct connection to the Server or use a proxy supporting HTTP/2 or h2c. If the server is configured to use a separate public port via `CM_PUBLIC_LISTEN`, please use that port instead of the management port.

Docker deployments should persist `/state`. `CM_NODE_ID_FILE` stores the node identity, and `CM_AGENT_TOKEN_FILE` stores the dedicated token returned after registration. Do not reuse the same `CM_NODE_ID` across multiple servers.

When an HTTPS URL omits the port, the Agent uses `443` for gRPC. When an HTTP URL omits the port, it uses `80`. If you proxy gRPC, do not rewrite it to `/grpc/`; forward the real service prefix:

```nginx
location /cyber_monitor.agentrpc.AgentService/ {
    grpc_pass grpc://127.0.0.1:25013;
}
```

If a node has broken IPv6 routing to a CDN, both HTTP and gRPC can time out. Prefer fixing host IPv6 routing. As a temporary workaround, add `--add-host <domain>:<working-ipv4>` to `docker run` so that node uses IPv4 for the Agent endpoint.

The default command above disables remote updates initiated by the management panel. To enable one-click updates for Docker Agent deployments, set both `CM_DISABLE_UPDATE=0` and `CM_ENABLE_DOCKER_UPDATE=1`, then mount `/var/run/docker.sock`.

### 4. Installing the Agent

A default `Node ID` is generated and persisted during first-time installation. You may specify a custom ID to align with your existing asset management strategy.

Note: The installation process uses HTTP for the initial bootstrap handshake. Once running, the Agent favors gRPC but falls back to HTTP when necessary. When using an HTTPS address, maintaining HTTP/2 through your proxy is recommended for optimal performance.

**Linux (systemd)**

```bash
tmp="$(mktemp -d)"
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/install-common.sh -o "$tmp/install-common.sh"
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.sh -o "$tmp/agent.sh"
sudo bash "$tmp/agent.sh" --server-url http://<server-ip>:25012 --agent-token <your-token>
rm -rf "$tmp"
```

**Windows**

```powershell
$script = Join-Path $env:TEMP 'agent.ps1'
Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.ps1' -OutFile $script
& $script -ServerUrl 'http://<server-ip>:25012' -AgentToken '<your-token>'
```

Linux custom parameters use shell flags such as `--node-id` and `--disable-update`. Windows custom parameters use PowerShell flags such as `-NodeId` and `-DisableUpdate`.

### 5. Uninstalling the Agent

**Linux (systemd)**

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent-uninstall.sh -o /tmp/agent-uninstall.sh && sudo bash /tmp/agent-uninstall.sh
```

**Windows**

```powershell
$script = Join-Path $env:TEMP 'agent-uninstall.ps1'
Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent-uninstall.ps1' -OutFile $script
& $script
```

The uninstallation script removes the agent binary, configuration files, and system service registrations.

## 📖 Deployment Architecture

CyberMonitor utilizes an Agent-collector and Server-aggregator architecture.

### 1. Unified Deployment

By default, port `25012` handles the public dashboard, administrative management, and Agent data reporting.

### 2. Separated Deployment

To isolate management access from public status pages, use the `CM_PUBLIC_LISTEN` environment variable. The public page always serves a single origin — it connects to the WebSocket and API endpoints of the host it is deployed on, so no extra `config.json` is required alongside the frontend.

### 3. Static Hosting

The public page can also be deployed to any static host (Cloudflare Pages / Netlify / any static space). Upload the `internal/server/web/public/` directory, then edit `<meta name="cm-api-base">` in `index.html` to point at your monitor server (e.g. `https://monitor.example.com`). The server must allow cross-origin access to the public API (recent versions ship with CORS built in).

<div align="center">
  If you find CyberMonitor useful, please consider giving us a ⭐️ Star!
</div>
