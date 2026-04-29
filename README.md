<div align="center">
  <h1>CyberMonitor</h1>
  <p>A minimalist, elegant, and lightweight self-hosted server monitoring system.</p>

  <p><strong>English</strong> · <a href="./README_zh-CN.md">简体中文</a></p>

  <p>
    <a href="https://github.com/crazy0x70/CyberMonitor/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
    <img src="https://img.shields.io/badge/Go-1.25-blue" alt="Go Version">
    <img src="https://img.shields.io/badge/React-19-61dafb" alt="React">
  </p>
</div>

## 🚀 Getting Started

### 1. Quick Installation

To automatically configure the systemd service and interactively choose between installing the Server or Agent, run:

```bash
bash -c "$(curl -L https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh)" @ install
```

### 2. Deploying the Server via Docker

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

### 3. Deploying the Agent via Docker

```bash
docker run -d \
  --name cyber-monitor-agent \
  --network host \
  --restart always \
  --cap-add NET_RAW \
  -e CM_SERVER_URL="http://<server-ip>:25012" \
  -e CM_AGENT_TOKEN="<your-token>" \
  -e CM_NODE_ID="my-node-id" \
  -v /:/host:ro \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/crazy0x70/cyber-monitor-agent:latest
```

Configuration notes:
The `CM_SERVER_URL` serves as the unified entry point for the Agent. Upon startup, the Agent attempts to establish a gRPC control link. If your environment, such as a reverse proxy or CDN, only supports HTTP/1.1, the Agent will automatically fall back to HTTP. For persistent gRPC connectivity, ensure the Agent has a direct connection to the Server or use a proxy supporting HTTP/2 or h2c. If the server is configured to use a separate public port via `CM_PUBLIC_LISTEN`, please use that port instead of the management port.

To persist the node identity on the host, mount a local directory:

```bash
-v ./agent-home:/home/cm
```

This ensures the container's `~/.cybermonitor-node-id` is mapped to your host, allowing identification reuse upon container recreation.

For backward compatibility, the Agent continues to support legacy environment variables (`server-url`, `agent-token`, `node-id`), though the new `CM_*` prefixed variables are recommended. To disable remote updates initiated by the management panel, add:

```bash
-e CM_DISABLE_UPDATE=1
```

The node will continue to report monitoring data but will be flagged as update-disabled in the dashboard.

### 4. Installing the Agent

A default `Node ID` is generated and persisted during first-time installation. You may specify a custom ID to align with your existing asset management strategy.

Note: The installation process uses HTTP for the initial bootstrap handshake. Once running, the Agent favors gRPC but falls back to HTTP when necessary. When using an HTTPS address, maintaining HTTP/2 through your proxy is recommended for optimal performance.

**Linux / macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.sh -o /tmp/agent.sh && bash /tmp/agent.sh --server-url http://<server-ip>:25012 --agent-token <your-token>
```

**Windows**

```powershell
$script = Join-Path $env:TEMP 'agent.ps1'
Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.ps1' -OutFile $script
& $script -ServerUrl 'http://<server-ip>:25012' -AgentToken '<your-token>'
```

To provide custom parameters such as `--node-id` or `--disable-update`, append them to the command above as appropriate.

### 5. Uninstalling the Agent

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

The uninstallation script removes the agent binary, configuration files, and system service registrations.

## 📖 Deployment Architecture

CyberMonitor utilizes an Agent-collector and Server-aggregator architecture.

### 1. Unified Deployment

By default, port `25012` handles the public dashboard, administrative management, and Agent data reporting.

### 2. Separated Deployment

To isolate management access from public status pages, use the `CM_PUBLIC_LISTEN` environment variable. You can deploy the frontend as a static site (e.g., via Cloudflare Pages) by providing a `config.json` that points to your backend:

```json
{
  "socket": "wss://api.example.com:25013/ws",
  "apiURL": "https://api.example.com:25013"
}
```

<div align="center">
  If you find CyberMonitor useful, please consider giving us a ⭐️ Star!
</div>
