# CyberMonitor

Lightweight, self-hosted server monitoring. One server binary with the status page and admin console built in, plus a small agent on each machine you want to watch. No database to set up — everything lives in one data directory.

English · [简体中文](./README_zh-CN.md)

## Features

- **Live status page** — online state, CPU, memory, disk, GPU and network for every node, updated every second, plus TCP/ICMP latency and packet loss charts (1 hour / 1 day / 1 week). Light and dark themes, English and Chinese.
- **AI operations assistant** — ask questions about your fleet in natural language; the snapshot it reasons over includes CPU, memory and network history summaries over the last hour, day and week.
- **Admin console** — group and tag nodes, track expiry dates, set monthly traffic quotas, and choose which probes each node runs.
- **Alerts** — rules on CPU, memory, disk, GPU, bandwidth, connections, probe latency/loss, expiry and traffic quota, plus node offline. Notifications go to Telegram, Feishu, DingTalk, WeCom, Slack, Bark or email, with recovery notices.
- **One-click updates** — update the server and every agent from the admin console.
- **Small footprint** — the server idles at about 35 MB of memory; agents read system counters directly and send one small report per second.
- **Secure sign-in** — random admin path, GitHub / OIDC login, Cloudflare Turnstile and brute-force lockout.

Runs on Linux (amd64, arm64, armv7), macOS (Intel, Apple silicon) and Windows (x64; agent also on ARM64). FreeBSD binaries are available on the [Releases](https://github.com/crazy0x70/CyberMonitor/releases) page.

## Quick start

### 1. Install the server

**Linux / macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o one-click.sh
sudo bash one-click.sh install-server
```

When it finishes, the script prints the status page URL, the admin console URL, the username and a one-time password. Sign in and change the password.

The server listens on port `25012` by default. Use `--listen :8080` to change the port and `--data-dir /path` to change where data is stored. On macOS, running without `sudo` installs for the current user only.

**Windows** (PowerShell as Administrator)

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.ps1 -OutFile one-click.ps1
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 install-server
```

**Docker**

```bash
docker run -d --name cyber-monitor-server --restart=always \
  -p 25012:25012 -v "$PWD/data:/data" \
  ghcr.io/crazy0x70/cyber-monitor-server:latest
docker logs cyber-monitor-server                        # username and password (printed once)
sudo grep -o '"admin_path": *"[^"]*"' data/state.json    # admin console path
```

A Compose file is available in [server-example.yml](./server-example.yml).

### 2. Add machines

In the admin console, open **Nodes**. The **Quick Agent onboarding** panel shows a command with your server address and token already filled in. Run it on each machine you want to monitor. Once you have nodes the panel collapses to a **Connect new node** button; on a fresh install with no nodes it stays expanded:

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o one-click.sh
sudo bash one-click.sh install-agent --server-url http://YOUR_SERVER:25012 --agent-token YOUR_TOKEN
```

```powershell
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 install-agent -ServerUrl http://YOUR_SERVER:25012 -AgentToken YOUR_TOKEN
```

Docker (Linux hosts):

```bash
docker run -d --name cyber-monitor-agent --restart=always \
  --net=host --pid=host -v /:/host:ro \
  -e CM_SERVER_URL=http://YOUR_SERVER:25012 -e CM_AGENT_TOKEN=YOUR_TOKEN \
  ghcr.io/crazy0x70/cyber-monitor-agent:latest
```

The node shows up on the status page within a few seconds. A Compose file is available in [agent-example.yml](./agent-example.yml). The install script needs root on Linux, so drop `sudo` only if you are already running as root.

## Upgrade

**From the admin console (recommended).** **Settings → System info** shows when a new version is available and updates the server in one click. On the **Nodes** page, **Update all** updates every agent. This works for Linux and macOS installs, and for Docker when the container has access to the Docker socket (see [server-example.yml](./server-example.yml)). Windows does not support in-place updates; use the script.

**With the script** (keeps your configuration and data):

```bash
sudo bash one-click.sh upgrade-server            # or: upgrade-agent
sudo bash one-click.sh upgrade-server --version v1.2.3
```

```powershell
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 upgrade-server   # or: upgrade-agent
```

**Docker:** pull the new image and recreate the container with the same volume and environment:

```bash
docker pull ghcr.io/crazy0x70/cyber-monitor-server:latest
docker rm -f cyber-monitor-server
# then run the same `docker run` command as before
```

## Uninstall

```bash
sudo bash one-click.sh uninstall-agent
sudo bash one-click.sh uninstall-server              # deletes the data directory
sudo bash one-click.sh uninstall-server --keep-data  # keeps it
```

```powershell
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 uninstall-agent
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 uninstall-server -KeepData
```

Running `one-click.sh` or `one-click.ps1` with no arguments opens an interactive menu with the same options.

## Where things are

| | Linux / macOS (sudo) | macOS (current user) | Windows |
|---|---|---|---|
| Programs | `/opt/CyberMonitor/` | `~/CyberMonitor/` | `C:\ProgramData\CyberMonitor\` |
| Data | `/opt/CyberMonitor/data/` | `~/CyberMonitor/data/` | `C:\ProgramData\CyberMonitor\data\` |
| Service config | `/etc/cybermonitor/*.conf` | `~/CyberMonitor/etc/*.conf` | Windows service settings |
| Server log | `data/server.log`, also shown on the admin console's **Logs** page | same | same |

To back up, copy the data directory. It contains settings, nodes and history. History is split by kind: `data/history/network/` (probe latency and loss), `data/history/offline/` (offline events) and `data/history/resource/` (CPU, memory and network, recorded for the AI operations assistant). Resource history retention is chosen under **Settings → System → Resource history retention** (1 / 7 / 30 days) and applies immediately.

## Configuration

The server reads these flags or environment variables. When installed with the script, edit `/etc/cybermonitor/server.conf` and restart the service.

| Flag | Environment | Default | Description |
|---|---|---|---|
| `-listen` | `CM_LISTEN` | `:25012` | Address for the status page, admin console and agents |
| `-data-dir` | `CM_DATA_DIR` | `./data` | Data directory |
| `-public-listen` | `CM_PUBLIC_LISTEN` | — | Serve the status page and agents on a separate port, so the admin console can stay private |
| `-trust-proxy-headers` | `CM_TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-*` from your reverse proxy (needed for correct client IPs) |
| `-admin-path` | `CM_ADMIN_PATH` | random | Admin console path |

Agent options: `-server-url` / `CM_SERVER_URL`, `-agent-token` / `CM_AGENT_TOKEN`, `-net-iface` / `CM_NET_IFACE` (only count these network interfaces) and `-disable-update` / `CM_DISABLE_UPDATE` (ignore update requests from the server). Run either binary with `-h` for the full list.

## Reverse proxy

Agents connect over gRPC and fall back to plain HTTP when the proxy can't carry it. Everything is on one port. An nginx example with HTTPS:

```nginx
server {
    listen 443 ssl http2;
    server_name monitor.example.com;
    # ssl_certificate ...;

    location /cyber_monitor.agentrpc.AgentService/ {
        grpc_pass grpc://127.0.0.1:25012;
    }
    location / {
        proxy_pass http://127.0.0.1:25012;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Start the server with `CM_TRUST_PROXY_HEADERS=true` and give agents `--server-url https://monitor.example.com`.

## FAQ

**I lost the admin password.** Stop the server, reset it, and start it again:

```bash
sudo systemctl stop cyber-monitor-server
sudo /opt/CyberMonitor/cyber-monitor-server -reset-password -data-dir /opt/CyberMonitor/data
sudo systemctl start cyber-monitor-server
```

The new password and the admin path are printed.

**ICMP probes show no data.** ICMP needs raw sockets: run the agent as root (the script does this), or give it `CAP_NET_RAW`. TCP probes need no extra permission.

**A node in Docker shows up as new after recreating the container.** Mount the host root (`-v /:/host:ro`) so the agent derives a stable node ID from the host, or set `CM_NODE_ID`.

**An agent can't connect over IPv6 to a CDN.** Fix the host's IPv6 route, or pin the server name to IPv4 with `--add-host monitor.example.com:<ipv4>` (Docker) or `/etc/hosts`.

**The status page on a static host.** Upload `internal/server/web/public/` to any static host and set `<meta name="cm-api-base">` in `index.html` to your server URL.

**A notification fails with `目标 … 是内网/保留地址，已被安全策略拒绝` ("target is a private or reserved address, rejected by the security policy").** The server refuses notification targets that resolve to private or reserved addresses. The usual causes are a fake-ip proxy on the server machine (Clash, Surge, OpenClash and similar resolve public domains to `198.18.0.0/15`) and a target that really is an internal service (self-hosted Bark, self-hosted Telegram Bot API, internal SMTP). Turn on **Allow private network addresses** in that channel's settings under **Alerts → Channels**; the switch exists for every channel type, email included.

**How is a rule's duration judged?** The duration is a window statistic, not "continuously over the threshold". A rule fires when the metric stays over the threshold for more than about 70% of the window, and recovers once that share drops below about 30%. The gap in between is a hysteresis band: the rule keeps its current state, so a value hovering around the threshold no longer sends alert/recovery pairs. **Immediately** judges every single sample.

**Moving to a new server.** Copying the data directory is still the recommended way (see [Where things are](#where-things-are)). If you use **Settings → System info → Configuration backup → Export configuration** instead, note that the exported file contains no secrets: webhook URLs, bot tokens, email passwords, chat IDs and recipient lists are cleared. After importing it on the new server, re-enter those values under **Alerts → Channels**; channels that are still missing required fields are marked **Missing required fields** and cannot send alerts.

**The install command says `localhost` or `127.0.0.1`.** When no Agent endpoint is configured, the command uses the address you are currently using to reach the admin console; that address is only used to build the command and is never saved. If agents cannot reach it (you open the console through a reverse proxy or from the machine itself, or the agent-facing address differs), fill in **Agent endpoint** under **Settings → Agent onboarding**. With a separate public port (`-public-listen`) the suggestion uses the status page port.

## Build from source

Requires Go (version in `go.mod`) and Node.js (version in the `Dockerfile`). The admin console is embedded into the server binary, so build it first:

```bash
npm --prefix internal/server/web/admin ci
npm --prefix internal/server/web/admin run build:admin
go build -o dist/cyber-monitor-server ./cmd/server
go build -o dist/cyber-monitor-agent ./cmd/agent
```

For admin console development, `npm --prefix internal/server/web/admin run dev` starts a dev server on port 3000.

## License

[MIT](./LICENSE)
