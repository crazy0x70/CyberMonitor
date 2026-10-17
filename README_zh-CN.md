# CyberMonitor

轻量的自托管服务器监控。一个服务端程序，内置状态页和管理后台；在每台要监控的机器上装一个小巧的 Agent。不需要安装数据库，所有数据都在一个目录里。

[English](./README.md) · 简体中文

## 功能

- **实时状态页**：每秒刷新每台节点的在线状态、CPU、内存、磁盘、GPU 和网络，并提供 TCP / ICMP 延迟与丢包曲线（1 小时 / 1 天 / 1 周）。支持深浅色主题和中英文。
- **管理后台**：节点分组和标签、到期时间、每月流量配额，以及按节点选择要执行的探测。
- **告警**：可对 CPU、内存、磁盘、GPU、带宽、连接数、探测延迟 / 丢包、到期和流量配额设置规则，另有节点离线告警。通过 Telegram、飞书、钉钉、企业微信、Slack、Bark 或邮件通知，恢复时也会提醒。
- **一键更新**：在管理后台更新服务端和全部 Agent。
- **占用小**：服务端空闲时内存约 35 MB；Agent 直接读取系统计数器，每秒上报一次。
- **安全登录**：随机后台路径、GitHub / OIDC 登录、Cloudflare Turnstile 人机验证和防暴力破解。

支持 Linux（amd64、arm64、armv7）、macOS（Intel、Apple 芯片）和 Windows（x64；Agent 另支持 ARM64）。FreeBSD 版本可在 [Releases](https://github.com/crazy0x70/CyberMonitor/releases) 页面下载。

## 快速开始

### 1. 安装服务端

**Linux / macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o one-click.sh
sudo bash one-click.sh install-server
```

安装完成后，脚本会显示状态页地址、管理后台地址、用户名和一次性密码。请登录后修改密码。

服务端默认监听 `25012` 端口。用 `--listen :8080` 改端口，用 `--data-dir /path` 改数据目录。macOS 上不加 `sudo` 则只为当前用户安装。

**Windows**（以管理员身份运行 PowerShell）

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.ps1 -OutFile one-click.ps1
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 install-server
```

**Docker**

```bash
docker run -d --name cyber-monitor-server --restart=always \
  -p 25012:25012 -v "$PWD/data:/data" \
  ghcr.io/crazy0x70/cyber-monitor-server:latest
docker logs cyber-monitor-server                        # 用户名和密码（只打印一次）
sudo grep -o '"admin_path": *"[^"]*"' data/state.json    # 管理后台路径
```

Compose 示例见 [server-example.yml](./server-example.yml)。

### 2. 添加机器

在管理后台打开 **节点管理**，**Agent 快速接入** 面板里有已经填好服务端地址和 Token 的命令，在每台要监控的机器上运行即可：

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o one-click.sh
sudo bash one-click.sh install-agent --server-url http://你的服务器:25012 --agent-token 你的TOKEN
```

```powershell
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 install-agent -ServerUrl http://你的服务器:25012 -AgentToken 你的TOKEN
```

Docker（Linux 主机）：

```bash
docker run -d --name cyber-monitor-agent --restart=always \
  --net=host --pid=host -v /:/host:ro \
  -e CM_SERVER_URL=http://你的服务器:25012 -e CM_AGENT_TOKEN=你的TOKEN \
  ghcr.io/crazy0x70/cyber-monitor-agent:latest
```

几秒后节点就会出现在状态页上。Compose 示例见 [agent-example.yml](./agent-example.yml)。

## 升级

**在管理后台升级（推荐）。** **基础设置 → 系统信息** 会提示新版本，一键更新服务端；**节点管理** 页的 **全部更新** 会更新所有 Agent。适用于 Linux、macOS 安装，以及能访问 Docker socket 的 Docker 部署（见 [server-example.yml](./server-example.yml)）。Windows 不支持在线更新，请用脚本升级。

**用脚本升级**（保留配置和数据）：

```bash
sudo bash one-click.sh upgrade-server            # 或 upgrade-agent
sudo bash one-click.sh upgrade-server --version v1.2.3
```

```powershell
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 upgrade-server   # 或 upgrade-agent
```

**Docker**：拉取新镜像，用原来的数据卷和环境变量重建容器：

```bash
docker pull ghcr.io/crazy0x70/cyber-monitor-server:latest
docker rm -f cyber-monitor-server
# 然后重新执行之前的 docker run 命令
```

## 卸载

```bash
sudo bash one-click.sh uninstall-agent
sudo bash one-click.sh uninstall-server              # 删除数据目录
sudo bash one-click.sh uninstall-server --keep-data  # 保留数据目录
```

```powershell
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 uninstall-agent
powershell -ExecutionPolicy Bypass -File .\one-click.ps1 uninstall-server -KeepData
```

不带参数运行 `one-click.sh` 或 `one-click.ps1` 会打开交互菜单，包含以上所有操作。

## 文件位置

| | Linux / macOS（sudo） | macOS（当前用户） | Windows |
|---|---|---|---|
| 程序 | `/opt/CyberMonitor/` | `~/CyberMonitor/` | `C:\ProgramData\CyberMonitor\` |
| 数据 | `/opt/CyberMonitor/data/` | `~/CyberMonitor/data/` | `C:\ProgramData\CyberMonitor\data\` |
| 服务配置 | `/etc/cybermonitor/*.conf` | `~/CyberMonitor/etc/*.conf` | Windows 服务设置 |
| 服务端日志 | `data/server.log`，也可在管理后台 **日志查看** 页查看 | 同左 | 同左 |

备份时复制数据目录即可，里面包含设置、节点和历史数据。

## 配置

服务端支持以下参数或环境变量。用脚本安装时，修改 `/etc/cybermonitor/server.conf` 后重启服务即可。

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `-listen` | `CM_LISTEN` | `:25012` | 状态页、管理后台和 Agent 接入的监听地址 |
| `-data-dir` | `CM_DATA_DIR` | `./data` | 数据目录 |
| `-public-listen` | `CM_PUBLIC_LISTEN` | — | 状态页和 Agent 接入改用单独端口，管理后台可以只在内网开放 |
| `-trust-proxy-headers` | `CM_TRUST_PROXY_HEADERS` | `false` | 信任反向代理传来的 `X-Forwarded-*`（获取真实客户端 IP 需要开启） |
| `-admin-path` | `CM_ADMIN_PATH` | 随机 | 管理后台路径 |

Agent 常用参数：`-server-url` / `CM_SERVER_URL`、`-agent-token` / `CM_AGENT_TOKEN`、`-net-iface` / `CM_NET_IFACE`（只统计指定网卡）、`-disable-update` / `CM_DISABLE_UPDATE`（忽略服务端下发的更新）。完整列表用 `-h` 查看。

## 反向代理

Agent 优先用 gRPC 连接，代理不支持时会自动改用普通 HTTP，所有流量都在同一个端口。nginx + HTTPS 示例：

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

服务端加上 `CM_TRUST_PROXY_HEADERS=true`，Agent 的 `--server-url` 填 `https://monitor.example.com`。

## 常见问题

**忘记管理员密码。** 停止服务端，重置后再启动：

```bash
sudo systemctl stop cyber-monitor-server
sudo /opt/CyberMonitor/cyber-monitor-server -reset-password -data-dir /opt/CyberMonitor/data
sudo systemctl start cyber-monitor-server
```

会打印新密码和管理后台路径。

**ICMP 探测没有数据。** ICMP 需要 raw socket：以 root 运行 Agent（脚本默认如此），或授予 `CAP_NET_RAW`。TCP 探测不需要额外权限。

**Docker 里的 Agent 重建容器后变成了新节点。** 挂载宿主机根目录（`-v /:/host:ro`），Agent 会据此生成固定的节点 ID；或者设置 `CM_NODE_ID`。

**Agent 通过 IPv6 连不上 CDN。** 修复主机的 IPv6 路由，或把服务端域名固定到 IPv4：Docker 用 `--add-host monitor.example.com:<IPv4>`，其他情况写入 `/etc/hosts`。

**把状态页放到静态托管。** 把 `internal/server/web/public/` 上传到任意静态托管，并把 `index.html` 里的 `<meta name="cm-api-base">` 改成服务端地址。

## 从源码构建

需要 Go（版本见 `go.mod`）和 Node.js（版本见 `Dockerfile`）。管理后台会嵌入服务端程序，所以要先构建它：

```bash
npm --prefix internal/server/web/admin ci
npm --prefix internal/server/web/admin run build:admin
go build -o dist/cyber-monitor-server ./cmd/server
go build -o dist/cyber-monitor-agent ./cmd/agent
```

开发管理后台时，`npm --prefix internal/server/web/admin run dev` 会在 3000 端口启动开发服务器。

## 许可证

[MIT](./LICENSE)
