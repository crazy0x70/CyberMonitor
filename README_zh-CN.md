# CyberMonitor

自托管的服务器监控。一个 32MB 的 Go 二进制把状态页和管理后台都嵌进去了，无需外置数据库——配置和节点状态落在数据目录的 JSON 文件里，连通性历史存在内嵌的时序存储里。Agent 装在被监控的机器上，每秒上报资源；Server 聚合后推给浏览器。

[English](./README.md) · 简体中文

## 你会得到什么

**状态页**（访客看的那个）：节点在线状态、CPU/内存/磁盘用量、上下行速率、每个节点的连通性曲线（TCP/ICMP 延迟 + 丢包率，1 小时/1 天/1 周三档）。深浅色主题，中英双语，可以换自定义背景图。

**管理后台**（路径随机生成，比如 `/uGXfuIMrjdzJ`）：九个页面——首页、节点管理、分组管理、探测设置、通知告警、基础设置、AI 服务商、日志。能做的事：

- 给节点分组打标签、标注到期时间和续费周期
- 配置探测目标（TCP 端口或 ICMP）下发到指定节点，或让 Agent 启动参数自带
- Telegram / 飞书告警，节点离线时推送
- 接入 OpenAI 或任何兼容端点做运维提示词
- GitHub OAuth / OIDC 登录、Cloudflare Turnstile 人机验证、防爆破（15 分钟内错 5 次密码锁 15 分钟）

## 装 Server

一条命令，Linux 走 systemd，macOS 走 launchd：

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o /tmp/one-click.sh
sudo bash /tmp/one-click.sh
```

装完监听 `:25012`，浏览器打开 `http://<ip>:25012` 是公开状态页。管理后台的入口路径、账号、密码都在首次启动时随机生成。一键脚本装的：密码由安装器生成并打印在**安装终端输出的末尾**（服务日志只显示「已设置（不回显）」）；手动二进制或 Docker 装的：账号和密码在**首次启动日志**里打印一次（systemd 服务名为 `cyber-monitor-server`，看 `journalctl -u cyber-monitor-server`）。入口路径存在数据目录 `state.json` 的 `settings.admin_path` 字段（一键安装默认数据目录 `/opt/CyberMonitor/data`）。登录后第一件事改密码。备份就是备份整个数据目录。

Docker 也行：

```bash
mkdir -p ./data
docker run -d -p 25012:25012 -e CM_DATA_DIR=/data -v "$(pwd)/data:/data" \
  --name cyber-monitor-server --restart=always \
  ghcr.io/crazy0x70/cyber-monitor-server:latest
```

注意：默认的 Docker 命令不挂 docker.sock，管理面板里的一键更新对 Docker 部署不可用；要开就设 `CM_ENABLE_DOCKER_UPDATE=1` 并挂 `/var/run/docker.sock` —— 面板一键更新会自动重建容器并**保留节点身份**。不开就自己 pull 新镜像重建容器，重建时务必保留身份：沿用相同的卷挂载与环境变量（`CM_NODE_ID_FILE` + `/state`），或显式传 `-e CM_NODE_ID=<节点 ID>`（在后台节点抽屉里可以看到）。什么都不带的重建容器会被当成全新节点重新注册。

## 装 Agent

后台「节点管理」页有现成命令，填好 Server 地址和 Token 复制执行即可。手动装：

#### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o /tmp/one-click.sh
sudo bash /tmp/one-click.sh install-agent --server-url http://<server-ip>:25012 --agent-token <你的token>
```

macOS 不加 sudo 装成用户级 LaunchAgent（登录时启动），加 sudo 装系统级 LaunchDaemon（开机启动）。日志在 `/var/log/cybermonitor-agent.log`（root）或 `~/Library/Logs/`（用户）。

#### Windows

```powershell
$script = Join-Path $env:TEMP 'one-click.ps1'
Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.ps1' -OutFile $script
& $script install-agent -ServerUrl 'http://<server-ip>:25012' -AgentToken '<你的token>'
```

## 卸载

卸载同样用安装脚本。Linux/macOS：

```bash
sudo bash /tmp/one-click.sh uninstall-agent     # 删除 Agent 二进制、服务注册、身份文件
sudo bash /tmp/one-click.sh uninstall-server    # 加 --keep-data 保留数据目录
```

sudo 装的（系统级）必须用 sudo 卸；macOS 用户级安装不带 sudo 卸。Windows：

```powershell
& $script uninstall-agent
& $script uninstall-server    # -KeepData 保留数据目录
```

卸载会删二进制、服务注册和配置/身份文件；`--keep-data` / `-KeepData` 保留数据目录（节点、设置、历史）。

### Agent 上报什么

CPU（使用率、1/5/15 分钟负载、型号、核数）、内存、每个挂载点的磁盘、磁盘读写速率、网络上下行速率和累计流量、进程数、运行时长。ICMP 探测需要 raw socket，Linux 上 root 或 `CAP_NET_RAW`，容器里记得 `--cap-add NET_RAW`。

### 本地探测目标（可选）

后台没给节点配探测时，Agent 可以用 `-net-tests` 自带目标，逗号分隔：

```text
1.1.1.1  tcp:example.com:443  DNS@tcp:1.1.1.1:443
```

带端口走 TCP，不带走 ICMP；`名称@` 可选。IPv6 要加方括号：`icmp:[2001:db8::1]`。解析不了的目标会被跳过并记日志，不影响其余项。

注意：`-net-tests` 的结果只进实时展示，不进服务端历史（曲线和丢包统计只统计后台下发的探测目标）。

## 网络与代理

Agent 优先走 gRPC，环境只支持 HTTP/1.1 时自动回退 HTTP。HTTPS 地址不带端口时 gRPC 用 443，HTTP 用 80。代理 gRPC 时不要改写成 `/grpc/`，按真实服务前缀转发：

```nginx
location /cyber_monitor.agentrpc.AgentService/ {
    grpc_pass grpc://127.0.0.1:25013;
}
```

某个节点到 CDN 的 IPv6 路由坏了会导致 HTTP 和 gRPC 都超时——优先修宿主机路由；临时办法是 `--add-host <域名>:<可用IPv4>` 让它走 IPv4。

## 分离部署与静态托管

- 默认一个端口（25012）同时服务状态页、后台和 Agent 上报。
- 想把管理入口和公开页分开：设 `CM_PUBLIC_LISTEN`，公开页走独立端口。
- 状态页也能整个丢到 Cloudflare Pages / Netlify / 任意静态空间：上传 `internal/server/web/public/` 目录，改 `index.html` 里的 `<meta name="cm-api-base">` 指向你的 Server（Server 自带公开 API 的 CORS）。

## 性能与已知限制

快照聚合 + JSON 序列化的实测成本（Apple M5 Pro，含构建快照、编码、摘要）：10 个节点约 54µs / 39KB，100 个约 535µs / 530KB，1000 个约 5.7ms / 12MB——每秒一次，千节点规模约占单核 1%。资源**历史**不落盘（只有连通性探测有 1H/1D/1W 历史），状态页看到的资源数字是当前值，重启后不回放。这是刻意的：资源历史写盘的 IO 和体积对这个体量的工具不划算。

License: MIT。
