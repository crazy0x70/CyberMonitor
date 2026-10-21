export function buildAgentInstallCommand(endpoint: string, token: string) {
  const normalizedEndpoint = endpoint.trim();
  if (!normalizedEndpoint) return "";
  const normalizedToken = token.trim() || "<你的AgentToken>";

  // POSIX 单引号转义：把内部的 ' 变成 '\'' （先闭合、插入转义后的引号、再重开）。
  // 注意必须用普通字符串字面量，模板字面量里的 \' 会被 JS 当成转义的引号，
  // 实际替成 '''，生成的命令会提前断引号。
  const escapeShell = (value: string) => `'${String(value).replace(/'/g, "'\\''")}'`;
  const safeEndpoint = escapeShell(normalizedEndpoint);
  const safeToken = escapeShell(normalizedToken);
  // one-click.sh 在 Linux 上本来就要求 root；很多最小化 VPS 以 root 登录且没装
  // sudo，固定加 sudo 会在 `sudo: command not found` 处直接失败（set -e）。
  const install = `bash "$tmp/one-click.sh" install-agent --server-url ${safeEndpoint} --agent-token ${safeToken}`;
  return [
    `set -e`,
    `tmp="$(mktemp -d)"`,
    `trap 'rm -rf "$tmp"' EXIT`,
    `curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o "$tmp/one-click.sh"`,
    `if [ "$(id -u)" -eq 0 ]; then`,
    `  ${install}`,
    `else`,
    `  sudo ${install}`,
    `fi`,
  ].join("\n");
}

// 推断出的对接地址可能只有本机可达（localhost / 回环），面板要额外给出提示。
// 解析失败按「非回环」处理，避免误报。
export function isLoopbackAgentHost(endpoint: string): boolean {
  const raw = endpoint.trim();
  if (!raw) return false;
  let hostname: string;
  try {
    hostname = new URL(raw).hostname;
  } catch {
    return false;
  }
  // URL.hostname 对 IPv6 保留方括号，统一去掉并转小写再比较。
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) return false;
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1" || host === "0:0:0:0:0:0:0:1") return true;
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!ipv4) return false;
  if (!ipv4[1].startsWith("127")) return false;
  return ipv4.slice(1).every((part) => Number(part) <= 255);
}

export function buildAgentWindowsInstallCommand(endpoint: string, token: string) {
  const normalizedEndpoint = endpoint.trim();
  if (!normalizedEndpoint) return "";
  const normalizedToken = token.trim() || "<你的AgentToken>";

  const escapePwsh = (value: string) => String(value).replace(/'/g, "''");
  const safeEndpoint = escapePwsh(normalizedEndpoint);
  const safeToken = escapePwsh(normalizedToken);
  return [
    `$ErrorActionPreference = 'Stop'`,
    `$script = Join-Path $env:TEMP ("cybermonitor-one-click-" + [guid]::NewGuid().ToString() + ".ps1")`,
    `try {`,
    `  Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.ps1' -OutFile $script -ErrorAction Stop`,
    `  & $script install-agent -ServerUrl '${safeEndpoint}' -AgentToken '${safeToken}'`,
    `} finally {`,
    `  Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue`,
    `}`,
  ].join("\n");
}
