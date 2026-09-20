// AgentToken 由管理端设置 API 回传真实值：命令直接内嵌，复制即可执行；
// 仅在尚未配置 Token 时退化为占位符 <你的AgentToken>。
export function buildAgentInstallCommand(endpoint: string, token: string) {
  const normalizedEndpoint = endpoint.trim();
  if (!normalizedEndpoint) return "";
  const normalizedToken = token.trim() || "<你的AgentToken>";

  const escapeShell = (value: string) => `'${String(value).replace(/'/g, `'\''`)}'`;
  const safeEndpoint = escapeShell(normalizedEndpoint);
  const safeToken = escapeShell(normalizedToken);
  return [
    `set -e`,
    `tmp="$(mktemp -d)"`,
    `trap 'rm -rf "$tmp"' EXIT`,
    `curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/one-click.sh -o "$tmp/one-click.sh"`,
    `sudo bash "$tmp/one-click.sh" install-agent --server-url ${safeEndpoint} --agent-token ${safeToken}`,
  ].join("\n");
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
