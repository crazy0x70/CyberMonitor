// AgentToken 已脱敏回传（agent_token_set 区分"已配置但隐藏"）：
// 构建安装命令时用占位符，用户复制后自行替换。
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
