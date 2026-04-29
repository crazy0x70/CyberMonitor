export function buildAgentInstallCommand(endpoint: string, token: string) {
  const normalizedEndpoint = endpoint.trim();
  const normalizedToken = token.trim();
  if (!normalizedEndpoint || !normalizedToken) return "";

  const escapeShell = (value: string) => `'${String(value).replace(/'/g, `'\\''`)}'`;
  const safeEndpoint = escapeShell(normalizedEndpoint);
  const safeToken = escapeShell(normalizedToken);
  return [
    `tmp="$(mktemp -d)"`,
    `curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/install-common.sh -o "$tmp/install-common.sh"`,
    `curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.sh -o "$tmp/agent.sh"`,
    `sudo bash "$tmp/agent.sh" --server-url ${safeEndpoint} --agent-token ${safeToken}`,
    `rm -rf "$tmp"`,
  ].join("\n");
}

export function buildAgentWindowsInstallCommand(endpoint: string, token: string) {
  const normalizedEndpoint = endpoint.trim();
  const normalizedToken = token.trim();
  if (!normalizedEndpoint || !normalizedToken) return "";

  const escapePwsh = (value: string) => String(value).replace(/'/g, "''");
  const safeEndpoint = escapePwsh(normalizedEndpoint);
  const safeToken = escapePwsh(normalizedToken);
  return [
    `$script = Join-Path $env:TEMP 'agent.ps1'`,
    `Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/scripts/agent.ps1' -OutFile $script`,
    `& $script -ServerUrl '${safeEndpoint}' -AgentToken '${safeToken}'`,
  ].join("\n");
}
