export function buildAgentInstallCommand(endpoint: string, token: string) {
  const normalizedEndpoint = endpoint.trim();
  const normalizedToken = token.trim();
  if (!normalizedEndpoint || !normalizedToken) return "";
  return `curl -fsSL https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.sh -o /tmp/agent.sh && bash /tmp/agent.sh --server-url ${normalizedEndpoint} --agent-token ${normalizedToken}`;
}

export function buildAgentWindowsInstallCommand(endpoint: string, token: string) {
  const normalizedEndpoint = endpoint.trim();
  const normalizedToken = token.trim();
  if (!normalizedEndpoint || !normalizedToken) return "";

  const escapePwsh = (value: string) => String(value).replace(/'/g, "''");
  const safeEndpoint = escapePwsh(normalizedEndpoint);
  const safeToken = escapePwsh(normalizedToken);
  return `powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing https://raw.githubusercontent.com/crazy0x70/CyberMonitor/main/agent.ps1 -OutFile ($env:TEMP + '\\agent.ps1'); & ($env:TEMP + '\\agent.ps1') -ServerUrl '${safeEndpoint}' -AgentToken '${safeToken}'"`;
}
