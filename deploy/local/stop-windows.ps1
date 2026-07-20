$ErrorActionPreference = "SilentlyContinue"
$Bind = if ($env:REVX_MCP_BIND) { $env:REVX_MCP_BIND } else { "127.0.0.1:9310" }
$Port = [int]($Bind.Split(":")[-1])
$Workspace = if ($env:REVX_WORKSPACE) { $env:REVX_WORKSPACE } else { Join-Path $env:LOCALAPPDATA "revx\workspace" }
$PidFile = Join-Path (Split-Path $Workspace -Parent) "mcp-http.pid"
if (Test-Path $PidFile) {
  $procId = Get-Content $PidFile | Select-Object -First 1
  if ($procId) { Stop-Process -Id $procId -Force }
  Remove-Item $PidFile -Force
}
Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
Write-Host "[revx] stopped $Bind"
