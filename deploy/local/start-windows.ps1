$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bind = if ($env:REVX_MCP_BIND) { $env:REVX_MCP_BIND } else { "127.0.0.1:9310" }
$Url = "http://$Bind/mcp"
$Workspace = if ($env:REVX_WORKSPACE) { $env:REVX_WORKSPACE } else { Join-Path $env:LOCALAPPDATA "revx\workspace" }

function Find-Engine {
  if ($env:REVX_ENGINE -and (Test-Path $env:REVX_ENGINE)) { return $env:REVX_ENGINE }
  $candidates = @(
    (Join-Path $Root "revx-engine.exe"),
    (Join-Path $Root "revx-engine"),
    (Join-Path (Split-Path $Root -Parent) "revx-engine.exe")
  )
  foreach ($c in $candidates) {
    if (Test-Path $c) { return $c }
  }
  $cmd = Get-Command revx-engine.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $cmd = Get-Command revx-engine -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}

$Engine = Find-Engine
if (-not $Engine) {
  Write-Error "[revx] revx-engine not found. Place revx-engine.exe next to this script or set REVX_ENGINE."
}

New-Item -ItemType Directory -Force -Path $Workspace | Out-Null
if (-not (Test-Path (Join-Path $Workspace ".revx"))) {
  & $Engine init $Workspace | Out-Null
}

try {
  $health = Invoke-WebRequest -Uri "http://$Bind/mcp/health" -UseBasicParsing -TimeoutSec 1
  if ($health.StatusCode -eq 200) {
    Write-Host "[revx] already running: $Url"
    Write-Host "[revx] engine: $Engine"
    Write-Host "[revx] workspace: $Workspace"
    exit 0
  }
} catch {}

Write-Host "[revx] starting MCP HTTP"
Write-Host "[revx] engine: $Engine"
Write-Host "[revx] workspace: $Workspace"
Write-Host "[revx] url: $Url"

$logDir = Split-Path $Workspace -Parent
$outLog = Join-Path $logDir "mcp-http.log"
$errLog = Join-Path $logDir "mcp-http.err.log"

if ($env:REVX_MCP_FOREGROUND -eq "1") {
  & $Engine mcp http --bind $Bind --workspace $Workspace
  exit $LASTEXITCODE
}

$proc = Start-Process -FilePath $Engine -ArgumentList @("mcp","http","--bind",$Bind,"--workspace",$Workspace) `
  -WindowStyle Hidden -PassThru -RedirectStandardOutput $outLog -RedirectStandardError $errLog
$proc.Id | Out-File -Encoding ascii (Join-Path $logDir "mcp-http.pid")

for ($i = 0; $i -lt 20; $i++) {
  try {
    $health = Invoke-WebRequest -Uri "http://$Bind/mcp/health" -UseBasicParsing -TimeoutSec 1
    if ($health.StatusCode -eq 200) {
      Write-Host "[revx] ready: $Url"
      Write-Host "[revx] codex config:"
      Write-Host "[mcp_servers.revx]"
      Write-Host "url = `"$Url`""
      exit 0
    }
  } catch {}
  Start-Sleep -Milliseconds 300
}

Write-Error "[revx] started but health check failed; see $errLog"
