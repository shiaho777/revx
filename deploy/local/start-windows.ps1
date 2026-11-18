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

$TokenFile = Join-Path $Workspace ".revx\mcp-token"
$Token = if ($env:REVX_MCP_TOKEN) { $env:REVX_MCP_TOKEN } else { "" }
if (-not $Token -and (Test-Path $TokenFile)) {
  $Token = (Get-Content $TokenFile -Raw).Trim()
}

function Get-AuthHeaders {
  if ($script:Token) { return @{ Authorization = "Bearer $($script:Token)" } }
  return @{}
}

function Test-Health {
  try {
    $health = Invoke-WebRequest -Uri "http://$Bind/mcp/health" -Headers (Get-AuthHeaders) -UseBasicParsing -TimeoutSec 1
    return ($health.StatusCode -eq 200)
  } catch { return $false }
}

function Write-ClientConfig {
  Write-Host "[revx] codex config:"
  Write-Host "[mcp_servers.revx]"
  Write-Host "url = `"$Url`""
  Write-Host "bearer_token_env_var = `"REVX_MCP_TOKEN`""
  if ($script:Token) {
    Write-Host "[revx] token: $($script:Token)"
    Write-Host "[revx] token file: $TokenFile"
    Write-Host "[revx] set REVX_MCP_TOKEN=$($script:Token)"
  } else {
    Write-Host "[revx] token will be generated at $TokenFile on first start"
  }
}

if (Test-Health) {
  Write-Host "[revx] already running: $Url"
  Write-Host "[revx] engine: $Engine"
  Write-Host "[revx] workspace: $Workspace"
  Write-ClientConfig
  exit 0
}

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
  if (-not $script:Token -and (Test-Path $TokenFile)) {
    $script:Token = (Get-Content $TokenFile -Raw).Trim()
  }
  if (Test-Health) {
    Write-Host "[revx] ready: $Url"
    Write-ClientConfig
    exit 0
  }
  Start-Sleep -Milliseconds 300
}

Write-Error "[revx] started but health check failed; see $errLog"
