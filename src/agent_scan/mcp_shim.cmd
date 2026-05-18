@echo off
where /q pwsh && set "PS=pwsh" || set "PS=powershell"
%PS% -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s=Get-Content -Raw -LiteralPath '%~f0'; & ([ScriptBlock]::Create($s.Substring($s.IndexOf('#---PS---')))) %*"
exit /b %ERRORLEVEL%

#---PS---
param(
  [string]$uuid = "",
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$Cmd
)

if (-not $Cmd) { [Console]::Error.WriteLine("mcp_shim: no command"); exit 2 }

$dir    = if ($env:TEMP) { $env:TEMP } else { "C:\Windows\Temp" }
$rand   = -join ((1..6) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
$prefix = if ($uuid) { "mcp_shim.$uuid" } else { "mcp_shim" }
$log    = Join-Path $dir "$prefix.$rand.log"
[Console]::Error.WriteLine("shim log: $log")

$exe  = $Cmd[0]
$rest = if ($Cmd.Count -gt 1) { $Cmd[1..($Cmd.Count-1)] } else { @() }
& $exe @rest | Tee-Object -FilePath $log
exit $LASTEXITCODE
