@echo off
where /q pwsh && set "PS=pwsh" || set "PS=powershell"
%PS% -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s=Get-Content -Raw -LiteralPath '%~f0'; & ([ScriptBlock]::Create($s.Substring($s.IndexOf('#---PS---')))) %*"
exit /b %ERRORLEVEL%

#---PS---
param(
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$Cmd
)

if (-not $Cmd) { [Console]::Error.WriteLine("snyk_mcp_stdio_local_proxy: no command"); exit 2 }

$joined = ($Cmd -join "`0") + "`0"
$bytes  = [System.Text.Encoding]::UTF8.GetBytes($joined)
$sha    = [System.Security.Cryptography.SHA256]::Create()
$hash   = (-join ($sha.ComputeHash($bytes) | ForEach-Object { '{0:x2}' -f $_ })).Substring(0, 12)

$dir    = if ($env:TEMP) { $env:TEMP } else { "C:\Windows\Temp" }
$rand   = -join ((1..6) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
$log    = Join-Path $dir "snyk_mcp_stdio_local_proxy.$hash.$rand.log"
[Console]::Error.WriteLine("snyk_mcp_stdio_local_proxy log: $log")

# Create the capture file with owner-only access (remove inherited ACL,
# leave a single ACE for the current user with FullControl).
New-Item -ItemType File -Path $log -Force | Out-Null
try {
  $acl  = Get-Acl -LiteralPath $log
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
    'FullControl', 'Allow'
  )
  $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $log -AclObject $acl
} catch {
  # Best-effort: leave inherited ACL in place if tightening fails.
}

$exe  = $Cmd[0]
$rest = if ($Cmd.Count -gt 1) { $Cmd[1..($Cmd.Count-1)] } else { @() }
& $exe @rest | ForEach-Object {
  $_
  if ($_ -match '"(tools|prompts|resources|resourceTemplates)"\s*:\s*\[|"serverInfo"\s*:') { Add-Content -LiteralPath $log -Value $_ }
}
exit $LASTEXITCODE
