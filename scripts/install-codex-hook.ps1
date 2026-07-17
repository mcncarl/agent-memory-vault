[CmdletBinding()]
param(
    [string]$RuntimeRoot = (Join-Path $env:LOCALAPPDATA 'AgentMemoryVault'),
    [string]$HooksPath = (Join-Path $env:USERPROFILE '.codex\hooks.json'),
    [switch]$AutoCloseout
)

$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $RuntimeRoot 'scripts\stop-hook.ps1'
if (-not (Test-Path -LiteralPath $wrapper)) { throw "Stop Hook wrapper was not found: $wrapper" }
$hooksDirectory = Split-Path -Parent $HooksPath
New-Item -ItemType Directory -Force -Path $hooksDirectory | Out-Null

if (Test-Path -LiteralPath $HooksPath) {
    try { $root = Get-Content -Raw -LiteralPath $HooksPath | ConvertFrom-Json }
    catch { throw "Invalid Codex hooks JSON: $HooksPath" }
} else {
    $root = [pscustomobject]@{}
}
if (-not $root.PSObject.Properties['hooks']) { $root | Add-Member -NotePropertyName hooks -NotePropertyValue ([pscustomobject]@{}) }
if (-not $root.hooks.PSObject.Properties['Stop']) { $root.hooks | Add-Member -NotePropertyName Stop -NotePropertyValue @() }

$mode = if ($AutoCloseout) { ' -AutoCloseout' } else { '' }
$command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}" -Actor codex -Protocol codex{1}' -f $wrapper, $mode
$existing = $root.hooks.Stop | ConvertTo-Json -Depth 20 -Compress
if (-not $existing -or $existing -notlike '*stop-hook.ps1*') {
    $entry = [pscustomobject]@{
        hooks = @([pscustomobject]@{ type = 'command'; command = $command; timeout = $(if ($AutoCloseout) { 320 } else { 20 }) })
    }
    $root.hooks.Stop = @($root.hooks.Stop) + @($entry)
}
$json = $root | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($HooksPath, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
Write-Output "[OK] Codex Stop Hook installed: $HooksPath"
Write-Output '[WARN] Confirm that [features] hooks = true is enabled in ~/.codex/config.toml.'
