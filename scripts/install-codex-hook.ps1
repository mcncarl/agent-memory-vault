[CmdletBinding()]
param(
    [string]$RuntimeRoot = (Join-Path $env:LOCALAPPDATA 'AgentMemoryVault'),
    [string]$HooksPath = (Join-Path $env:USERPROFILE '.codex\hooks.json'),
    [string]$ConfigPath = (Join-Path $env:USERPROFILE '.codex\config.toml'),
    [switch]$AutoCloseout
)

$ErrorActionPreference = 'Stop'
$memoryctl = Join-Path $RuntimeRoot 'scripts\memoryctl'
$classifier = Join-Path $RuntimeRoot 'scripts\agent_memory_host_automation.py'
$runtimePython = Join-Path $RuntimeRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $memoryctl -PathType Leaf)) { throw "Managed memoryctl was not found: $memoryctl" }
if (-not (Test-Path -LiteralPath $classifier -PathType Leaf)) { throw "Host automation classifier was not found: $classifier" }
if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf)) { throw "Managed Runtime Python was not found: $runtimePython" }
$hooksDirectory = Split-Path -Parent $HooksPath
New-Item -ItemType Directory -Force -Path $hooksDirectory | Out-Null
$utf8 = [System.Text.UTF8Encoding]::new($false)
$utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)

function Get-BytesOrEmpty([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return [System.IO.File]::ReadAllBytes($Path) }
    return [byte[]]@()
}

function Write-AtomicWithBackup([string]$Path, [byte[]]$Before, [byte[]]$After) {
    $directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
        $backup = "$Path.before-agent-memory-v2-$stamp.bak"
        $stream = [System.IO.File]::Open($backup, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try { $stream.Write($Before, 0, $Before.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    }
    $temporary = Join-Path $directory ('.' + [System.IO.Path]::GetFileName($Path) + '.agent-memory-' + [Guid]::NewGuid().ToString('N'))
    $stream = [System.IO.File]::Open($temporary, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($After, 0, $After.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $current = Get-BytesOrEmpty $Path
    if ([Convert]::ToBase64String($current) -ne [Convert]::ToBase64String($Before)) {
        throw "HOST_CONFIG_CHANGED_BEFORE_REPLACE: $Path"
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        [System.IO.File]::Replace($temporary, $Path, $null)
    } else {
        [System.IO.File]::Move($temporary, $Path)
    }
}

function Enable-CodexHooksFeature([string]$Path) {
    $before = Get-BytesOrEmpty $Path
    $text = $utf8.GetString($before)
    $section = [regex]::Match($text, '(?ms)^\s*\[features\]\s*\r?\n(?<body>.*?)(?=^\s*\[|\z)')
    if ($section.Success) {
        $body = $section.Groups['body']
        $hooks = [regex]::Match($body.Value, '(?m)^(?<prefix>\s*hooks\s*=\s*)(?<value>true|false)(?<suffix>[^\r\n]*)')
        if ($hooks.Success) {
            $bodyText = $body.Value.Remove($hooks.Index, $hooks.Length).Insert(
                $hooks.Index,
                $hooks.Groups['prefix'].Value + 'true' + $hooks.Groups['suffix'].Value
            )
            $text = $text.Remove($body.Index, $body.Length).Insert($body.Index, $bodyText)
        } else {
            $text = $text.Insert($body.Index, "hooks = true`r`n")
        }
    } else {
        if ($text -and -not $text.EndsWith("`n")) { $text += "`r`n" }
        $text += "`r`n[features]`r`nhooks = true`r`n"
    }
    $after = $utf8.GetBytes($text)
    if ([Convert]::ToBase64String($after) -ne [Convert]::ToBase64String($before)) {
        Write-AtomicWithBackup $Path $before $after
    }
}

$hooksBefore = Get-BytesOrEmpty $HooksPath
if (Test-Path -LiteralPath $HooksPath) {
    try {
        # Windows PowerShell 5.1 treats BOM-less Get-Content input as the
        # process ANSI code page. Decode the exact bytes explicitly so Chinese
        # and other non-ASCII third-party fields survive reconciliation.
        $hooksText = $utf8Strict.GetString($hooksBefore)
        if ($hooksText.Length -gt 0 -and $hooksText[0] -eq [char]0xFEFF) {
            $hooksText = $hooksText.Substring(1)
        }
        $root = $hooksText | ConvertFrom-Json
        if ($root -isnot [pscustomobject]) { throw 'CODEX_HOOKS_ROOT_INVALID' }
    } catch {
        throw "Invalid UTF-8 Codex hooks JSON: $HooksPath"
    }
} else { $root = [pscustomobject]@{} }
if (-not $root.PSObject.Properties['hooks']) { $root | Add-Member -NotePropertyName hooks -NotePropertyValue ([pscustomobject]@{}) }
if ($root.hooks -isnot [pscustomobject]) { throw 'CODEX_HOOKS_CONTAINER_INVALID' }
$hooksEnabled = if ($root.hooks.PSObject.Properties['enabled']) { $root.hooks.enabled } else { $null }
$hooksDisabled = if ($root.hooks.PSObject.Properties['disabled']) { $root.hooks.disabled } else { $null }
if (
    ($hooksEnabled -is [bool] -and $hooksEnabled -eq $false) -or
    ($hooksDisabled -is [bool] -and $hooksDisabled -eq $true)
) {
    # Enabling a globally disabled container is outside this installer's
    # authority. Fail before creating either host-file backup or replacement.
    throw 'CODEX_HOOK_EVENT_DISABLED'
}
if (-not $root.hooks.PSObject.Properties['Stop']) { $root.hooks | Add-Member -NotePropertyName Stop -NotePropertyValue @() }

$mode = if ($AutoCloseout) { ' --auto-closeout' } else { '' }
$command = '"{0}" -I -S "{1}" --actor codex stop-hook --protocol codex --event stop-hook{2} --timeout 300' -f $runtimePython, $memoryctl, $mode
$entryClassificationArgs = @(
    '-X', 'utf8', '-I', '-S', $classifier, 'classify-codex-hook-entry',
    '--runtime-root', $RuntimeRoot,
    '--runtime-python', $runtimePython,
    '--json'
)
if ($AutoCloseout) { $entryClassificationArgs += '--auto-closeout' }

function Get-CodexHookRouteClassification([object]$Hook) {
    $entryJson = ConvertTo-Json -InputObject $Hook -Depth 20 -Compress
    $previousOutputEncoding = $OutputEncoding
    try {
        # Windows PowerShell 5.1 otherwise encodes native-pipeline input as
        # ASCII.  Force UTF-8 at both ends so non-ASCII paths are classified
        # against the same shared contract as Doctor and publish-ready.
        $OutputEncoding = $utf8
        $classificationOutput = @($entryJson | & $runtimePython @entryClassificationArgs 2>&1)
        $classificationExitCode = $LASTEXITCODE
    } finally {
        $OutputEncoding = $previousOutputEncoding
    }
    if ($classificationExitCode -ne 0) {
        throw 'CODEX_HOOK_CLASSIFIER_FAILED'
    }
    try {
        $classification = ($classificationOutput -join [Environment]::NewLine) | ConvertFrom-Json
    } catch {
        throw 'CODEX_HOOK_CLASSIFIER_OUTPUT_INVALID'
    }
    $kind = [string]$classification.kind
    $reasonCode = [string]$classification.reason_code
    $agentMemoryRoute = $classification.agent_memory_route
    if (
        $kind -notin @('canonical', 'legacy', 'ambiguous', 'unrelated') -or
        -not $reasonCode -or
        $agentMemoryRoute -isnot [bool]
    ) {
        throw 'CODEX_HOOK_CLASSIFIER_OUTPUT_INVALID'
    }
    return $classification
}

$canonicalGroup = $null
foreach ($group in @($root.hooks.Stop)) {
    $kept = @()
    $hadManagedRoute = $false
    foreach ($hook in @($group.hooks)) {
        $classification = Get-CodexHookRouteClassification $hook
        switch ($classification.kind) {
            'unrelated' {
                if ($classification.agent_memory_route) {
                    throw 'CODEX_HOOK_CLASSIFIER_OUTPUT_INVALID'
                }
                $kept += $hook
            }
            { $_ -in @('canonical', 'legacy') } {
                if (-not $classification.agent_memory_route) {
                    throw 'CODEX_HOOK_CLASSIFIER_OUTPUT_INVALID'
                }
                $hadManagedRoute = $true
            }
            'ambiguous' {
                if (-not $classification.agent_memory_route) {
                    # An unknown third-party route is never ours to rewrite.
                    # Abort before either host configuration file is replaced.
                    throw 'CODEX_HOOK_UNMANAGED_AMBIGUOUS'
                }
                $hadManagedRoute = $true
            }
        }
    }
    $group.hooks = @($kept)
    $hasMatcher = $null -ne $group.PSObject.Properties['matcher']
    $matcher = if ($hasMatcher) { $group.matcher } else { $null }
    $groupDisabled = (
        ($group.PSObject.Properties['enabled'] -and $group.enabled -eq $false) -or
        ($group.PSObject.Properties['disabled'] -and $group.disabled -eq $true)
    )
    $matcherScoped = (
        $hasMatcher -and
        $null -ne $matcher -and
        -not ($matcher -is [string] -and $matcher -eq '')
    )
    if ($hadManagedRoute -and -not $groupDisabled -and -not $matcherScoped -and $null -eq $canonicalGroup) {
        # Reuse the original catch-all group when it is executable. This keeps
        # repeated installs byte-stable instead of accumulating empty groups.
        $canonicalGroup = $group
    }
}
$canonicalHook = [pscustomobject]@{
    type = 'command'
    command = $command
    timeout = $(if ($AutoCloseout) { 320 } else { 20 })
}
if ($null -ne $canonicalGroup) {
    $canonicalGroup.hooks = @($canonicalGroup.hooks) + @($canonicalHook)
} else {
    $entry = [pscustomobject]@{ hooks = @($canonicalHook) }
    $root.hooks.Stop = @($root.hooks.Stop) + @($entry)
}
$json = $root | ConvertTo-Json -Depth 20
$hooksAfter = $utf8.GetBytes($json + [Environment]::NewLine)
if ([Convert]::ToBase64String($hooksAfter) -ne [Convert]::ToBase64String($hooksBefore)) {
    Write-AtomicWithBackup $HooksPath $hooksBefore $hooksAfter
}
Enable-CodexHooksFeature $ConfigPath
$verificationArgs = @(
    '-I', '-S', $classifier, 'verify-codex-hook',
    '--hooks-json', $HooksPath,
    '--runtime-root', $RuntimeRoot,
    '--runtime-python', $runtimePython,
    '--json'
)
if ($AutoCloseout) { $verificationArgs += '--auto-closeout' }
$verificationOutput = @(& $runtimePython @verificationArgs 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "CODEX_HOOKS_INVALID: $($verificationOutput -join ' ')"
}
Write-Output "[OK] Codex Stop Hook installed: $HooksPath"
Write-Output "[OK] Codex hooks feature enabled: $ConfigPath"
