[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'status', 'run', 'uninstall')]
    [string]$Action = 'status',
    [string]$TaskName = 'AgentMemoryVaultAudit',
    [string]$Python = '',
    [string]$RuntimeRoot = '',
    [int]$DayOfWeek = 0,
    [string]$At = '10:30'
)

$ErrorActionPreference = 'Stop'
if (-not $RuntimeRoot) { $RuntimeRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$scriptRoot = Join-Path $RuntimeRoot 'scripts'
$memoryctl = Join-Path $scriptRoot 'memoryctl'
if (-not $Python) {
    $candidate = Join-Path $RuntimeRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw 'The managed Agent Memory Python was not found.'
    }
    $Python = $candidate
}

switch ($Action) {
    'install' {
        if (-not (Test-Path -LiteralPath $memoryctl -PathType Leaf)) { throw "Agent Memory entrypoint was not found: $memoryctl" }
        $days = @('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
        if ($DayOfWeek -lt 0 -or $DayOfWeek -gt 6) { throw 'DayOfWeek must be between 0 and 6.' }
        $taskAction = New-ScheduledTaskAction -Execute $Python `
            -Argument ('-I -S "{0}" --actor human audit-autorun --reason task-scheduler --json' -f $memoryctl) `
            -WorkingDirectory $RuntimeRoot
        $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $days[$DayOfWeek] -At $At
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
            -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
        Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $trigger `
            -Principal $principal -Settings $settings -Description 'Agent Memory Vault weekly audit' -Force | Out-Null
        Write-Output "[OK] installed task=$TaskName"
    }
    'status' {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) { Write-Output "[WARN] task_missing name=$TaskName"; exit 1 }
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Output "[OK] task=$TaskName state=$($task.State) last_result=$($info.LastTaskResult) next_run=$($info.NextRunTime)"
    }
    'run' {
        if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { throw "Scheduled task not found: $TaskName" }
        Start-ScheduledTask -TaskName $TaskName
        Write-Output "[OK] started task=$TaskName"
    }
    'uninstall' {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Output "[OK] uninstalled task=$TaskName"
        } else { Write-Output "[OK] task_already_absent name=$TaskName" }
    }
}
