[CmdletBinding()]
param(
    [ValidateSet('codex', 'claude')]
    [string]$Actor = 'codex',
    [ValidateSet('codex', 'claude')]
    [string]$Protocol = 'codex',
    [switch]$AutoCloseout,
    [int]$Timeout = 300,
    [string]$Python = ''
)

$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$memoryctl = Join-Path $scriptRoot 'memoryctl'

if (-not $Python) {
    $venvPython = Join-Path (Split-Path -Parent $scriptRoot) '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $venvPython) {
        $Python = $venvPython
    } else {
        $command = Get-Command python.exe -ErrorAction SilentlyContinue
        if (-not $command) { $command = Get-Command py.exe -ErrorAction SilentlyContinue }
        if (-not $command) { throw 'Python 3 was not found. Run scripts\install-windows.ps1 first.' }
        $Python = $command.Source
    }
}
if (-not (Test-Path -LiteralPath $memoryctl)) {
    throw "Agent Memory entrypoint was not found: $memoryctl"
}

$arguments = @('-I', '-S', $memoryctl, '--actor', $Actor, 'stop-hook', '--protocol', $Protocol, '--timeout', $Timeout)
if ($AutoCloseout) { $arguments += '--auto-closeout' }
$payload = [Console]::In.ReadToEnd()
try {
    if ($payload) { $payload | & $Python @arguments }
    else { & $Python @arguments }
    exit $LASTEXITCODE
} catch {
    Write-Error "Agent Memory Stop Hook failed: $($_.Exception.Message)"
    exit 2
}
