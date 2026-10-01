[CmdletBinding()]
param(
    [string]$MemoryRoot = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Agent Memory Vault'),
    [string]$GitRoot = '',
    [string]$ConfigRoot = (Join-Path $env:LOCALAPPDATA 'AgentMemoryVault'),
    [string]$UserId = 'demo-user',
    [string]$AgentId = 'shared',
    [string]$AppId = 'agent-memory',
    [switch]$InstallCodexHook,
    [switch]$AutoCloseout,
    [switch]$InstallAuditTask
)

$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$venvRoot = Join-Path $ConfigRoot '.venv'
$venvPython = Join-Path $venvRoot 'Scripts\python.exe'

function Test-ContainedPath([string]$Root, [string]$Path) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $target = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return (
        $candidate.Equals($target, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith($target + '\', [StringComparison]::OrdinalIgnoreCase)
    )
}

function Resolve-SourcePathComponents([string]$Path) {
    # Expand each existing parent reparse point without invoking the candidate.
    # A lexical check of the leaf alone can be bypassed by C:\alias -> target.
    $current = [IO.Path]::GetFullPath($Path)
    $seen = @{}
    for ($depth = 0; $depth -lt 64; $depth++) {
        $key = $current.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { throw 'SOURCE_PYTHON_REPARSE_CYCLE' }
        $seen[$key] = $true
        $root = [IO.Path]::GetPathRoot($current)
        $relative = $current.Substring($root.Length)
        $parts = @($relative -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $cursor = $root
        $redirected = $false
        for ($index = 0; $index -lt $parts.Count; $index++) {
            $cursor = [IO.Path]::Combine($cursor, [string]$parts[$index])
            if (-not (Test-Path -LiteralPath $cursor)) { return $current }
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { continue }
            $targets = @($item.Target)
            if ($targets.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$targets[0])) {
                throw 'SOURCE_PYTHON_REPARSE_INVALID'
            }
            $next = [string]$targets[0]
            if ($next.StartsWith('\??\')) { $next = $next.Substring(4) }
            if (-not [IO.Path]::IsPathRooted($next)) {
                $next = Join-Path (Split-Path -Parent $cursor) $next
            }
            for ($remaining = $index + 1; $remaining -lt $parts.Count; $remaining++) {
                $next = [IO.Path]::Combine($next, [string]$parts[$remaining])
            }
            $current = [IO.Path]::GetFullPath($next)
            $redirected = $true
            break
        }
        if (-not $redirected) { return $current }
    }
    throw 'SOURCE_PYTHON_REPARSE_CHAIN_TOO_DEEP'
}

function Assert-ExternalSourcePython([string]$Path) {
    # This runs before the first version probe.  Never execute a PATH shim,
    # explicit python.exe, or reparse chain that starts in or redirects into
    # the fixed target venv; only install_runtime may authenticate/reuse it.
    $target = Resolve-SourcePathComponents $venvRoot
    $current = Resolve-SourcePathComponents $Path
    if (Test-ContainedPath $target $current) { throw 'SOURCE_PYTHON_TARGET_VENV_FORBIDDEN' }
}

function Invoke-Checked([string]$Executable, [string[]]$Arguments, [string]$Label) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE" }
}

function Invoke-JsonChecked([string]$Executable, [string[]]$Arguments, [string]$Label) {
    $output = & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE" }
    try {
        $payload = (($output | Out-String).Trim() | ConvertFrom-Json)
    } catch {
        throw "$Label returned invalid JSON"
    }
    if ($null -eq $payload -or $payload.ok -ne $true) { throw "$Label returned an unsuccessful result" }
    return $payload
}

function Get-Utf8Sha256Hex([string]$Text) {
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($encoding.GetBytes($Text))
        return -join @($digest | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha256.Dispose()
    }
}

$git = Get-Command git.exe -ErrorAction SilentlyContinue
if (-not $git) { throw 'Git was not found in PATH.' }
$python = Get-Command py.exe -ErrorAction SilentlyContinue
$prefix = @('-3')
if (-not $python) { $python = Get-Command python.exe -ErrorAction SilentlyContinue; $prefix = @() }
if (-not $python) { throw 'Python 3 was not found in PATH.' }
Assert-ExternalSourcePython $python.Source
$version = & $python.Source @prefix -c 'import sys; print(sys.version_info.major * 100 + sys.version_info.minor); raise SystemExit(sys.version_info < (3, 10))'
if ($LASTEXITCODE -ne 0) { throw "Python 3.10 or newer is required; detected version code $version" }

# Never let an unrelated live session redirect installer discovery.
Get-ChildItem Env: | Where-Object { $_.Name -like 'AGENT_MEMORY_*' } | ForEach-Object {
    Remove-Item -LiteralPath ("Env:" + $_.Name)
}

$sourceScripts = Join-Path $repoRoot 'scripts'
$requestedGitRoot = if ([string]::IsNullOrWhiteSpace($GitRoot)) { $MemoryRoot } else { $GitRoot }
$stateDb = Join-Path $ConfigRoot 'state.sqlite'
$auditDb = Join-Path $ConfigRoot 'audit_decisions.sqlite'
function TomlPath([string]$Path) { return $Path.Replace('\', '/') }
function TomlString([string]$Value) { return $Value.Replace('\', '\\').Replace('"', '\"') }
$configDir = Join-Path $ConfigRoot 'config'
$configPath = Join-Path $configDir 'agent-memory.toml'

function Assert-NotReparsePoint([string]$Path, [string]$Label) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($true) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label path chain must not contain a reparse point"
            }
        }
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent -or $parent.FullName -eq $current) { break }
        $current = $parent.FullName
    }
}

Assert-NotReparsePoint $ConfigRoot 'ConfigRoot'
$existingConfig = Test-Path -LiteralPath $configPath -PathType Leaf
if ((Test-Path -LiteralPath $configPath) -and -not $existingConfig) {
    throw 'Config path exists but is not a regular file.'
}
Assert-NotReparsePoint $configPath 'Config file'

$configuredMemoryRoot = $MemoryRoot
$configuredGitRoot = $requestedGitRoot
if ($existingConfig) {
    $env:AGENT_MEMORY_CONFIG_FILE = $configPath
    $env:AGENT_MEMORY_CONFIG_ROOT = $ConfigRoot
    $pathProbe = @'
import json,sys
sys.path.insert(0, sys.argv[1])
from agent_memory_env import env_value, expand_path
print(json.dumps({
  "memory_root": str(expand_path(env_value("ROOT", "")).resolve()),
  "git_root": str(expand_path(env_value("GIT_ROOT", "")).resolve()),
  "state_db": str(expand_path(env_value("STATE_DB", "")).resolve()),
  "audit_db": str(expand_path(env_value("AUDIT_DB", "")).resolve()),
}))
'@
    $configured = & $python.Source @prefix -c $pathProbe $sourceScripts | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $null -eq $configured) { throw 'configured path resolution failed' }
    $configuredMemoryRoot = [string]$configured.memory_root
    $configuredGitRoot = [string]$configured.git_root
    $stateDb = [string]$configured.state_db
    $auditDb = [string]$configured.audit_db
}

$existingState = Test-Path -LiteralPath $stateDb -PathType Leaf
if ((Test-Path -LiteralPath $stateDb) -and -not $existingState) {
    throw 'State path exists but is not a regular file.'
}
Assert-NotReparsePoint $stateDb 'State database'
Assert-NotReparsePoint $auditDb 'Audit database'
if ($existingConfig -ne $existingState) {
    throw 'PARTIAL_INSTALL_AMBIGUOUS: config and state must either both exist or both be absent.'
}
$installationMode = if ($existingConfig) { 'upgrade' } else { 'fresh' }

if ($installationMode -eq 'upgrade') {
    if (
        [IO.Path]::GetFullPath($configuredMemoryRoot) -ne [IO.Path]::GetFullPath($MemoryRoot) -or
        [IO.Path]::GetFullPath($configuredGitRoot) -ne [IO.Path]::GetFullPath($requestedGitRoot)
    ) { throw 'CONFIGURED_ROOT_MISMATCH' }
    Assert-NotReparsePoint $configuredMemoryRoot 'MemoryRoot'
    Assert-NotReparsePoint $configuredGitRoot 'GitRoot'
    if (-not (Test-Path -LiteralPath $configuredMemoryRoot -PathType Container)) { throw 'UPGRADE_MEMORY_ROOT_INVALID' }
    if (-not (Test-Path -LiteralPath $configuredGitRoot -PathType Container)) { throw 'UPGRADE_GIT_ROOT_INVALID' }
    foreach ($governance in @('AGENTS.md', 'INDEX.md')) {
        $governancePath = Join-Path $configuredMemoryRoot $governance
        Assert-NotReparsePoint $governancePath "Governance $governance"
        if (-not (Test-Path -LiteralPath $governancePath -PathType Leaf)) { throw 'UPGRADE_GOVERNANCE_MISSING' }
    }
} else {
    Assert-NotReparsePoint $MemoryRoot 'MemoryRoot'
    if (Test-Path -LiteralPath $MemoryRoot) {
        if (-not (Test-Path -LiteralPath $MemoryRoot -PathType Container)) { throw 'FRESH_MEMORY_ROOT_INVALID' }
        if ($null -ne (Get-ChildItem -LiteralPath $MemoryRoot -Force | Select-Object -First 1)) {
            throw 'FRESH_MEMORY_ROOT_NOT_EMPTY'
        }
    }
}

# Mutations start only after the fresh/upgrade pair and Vault invariants are
# fully classified. Upgrade never bootstraps Markdown or initializes Git.
New-Item -ItemType Directory -Force -Path $ConfigRoot | Out-Null
# install_runtime owns the fixed target venv.  It either authenticates a ready
# v2 launcher before reuse or recoverably moves an untrusted legacy venv aside
# and creates a replacement with this already-selected source Python.  Creating
# it here would make a fresh venv look like unauthenticated pre-existing code.
Invoke-Checked $python.Source ($prefix + @((Join-Path $repoRoot 'scripts\install_runtime.py'), '--config-root', $ConfigRoot)) 'runtime installation'
$runtimeScripts = Join-Path $ConfigRoot 'scripts'
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
if ($installationMode -eq 'fresh') {
    $toml = @"
memory_root = "$(TomlString (TomlPath $MemoryRoot))"
git_root = "$(TomlString (TomlPath $requestedGitRoot))"
config_root = "$(TomlString (TomlPath $ConfigRoot))"
state_db = "$(TomlString (TomlPath $stateDb))"
audit_db = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'audit_decisions.sqlite')))"
closeout_log = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'logs\closeout.jsonl')))"
audit_run_log = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'logs\audit_runs.jsonl')))"
audit_report = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'reports\latest-audit.json')))"
python = "$(TomlString (TomlPath $venvPython))"
user_id = "$(TomlString $UserId)"
agent_id = "$(TomlString $AgentId)"
app_id = "$(TomlString $AppId)"

[closeout]
ordinary_memory_candidate_pool = false
ask_before_skill_promotion = true
run_sqlite_index_after_closeout = true
commit_scoped_memory_files = true

[observability]
enabled = true
stale_adoption_enforcement = "shadow"
shadow_min_days = 7

[shadow]
state_dir = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'shadow')))"
status = "observing"
shadow_started_at = ""
runtime_installed_at = ""
manifest_sha256 = ""
cutover_evidence_sha256 = ""
cutover_evidence_file = ""
cutover_from_config_sha256 = ""
cutover_config_backup = ""
cutover_at = ""

[write_gateway]
mode = "enforce"
writer_protocol_version = 2
state_schema_required = 4
canonical_actors = ["codex", "claude", "ailu"]
path_fencing = true
claims_are_projection = true
full_vault = true
ttl_hours = 24
max_proposal_bytes = 2097152
max_target_bytes = 8388608
max_snapshot_bytes = 262144

[semantic_retrieval]
enabled = false
semantic_mode = "auto"
ranking_version = "hybrid-v2-shadow"
vector_dir = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'zvec\memory_chunks_embeddinggemma_768')))"
embedding_model = "google/embeddinggemma-300m"
embedding_dim = 768
embedding_device = "cpu"
python = "$(TomlString (TomlPath $venvPython))"
lock_path = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'locks\zvec.lock')))"
zvec_lock_timeout_seconds = 2
zvec_max_distance = 0.72
require_local_model = false
model_revision = ""
model_manifest = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'models\embeddinggemma-300m\model-manifest.json')))"
dependency_lock = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'requirements-vector.lock')))"
candidate_pool_min = 64
candidate_pool_factor = 16
candidate_pool_scope_min = 128
candidate_pool_max = 512
embedding_worker_socket = "$(TomlString (TomlPath (Join-Path $ConfigRoot 'run\embedding.sock')))"
embedding_worker_idle_seconds = 600
embedding_worker_cold_timeout_seconds = 12
embedding_worker_warm_timeout_seconds = 2
run_vector_index_after_closeout = false
"@
    [System.IO.File]::WriteAllText($configPath, $toml, [System.Text.UTF8Encoding]::new($false))
}
$env:AGENT_MEMORY_CONFIG_FILE = $configPath
$env:AGENT_MEMORY_CONFIG_ROOT = $ConfigRoot
$memoryctl = Join-Path $runtimeScripts 'memoryctl'
function Memory-CommandArgs([string]$Command, [string[]]$Arguments) {
    return $prefix + @('-I', '-S', $memoryctl, '--actor', 'migration', $Command) + $Arguments
}
function Memory-MigrateArgs([string[]]$Arguments) {
    return Memory-CommandArgs -Command 'migrate' -Arguments $Arguments
}
if ($installationMode -eq 'upgrade') {
    $configStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
    $configBackupDir = Join-Path $ConfigRoot 'backups'
    New-Item -ItemType Directory -Force -Path $configBackupDir | Out-Null
    $configBackupPath = Join-Path $configBackupDir "agent-memory-before-v2-$configStamp.toml"
    Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('config-plan', '--json')) 'write gateway config migration plan'
    Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('config-apply', '--backup-path', $configBackupPath, '--json')) 'write gateway config migration apply'
}
$stateDbProbe = 'import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); from agent_memory_env import env_value, expand_path; print(expand_path(env_value("STATE_DB", sys.argv[2])).resolve())'
$configuredStateDb = & $python.Source @prefix -c $stateDbProbe $sourceScripts $stateDb
if ($LASTEXITCODE -ne 0) { throw "configured state path resolution failed with exit code $LASTEXITCODE" }
$stateDb = ([string]$configuredStateDb).Trim()
if ($installationMode -eq 'fresh') {
    Invoke-Checked $python.Source (Memory-CommandArgs -Command 'bootstrap' -Arguments @(
        '--memory-root', $MemoryRoot,
        '--config-root', $ConfigRoot, '--state-db', $stateDb, '--git-root', $requestedGitRoot,
        '--user-id', $UserId, '--agent-id', $AgentId, '--app-id', $AppId, '--init-git'
    )) 'vault bootstrap'
}

if ($installationMode -eq 'upgrade') {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
    $backupDir = Join-Path $ConfigRoot 'backups'
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
    $backupPath = Join-Path $backupDir "state-before-v2-$stamp.sqlite"
    Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('plan', '--json')) 'state migration plan'
    Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('apply', '--backup-path', $backupPath, '--json')) 'state migration apply'
} else {
    Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('init', '--json')) 'state v4 initialization'
}
if ($installationMode -eq 'upgrade' -and (Test-Path -LiteralPath $auditDb -PathType Leaf)) {
    $auditStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
    $auditBackupDir = Join-Path $ConfigRoot 'backups'
    New-Item -ItemType Directory -Force -Path $auditBackupDir | Out-Null
    $auditBackupPath = Join-Path $auditBackupDir "audit-before-v3-$auditStamp.sqlite"
    Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('audit-plan', '--json')) 'audit migration plan'
    Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('audit-apply', '--backup-path', $auditBackupPath, '--json')) 'audit migration apply'
} else {
    Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('audit-init', '--json')) 'audit v3 initialization'
}
Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('audit-verify', '--json')) 'audit v3 pre-publication verification'
Invoke-Checked $python.Source (Memory-MigrateArgs -Arguments @('verify', '--json')) 'state v4 pre-publication verification'

if ($InstallCodexHook) {
    $hookArgs = @('-RuntimeRoot', $ConfigRoot)
    # A published v2 runtime promises blocking automatic Stop closeout. Keep the
    # legacy switch accepted at this installer boundary, but always install the
    # safe managed policy when Codex hook installation is requested.
    $hookArgs += '-AutoCloseout'
    & (Join-Path $runtimeScripts 'install-codex-hook.ps1') @hookArgs
}
if ($InstallAuditTask) { & (Join-Path $runtimeScripts 'audit-task.ps1') install -RuntimeRoot $ConfigRoot -Python $venvPython }
$publishArgs = @('verify', '--publish-ready', '--json')
if ($InstallCodexHook) { $publishArgs += @('--require-host-hook', 'codex') } else { $publishArgs += '--no-host-hooks' }
$published = Invoke-JsonChecked $python.Source (Memory-MigrateArgs -Arguments $publishArgs) 'runtime ready strong preflight and publication'
$attestation = $published.preflight_attestation
$contentMigration = $attestation.content_migration
$expectedContentFields = @(
    'schema_version',
    'legacy_scope_documents',
    'safe_automatic_governance_documents',
    'governance_metadata_automatic_documents',
    'governance_risk_automatic_documents',
    'governance_automatic_overlap_documents',
    'governance_manual_review_documents',
    'governance_unsafe_documents',
    'temporal_failure_documents',
    'legacy_binding_sha256',
    'governance_binding_sha256',
    'governance_automatic_migration_fingerprint_sha256',
    'automatic_migration_fingerprint_sha256',
    'reason_codes'
)
$actualContentFields = @(
    $contentMigration.PSObject.Properties.Name | Sort-Object
)
$expectedContentFieldsSorted = @($expectedContentFields | Sort-Object)
if (
    $null -eq $attestation -or
    $null -eq $contentMigration -or
    -not (($contentMigration.schema_version -is [int]) -or ($contentMigration.schema_version -is [long])) -or
    $contentMigration.schema_version -ne 1 -or
    (Compare-Object $expectedContentFieldsSorted $actualContentFields).Count -ne 0
) {
    throw 'runtime ready preflight returned an invalid content migration attestation'
}
$countNames = @(
    'legacy_scope_documents',
    'safe_automatic_governance_documents',
    'governance_metadata_automatic_documents',
    'governance_risk_automatic_documents',
    'governance_automatic_overlap_documents',
    'governance_manual_review_documents',
    'governance_unsafe_documents',
    'temporal_failure_documents'
)
$counts = @{}
foreach ($countName in $countNames) {
    $rawCount = $contentMigration.$countName
    $parsedCount = [long]0
    $integerTyped = (
        ($rawCount -is [byte]) -or ($rawCount -is [sbyte]) -or
        ($rawCount -is [int16]) -or ($rawCount -is [uint16]) -or
        ($rawCount -is [int32]) -or ($rawCount -is [uint32]) -or
        ($rawCount -is [int64]) -or ($rawCount -is [uint64])
    )
    if (
        -not $integerTyped -or
        -not [long]::TryParse([string]$rawCount, [ref]$parsedCount) -or
        $parsedCount -lt 0
    ) {
        throw 'runtime ready preflight returned an invalid content migration attestation'
    }
    $counts[$countName] = $parsedCount
}
$legacyScopeCount = [long]$counts['legacy_scope_documents']
$safeGovernanceCount = [long]$counts['safe_automatic_governance_documents']
$metadataAutomaticCount = [long]$counts['governance_metadata_automatic_documents']
$riskAutomaticCount = [long]$counts['governance_risk_automatic_documents']
$overlapAutomaticCount = [long]$counts['governance_automatic_overlap_documents']
$temporalFailureCount = [long]$counts['temporal_failure_documents']
$contentMigrationRequired = $attestation.content_migration_required
$expectedReasons = @()
if ($legacyScopeCount -gt 0) { $expectedReasons += 'LEGACY_SCOPE_AUTOMATIC' }
if ($metadataAutomaticCount -gt 0) { $expectedReasons += 'GOVERNANCE_METADATA_V4_AUTOMATIC' }
if ($riskAutomaticCount -gt 0) { $expectedReasons += 'RISK_V4_AUTOMATIC' }
$rawReasons = $contentMigration.reason_codes
$reasonCodesAreArray = (
    $rawReasons -is [System.Array] -and
    $rawReasons -isnot [string] -and
    @($rawReasons | Where-Object { $_ -isnot [string] }).Count -eq 0
)
$actualReasons = if ($reasonCodesAreArray) { @($rawReasons) } else { @() }
$hashFields = @(
    'legacy_binding_sha256',
    'governance_binding_sha256',
    'governance_automatic_migration_fingerprint_sha256',
    'automatic_migration_fingerprint_sha256'
)
$invalidHashCount = @(
    $hashFields | Where-Object {
        [string]$contentMigration.$_ -notmatch '^[0-9a-f]{64}$'
    }
).Count
if ($invalidHashCount -ne 0) {
    throw 'runtime ready preflight returned an invalid content migration attestation'
}
$canonicalFingerprintPayload = (
    '{"governance_automatic_migration_fingerprint_sha256":"' +
    [string]$contentMigration.governance_automatic_migration_fingerprint_sha256 +
    '","legacy_binding_sha256":"' +
    [string]$contentMigration.legacy_binding_sha256 +
    '","schema_version":1}'
)
$computedAutomaticFingerprint = Get-Utf8Sha256Hex $canonicalFingerprintPayload
if (
    $contentMigrationRequired -isnot [bool] -or
    -not (($attestation.legacy_scope_documents -is [int]) -or ($attestation.legacy_scope_documents -is [long])) -or
    [string]$attestation.legacy_scope_documents -ne [string]$legacyScopeCount -or
    -not (($attestation.safe_automatic_governance_documents -is [int]) -or ($attestation.safe_automatic_governance_documents -is [long])) -or
    [string]$attestation.safe_automatic_governance_documents -ne [string]$safeGovernanceCount -or
    $overlapAutomaticCount -gt [Math]::Min($metadataAutomaticCount, $riskAutomaticCount) -or
    $safeGovernanceCount -ne ($metadataAutomaticCount + $riskAutomaticCount - $overlapAutomaticCount) -or
    $temporalFailureCount -gt $safeGovernanceCount -or
    $contentMigrationRequired -ne (($legacyScopeCount -gt 0) -or ($safeGovernanceCount -gt 0)) -or
    -not $reasonCodesAreArray -or
    $actualReasons.Count -ne $expectedReasons.Count -or
    ($actualReasons -join "`n") -ne ($expectedReasons -join "`n") -or
    [string]$contentMigration.automatic_migration_fingerprint_sha256 -ne $computedAutomaticFingerprint
) {
    throw 'runtime ready preflight returned an invalid content migration attestation'
}
if ($contentMigrationRequired) {
    [ordered]@{
        ok = $true
        status = 'runtime_ready_content_migration_required'
        runtime_ready = $true
        installation_complete = $false
        content_migration_required = $true
        legacy_scope_documents = $legacyScopeCount
        safe_automatic_governance_documents = $safeGovernanceCount
        content_migration = $contentMigration
        continuation = [ordered]@{
            required = $true
            reason_code = 'AUTOMATIC_CONTENT_MIGRATION_REMAINS'
            reason_codes = $actualReasons
            legacy_scope_documents = $legacyScopeCount
            safe_automatic_governance_documents = $safeGovernanceCount
            governance_metadata_automatic_documents = $metadataAutomaticCount
            governance_risk_automatic_documents = $riskAutomaticCount
            next_action = 'RUN_CONTENT_MIGRATE_THEN_RERUN_INSTALLER_STRONG_PUBLISH'
            instructions = 'Run the managed memoryctl content-migrate governance-v4/risk-v4 flow for the attested automatic debt; after Doctor reports zero automatic content debt, rerun this installer with the same roots and host-hook switches. Installation is complete only after that strong publish attests zero automatic debt.'
        }
        vault = $MemoryRoot
        runtime = $ConfigRoot
    } | ConvertTo-Json -Depth 6
} else {
    [ordered]@{
        ok = $true
        status = 'ready'
        runtime_ready = $true
        installation_complete = $true
        content_migration_required = $false
        legacy_scope_documents = 0
        safe_automatic_governance_documents = 0
        content_migration = $contentMigration
        continuation = [ordered]@{ required = $false }
        vault = $MemoryRoot
        runtime = $ConfigRoot
    } | ConvertTo-Json -Depth 6
}
