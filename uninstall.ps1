<#
.SYNOPSIS
Uninstall computer-history-mcp (and legacy computer-access-mcp) on Windows.

.DESCRIPTION
Stops running computer-history-mcp / computer-access-mcp daemons, stdio proxies,
native collectors, and key-store helpers; revokes DPAPI master keys, admin tokens,
and MCP client leases; deletes current (computer-history-mcp) and legacy
(computer-access-mcp) encrypted stores and temp fixture locks; uninstalls global
npm/pnpm links; and removes local repository build artifacts.

.EXAMPLE
.\uninstall.ps1 -DryRun

.EXAMPLE
.\uninstall.ps1

.EXAMPLE
.\uninstall.ps1 -Yes -KeepBuild

.EXAMPLE
.\uninstall.ps1 -Yes -DataDir "D:\custom\history-data"
#>
[CmdletBinding()]
param(
    [Alias('y')]
    [switch]$Yes,
    [switch]$DryRun,
    [switch]$KeepBuild,
    [string[]]$DataDir = @(),
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Usage {
    @'
Usage: .\uninstall.ps1 [options]

Stops running computer-history-mcp / computer-access-mcp processes, revokes all
DPAPI master keys, admin tokens, and MCP client leases, deletes current and legacy
encrypted stores, and removes installed CLI links and local build outputs.

Options:
  -Yes, -y              Skip interactive confirmation prompt
  -DryRun               Print planned actions without modifying anything
  -DataDir <path[]>     Also revoke keys and delete custom data directory path(s)
  -KeepBuild            Keep local build outputs (dist\, native-bin\, native build dirs)
  -Help, -h             Show this help message
'@ | Write-Output
}

if ($Help) {
    Show-Usage
    exit 0
}

$AppNames = @('computer-history-mcp', 'computer-access-mcp')
$KeyFilenames = @('admin.token', 'auth-leases.json', 'restart-resume.json', 'master.key.dpapi')
$BuildPaths = @(
    'dist',
    'native-bin',
    'native\windows\target',
    'native\macos\collector\.build',
    'native\macos\contract\.build',
    'native\macos\key-store\.build',
    'fixtures\macos\app\.build'
)

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:DataDirs = New-Object System.Collections.Generic.List[string]
$script:TempLockFiles = New-Object System.Collections.Generic.List[string]
$script:TargetProcesses = New-Object System.Collections.Generic.List[pscustomobject]
$script:TargetTasks = New-Object System.Collections.Generic.List[string]
$script:Warnings = 0

function Add-Warning([string]$Message) {
    [Console]::Error.WriteLine("warning: $Message")
    $script:Warnings++
}

function Normalize-WindowsPath([string]$RawPath) {
    if ([string]::IsNullOrWhiteSpace($RawPath)) {
        return ''
    }
    $trimmed = $RawPath.Trim()
    # Reject device paths, UNC shares, and parent-directory traversal before calling GetFullPath.
    if ($trimmed.StartsWith('\\') -or $trimmed.StartsWith('//')) {
        return $trimmed
    }
    $slashNorm = $trimmed -replace '/', '\'
    $parts = $slashNorm.Split('\')
    foreach ($part in $parts) {
        if ($part -eq '..') {
            return $slashNorm
        }
    }
    $candidatePath = if ([System.IO.Path]::IsPathRooted($trimmed)) {
        $trimmed
    } else {
        Join-Path (Get-Location).Path $trimmed
    }
    try {
        $full = [System.IO.Path]::GetFullPath($candidatePath)
    } catch {
        return ''
    }
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $root.Length) {
        $full = $full.TrimEnd('\', '/')
    }
    return $full
}

function Test-IsReparsePoint([string]$Path) {
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            return $false
        }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    } catch {
        # Fail closed if attributes cannot be inspected.
        return $true
    }
}

function Test-SafeTargetDir([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    # Must be a standard drive-rooted absolute path (no UNC, no \\?\ device prefixes).
    if ($Path -notmatch '^[A-Za-z]:\\') {
        return $false
    }
    # Refuse parent-directory traversal segments.
    foreach ($seg in $Path.Split('\')) {
        if ($seg -eq '..') {
            return $false
        }
    }
    # Never dereference or delete symlinks or NTFS junctions as data directories.
    if (Test-IsReparsePoint $Path) {
        return $false
    }

    # Require at least two path components below drive root (never C:\ or C:\Users, C:\Temp, etc.).
    $rel = $Path.Substring(3).TrimEnd('\')
    $segments = @($rel.Split('\') | Where-Object { $_ -ne '' })
    if ($segments.Count -lt 2) {
        return $false
    }

    $blocked = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in @(
        $env:USERPROFILE,
        $env:LOCALAPPDATA,
        $env:APPDATA,
        $env:TEMP,
        $env:TMP,
        $env:SystemRoot,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $ScriptDir
    )) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $norm = Normalize-WindowsPath $candidate
            if ($norm) {
                $blocked.Add($norm)
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        foreach ($sub in @('AppData', 'AppData\Local', 'AppData\Roaming', 'Documents', 'Desktop')) {
            $norm = Normalize-WindowsPath (Join-Path $env:USERPROFILE $sub)
            if ($norm) {
                $blocked.Add($norm)
            }
        }
    }
    foreach ($b in $blocked) {
        if ($Path.Equals($b, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    return $true
}

function Add-UniqueDataDir([string]$RawPath, [bool]$Strict) {
    if ([string]::IsNullOrWhiteSpace($RawPath)) {
        return
    }
    $path = Normalize-WindowsPath $RawPath
    if (-not (Test-SafeTargetDir $path)) {
        if ($Strict) {
            [Console]::Error.WriteLine("error: refusing unsafe or symlinked/junction data directory: $RawPath")
            exit 1
        }
        Add-Warning "skipping unsafe or symlinked/junction data directory: $RawPath"
        return
    }
    foreach ($existing in $script:DataDirs) {
        if ($existing.Equals($path, [System.StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }
    $script:DataDirs.Add($path)
}

function Collect-DataDirs {
    $baseDir = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($baseDir) -and -not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $baseDir = Join-Path $env:USERPROFILE 'AppData\Local'
    }
    if (-not [string]::IsNullOrWhiteSpace($baseDir)) {
        foreach ($app in $AppNames) {
            Add-UniqueDataDir (Join-Path $baseDir $app) $false
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTER_HISTORY_DATA_DIR)) {
        Add-UniqueDataDir $env:COMPUTER_HISTORY_DATA_DIR $false
    }
    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTER_ACCESS_DATA_DIR)) {
        Add-UniqueDataDir $env:COMPUTER_ACCESS_DATA_DIR $false
    }
    foreach ($custom in $DataDir) {
        if ([string]::IsNullOrWhiteSpace($custom)) {
            [Console]::Error.WriteLine('error: -DataDir requires a non-empty path')
            exit 2
        }
        Add-UniqueDataDir $custom $true
    }

    $tempDir = [System.IO.Path]::GetTempPath()
    if (-not [string]::IsNullOrWhiteSpace($tempDir) -and (Test-Path -LiteralPath $tempDir)) {
        foreach ($pattern in @('dsh-computer-history-fixture-*.lock', 'dsh-computer-access-fixture-*.lock')) {
            Get-ChildItem -LiteralPath $tempDir -Filter $pattern -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
                    $script:TempLockFiles.Add($_.FullName)
                }
            }
        }
    }
}

function Test-MatchesProjectProcess([string]$Name, [string]$CommandLine) {
    $procName = if ($Name) { $Name.ToLowerInvariant() } else { '' }
    $cmd = if ($CommandLine) { $CommandLine } else { '' }

    if ($cmd -match '(?i)uninstall\.ps1') {
        return $false
    }
    if ($procName -in @(
        'computer-history-collector.exe',
        'computer-access-collector.exe',
        'computer-history-key-store.exe',
        'computer-access-key-store.exe'
    )) {
        return $true
    }
    if ($procName -eq 'node.exe' -and $cmd -match '(?i)(computer-history-mcp|computer-access-mcp|dist[\\/]server[\\/]cli\.js|src[\\/]server[\\/]cli\.ts)["'']?\s+(serve|stdio)(\s|$)') {
        return $true
    }
    return $false
}

function Collect-RunningProcesses {
    $parentPid = 0
    try {
        $selfProc = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction SilentlyContinue
        if ($selfProc) {
            $parentPid = [int]$selfProc.ParentProcessId
        }
    } catch {
        $parentPid = 0
    }

    $allProcs = @()
    try {
        $allProcs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    } catch {
        Add-Warning "failed to enumerate running processes via Win32_Process: $($_.Exception.Message)"
        return
    }

    foreach ($p in $allProcs) {
        $pidVal = [int]$p.ProcessId
        if ($pidVal -eq $PID -or ($parentPid -gt 0 -and $pidVal -eq $parentPid)) {
            continue
        }
        $name = if ($null -ne $p.Name) { [string]$p.Name } else { '' }
        $cmd = if ($null -ne $p.CommandLine) { [string]$p.CommandLine } else { '' }
        if (Test-MatchesProjectProcess $name $cmd) {
            $displayCmd = if ($cmd) { $cmd } else { $name }
            $script:TargetProcesses.Add([pscustomobject]@{
                ProcessId   = $pidVal
                Name        = $name
                CommandLine = $displayCmd
            })
        }
    }
}

function Collect-ScheduledTasks {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        return
    }
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -match '(?i)^(computer-history-mcp|computer-access-mcp)'
        } | ForEach-Object {
            $script:TargetTasks.Add($_.TaskName)
        }
    } catch {
        # Ignore restricted Task Scheduler environments.
    }
}

function Test-IsRepoCheckout {
    $pkgJson = Join-Path $ScriptDir 'package.json'
    if (-not (Test-Path -LiteralPath $pkgJson -PathType Leaf)) {
        return $false
    }
    try {
        $raw = Get-Content -LiteralPath $pkgJson -Raw -ErrorAction Stop
        return ($raw -match '"name"\s*:\s*"(computer-history-mcp|computer-access-mcp)"')
    } catch {
        return $false
    }
}

function Show-Plan {
    Write-Output 'computer-history-mcp uninstall plan (Windows)'
    Write-Output '---------------------------------------------'

    if ($script:TargetProcesses.Count -gt 0) {
        Write-Output "Running processes to stop ($($script:TargetProcesses.Count)):"
        foreach ($p in $script:TargetProcesses) {
            Write-Output "  - PID $($p.ProcessId): $($p.CommandLine)"
        }
    } else {
        Write-Output 'Running processes to stop: none'
    }

    if ($script:TargetTasks.Count -gt 0) {
        Write-Output "Scheduled tasks to remove ($($script:TargetTasks.Count)):"
        foreach ($t in $script:TargetTasks) {
            Write-Output "  - $t"
        }
    }

    Write-Output 'Data directories (DPAPI keys, tokens, leases, and encrypted stores) to delete:'
    if ($script:DataDirs.Count -gt 0) {
        foreach ($dir in $script:DataDirs) {
            if (Test-Path -LiteralPath $dir -PathType Container) {
                Write-Output "  - $dir (exists)"
            } else {
                Write-Output "  - $dir (not present)"
            }
        }
    } else {
        Write-Output '  - none'
    }

    if ($script:TempLockFiles.Count -gt 0) {
        Write-Output "Temporary fixture lock files to delete ($($script:TempLockFiles.Count)):"
        $previewCount = [Math]::Min(5, $script:TempLockFiles.Count)
        for ($i = 0; $i -lt $previewCount; $i++) {
            Write-Output "  - $($script:TempLockFiles[$i])"
        }
        if ($script:TempLockFiles.Count -gt $previewCount) {
            Write-Output "  - ... and $($script:TempLockFiles.Count - $previewCount) more"
        }
    }

    Write-Output 'Package / build cleanup:'
    Write-Output "  - Global npm/pnpm links for: $($AppNames -join ', ') (if installed)"
    if ($KeepBuild) {
        Write-Output '  - Local repo build artifacts: kept (-KeepBuild)'
    } elseif (Test-IsRepoCheckout) {
        Write-Output "  - Local repo build artifacts under ${ScriptDir}: dist\, native-bin\, native\windows\target\"
    } else {
        Write-Output '  - Local repo build artifacts: skipped (not running inside repository root)'
    }
}

function Stop-TargetProcesses {
    Write-Output '[1/4] Stopping running processes and scheduled tasks...'
    if ($script:TargetTasks.Count -gt 0) {
        foreach ($taskName in $script:TargetTasks) {
            if ($DryRun) {
                Write-Output "  [dry-run] would unregister scheduled task: $taskName"
            } else {
                try {
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                    Write-Output "  unregistered scheduled task: $taskName"
                } catch {
                    Add-Warning "failed to unregister scheduled task '$taskName': $($_.Exception.Message)"
                }
            }
        }
    }

    if ($script:TargetProcesses.Count -eq 0) {
        Write-Output '  no matching processes running'
        return
    }

    # Stop Node serve/stdio supervisors FIRST so they cannot respawn collectors,
    # then stop any remaining native collectors and key-store helpers.
    $orderedProcesses = @(
        $script:TargetProcesses | Where-Object { $_.Name -ieq 'node.exe' }
        $script:TargetProcesses | Where-Object { $_.Name -ine 'node.exe' }
    )
    foreach ($p in $orderedProcesses) {
        if ($DryRun) {
            Write-Output "  [dry-run] would stop PID $($p.ProcessId) ($($p.Name))"
            continue
        }
        $proc = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) {
            Write-Output "  already exited PID $($p.ProcessId)"
            continue
        }
        try {
            $null = $proc.CloseMainWindow()
        } catch {
            # Console/headless processes have no main window.
        }
    }

    if ($DryRun) {
        return
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(2)
    while ([DateTime]::UtcNow -lt $deadline) {
        $anyAlive = $false
        foreach ($p in $orderedProcesses) {
            if (Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue) {
                $anyAlive = $true
                break
            }
        }
        if (-not $anyAlive) {
            break
        }
        Start-Sleep -Milliseconds 150
    }

    foreach ($p in $orderedProcesses) {
        $proc = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
        if ($proc) {
            try {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
                Write-Output "  stopped PID $($p.ProcessId) ($($p.Name))"
            } catch {
                Add-Warning "failed to stop PID $($p.ProcessId) ($($p.Name)): $($_.Exception.Message)"
            }
        } else {
            Write-Output "  stopped PID $($p.ProcessId) ($($p.Name))"
        }
    }
}

function Remove-CredentialFileSecurely([string]$FilePath) {
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return
    }
    if ($DryRun) {
        Write-Output "  [dry-run] would revoke/remove $FilePath"
        return
    }
    if (Test-IsReparsePoint $FilePath) {
        # Never follow symlinks when wiping; remove only the link itself.
        try {
            Remove-Item -LiteralPath $FilePath -Force -ErrorAction Stop
            Write-Output "  removed link $FilePath"
        } catch {
            Add-Warning "failed to remove link ${FilePath}: $($_.Exception.Message)"
        }
        return
    }
    try {
        $fi = Get-Item -LiteralPath $FilePath -Force -ErrorAction Stop
        if ($fi.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
            $fi.Attributes = $fi.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
        }
        if (-not $fi.PSIsContainer -and $fi.Length -gt 0 -and $fi.Length -le 1048576) {
            $zeros = New-Object byte[] ([int]$fi.Length)
            [System.IO.File]::WriteAllBytes($FilePath, $zeros)
        }
        Remove-Item -LiteralPath $FilePath -Force -ErrorAction Stop
        Write-Output "  revoked $FilePath"
    } catch {
        Add-Warning "failed to revoke ${FilePath}: $($_.Exception.Message)"
    }
}

function Revoke-Keys {
    Write-Output '[2/4] Revoking DPAPI master keys, admin tokens, and MCP client leases...'
    $revokedAny = $false
    foreach ($dir in $script:DataDirs) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
            continue
        }
        if (Test-IsReparsePoint $dir) {
            Add-Warning "refusing to traverse reparse point directory: $dir"
            continue
        }
        foreach ($keyFile in $KeyFilenames) {
            $target = Join-Path $dir $keyFile
            if (Test-Path -LiteralPath $target) {
                $revokedAny = $true
                Remove-CredentialFileSecurely $target
            }
        }
    }
    if (-not $revokedAny) {
        Write-Output '  no key, token, or lease files found'
    }
}

function Remove-Stores {
    Write-Output '[3/4] Deleting current and legacy history stores and runtime locks...'
    foreach ($dir in $script:DataDirs) {
        if (-not (Test-Path -LiteralPath $dir)) {
            Write-Output "  not present: $dir"
            continue
        }
        if (-not (Test-SafeTargetDir $dir)) {
            Add-Warning "refusing to delete unsafe path: $dir"
            continue
        }
        if ($DryRun) {
            Write-Output "  [dry-run] would delete data directory: $dir"
            continue
        }
        $childReparse = @(Get-ChildItem -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        })
        if ($childReparse.Count -gt 0) {
            Add-Warning "refusing recursive delete on $dir because it contains a symlink/junction: $($childReparse[0].FullName)"
            continue
        }
        try {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
            Write-Output "  deleted data directory: $dir"
        } catch {
            Add-Warning "failed to delete data directory ${dir}: $($_.Exception.Message)"
        }
    }

    if ($script:TempLockFiles.Count -gt 0) {
        if ($DryRun) {
            Write-Output "  [dry-run] would delete $($script:TempLockFiles.Count) temp fixture lock file(s)"
        } else {
            $deletedLocks = 0
            foreach ($lockFile in $script:TempLockFiles) {
                if (-not (Test-Path -LiteralPath $lockFile)) {
                    continue
                }
                if (Test-IsReparsePoint $lockFile) {
                    Add-Warning "skipping reparse point lock file: $lockFile"
                    continue
                }
                try {
                    Remove-Item -LiteralPath $lockFile -Force -ErrorAction Stop
                    $deletedLocks++
                } catch {
                    Add-Warning "failed to delete temp lock file ${lockFile}: $($_.Exception.Message)"
                }
            }
            Write-Output "  deleted $deletedLocks temp fixture lock file(s)"
        }
    }
}

function Uninstall-PackagesAndBuilds {
    Write-Output '[4/4] Uninstalling global CLI packages and local build artifacts...'
    $removedAny = $false

    if (Get-Command pnpm -ErrorAction SilentlyContinue) {
        $pnpmRoot = ''
        try {
            $pnpmRoot = (& pnpm root -g 2>$null | Select-Object -First 1)
            if ($pnpmRoot) { $pnpmRoot = $pnpmRoot.Trim() }
        } catch {
            $pnpmRoot = ''
        }
        if (-not [string]::IsNullOrWhiteSpace($pnpmRoot)) {
            foreach ($pkg in $AppNames) {
                $pkgPath = Join-Path $pnpmRoot $pkg
                if (Test-Path -LiteralPath $pkgPath) {
                    $removedAny = $true
                    if ($DryRun) {
                        Write-Output "  [dry-run] would run: pnpm remove -g $pkg"
                    } else {
                        & pnpm remove -g $pkg *> $null
                        if ($LASTEXITCODE -eq 0) {
                            Write-Output "  removed global pnpm package: $pkg"
                        } else {
                            Add-Warning "pnpm remove -g $pkg failed (exit code $LASTEXITCODE)"
                        }
                    }
                }
            }
        }
    }

    if (Get-Command npm -ErrorAction SilentlyContinue) {
        $npmRoot = ''
        try {
            $npmRoot = (& npm root -g 2>$null | Select-Object -First 1)
            if ($npmRoot) { $npmRoot = $npmRoot.Trim() }
        } catch {
            $npmRoot = ''
        }
        if (-not [string]::IsNullOrWhiteSpace($npmRoot)) {
            foreach ($pkg in $AppNames) {
                $pkgPath = Join-Path $npmRoot $pkg
                if (Test-Path -LiteralPath $pkgPath) {
                    $removedAny = $true
                    if ($DryRun) {
                        Write-Output "  [dry-run] would run: npm uninstall -g $pkg"
                    } else {
                        & npm uninstall -g $pkg *> $null
                        if ($LASTEXITCODE -eq 0) {
                            Write-Output "  removed global npm package: $pkg"
                        } else {
                            Add-Warning "npm uninstall -g $pkg failed (exit code $LASTEXITCODE)"
                        }
                    }
                }
            }
        }
    }

    if (-not $KeepBuild -and (Test-IsRepoCheckout)) {
        foreach ($rel in $BuildPaths) {
            $target = Join-Path $ScriptDir $rel
            if ((Test-Path -LiteralPath $target) -and (-not (Test-IsReparsePoint $target))) {
                $removedAny = $true
                if ($DryRun) {
                    Write-Output "  [dry-run] would delete build directory: $target"
                } else {
                    try {
                        Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
                        Write-Output "  deleted build directory: $target"
                    } catch {
                        Add-Warning "failed to delete build directory ${target}: $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    if (-not $removedAny) {
        Write-Output '  no global CLI packages or local build outputs found'
    }
}

# Main execution
Collect-DataDirs
Collect-RunningProcesses
Collect-ScheduledTasks
Show-Plan
Write-Output ''

if (-not $DryRun -and -not $Yes) {
    $isInteractive = [Environment]::UserInteractive -and (-not [Console]::IsInputRedirected)
    if (-not $isInteractive) {
        [Console]::Error.WriteLine('error: non-interactive stdin; re-run with -Yes to confirm deletion or -DryRun to preview')
        exit 1
    }
    $reply = Read-Host 'This permanently revokes all DPAPI keys/tokens and deletes retained history stores. Continue? [y/N]'
    if ($reply -notin @('y', 'Y', 'yes', 'YES', 'Yes')) {
        Write-Output 'Aborted. No files, processes, or keys were modified.'
        exit 0
    }
    Write-Output ''
}

Stop-TargetProcesses
Revoke-Keys
Remove-Stores
Uninstall-PackagesAndBuilds

Write-Output ''
if ($DryRun) {
    Write-Output 'Dry run complete. No files, processes, or keys were modified.'
} elseif ($script:Warnings -gt 0) {
    Write-Output "Uninstall finished with $($script:Warnings) warning(s); review the messages above."
} else {
    Write-Output 'Uninstall complete.'
}

@'

Manual follow-up (optional):
  - Remove "computer-history" / "computer-access" entries from your AI client MCP config (Antigravity, Claude, Cursor).
  - Delete the cloned repository folder if you do not plan to rebuild from source.
'@ | Write-Output

if ($script:Warnings -gt 0 -and -not $DryRun) {
    exit 1
}
