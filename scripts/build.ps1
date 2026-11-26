#Requires -Version 5.1
<#
.SYNOPSIS
    Checks, tests and builds Predator Remote Controller and assembles the single-file release.

.DESCRIPTION
    Runs, in order, stopping at the first failure:
      1. cargo fmt --all -- --check
      2. cargo check --all-targets
      3. cargo test --all-targets
      4. cargo clippy --all-targets -- -D warnings
      5. cargo build --release --target x86_64-pc-windows-msvc --bin predator-tray
      6. cargo build --release --target x86_64-pc-windows-msvc --bin predator-service --features embed-tray
         (with PREDATOR_EMBED_TRAY = the tray from step 5, which is embedded into the service exe)
    Then it writes the release folder (default .\dist):
      PredatorRemoteController.exe   the whole program in one file (service + setup + embedded tray)
      SHA256SUMS.txt                 SHA-256 of every file in the folder
      README.md, LICENSE             copied from the repository
    and verifies the result: the exe runs 'version', and the tray it extracts with the hidden
    'extract-tray' diagnostic is byte-identical to the tray built in step 5.

    Nothing is installed and no service is touched. To install, start the exe (double-click).

.PARAMETER OutDir
    Release folder. Default: <repo>\dist (recreated on every run).

.PARAMETER SkipChecks
    Only run the release builds (skips fmt, check, test and clippy). For quick local iterations.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1

.NOTES
    Exit code: 0 = success, otherwise the failing cargo exit code (or 1).
    Honours CARGO_TARGET_DIR.
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [switch]$SkipChecks
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$Target = 'x86_64-pc-windows-msvc'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ReleaseExe = 'PredatorRemoteController.exe'
$EmbedVar = 'PREDATOR_EMBED_TRAY'

function Write-Step([string]$Message) {
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Quotes one argument following the CommandLineToArgvW rules.
function ConvertTo-QuotedArgument([string]$Value) {
    if ($null -eq $Value) { $Value = '' }
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $slashes = 0
    foreach ($c in $Value.ToCharArray()) {
        if ($c -eq [char]'\') {
            $slashes++
            continue
        }
        if ($c -eq [char]'"') {
            [void]$sb.Append([char]'\', (2 * $slashes + 1))
            [void]$sb.Append([char]'"')
        }
        else {
            if ($slashes -gt 0) { [void]$sb.Append([char]'\', $slashes) }
            [void]$sb.Append($c)
        }
        $slashes = 0
    }
    if ($slashes -gt 0) { [void]$sb.Append([char]'\', (2 * $slashes)) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Join-CommandLine([string[]]$Arguments) {
    if ($null -eq $Arguments -or $Arguments.Count -eq 0) { return '' }
    return (@($Arguments | ForEach-Object { ConvertTo-QuotedArgument $_ }) -join ' ')
}

# Runs a program attached to this console (live output) in $RepoRoot; returns its exit code.
# The child inherits this process's environment (including PREDATOR_EMBED_TRAY when set).
function Invoke-Exe {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = Join-CommandLine $Arguments
    $psi.UseShellExecute = $false
    $psi.WorkingDirectory = $RepoRoot
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        [void]$proc.Start()
        $proc.WaitForExit()
        return $proc.ExitCode
    }
    finally {
        $proc.Dispose()
    }
}

# Runs a program and captures stdout as UTF-8 (stderr stays on the console). Returns @{ExitCode; Output}.
function Invoke-ExeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = Join-CommandLine $Arguments
    $psi.UseShellExecute = $false
    $psi.WorkingDirectory = $RepoRoot
    $psi.RedirectStandardOutput = $true
    $psi.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        [void]$proc.Start()
        $stdout = $proc.StandardOutput.ReadToEndAsync()
        $proc.WaitForExit()
        return @{ ExitCode = $proc.ExitCode; Output = $stdout.Result }
    }
    finally {
        $proc.Dispose()
    }
}

function Get-CargoPath {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path -LiteralPath $cargoBin -PathType Container) {
        $parts = @($env:PATH -split ';' | ForEach-Object { $_.TrimEnd('\') })
        if ($parts -notcontains $cargoBin.TrimEnd('\')) { $env:PATH = "$cargoBin;$env:PATH" }
    }
    $cmd = Get-Command cargo -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $cmd) {
        throw 'cargo was not found. Install Rust from https://rustup.rs (MSVC toolchain + Visual Studio Build Tools with the Windows SDK).'
    }
    return $cmd.Source
}

# @{ TargetDir; Version } from cargo metadata (falls back to CARGO_TARGET_DIR / .\target).
function Get-CargoInfo([string]$Cargo) {
    $info = @{ TargetDir = $null; Version = $null }
    $r = Invoke-ExeCapture -FilePath $Cargo -Arguments @('metadata', '--format-version', '1', '--no-deps')
    if ($r.ExitCode -eq 0) {
        try {
            $meta = $r.Output | ConvertFrom-Json
            if ($meta.target_directory) { $info.TargetDir = [string]$meta.target_directory }
            $pkg = @($meta.packages | Where-Object { $_.name -eq 'predator' }) | Select-Object -First 1
            if ($null -ne $pkg) { $info.Version = [string]$pkg.version }
        }
        catch {
            Write-Host '    cargo metadata returned unexpected output; using the default target folder.' -ForegroundColor Yellow
        }
    }
    if ($null -eq $info.TargetDir) {
        if (-not [string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
            $info.TargetDir = if ([System.IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) { $env:CARGO_TARGET_DIR } else { Join-Path $RepoRoot $env:CARGO_TARGET_DIR }
        }
        else {
            $info.TargetDir = Join-Path $RepoRoot 'target'
        }
    }
    return $info
}

function Format-Duration([TimeSpan]$Span) {
    if ($Span.TotalMinutes -ge 1) { return ('{0}m {1:00}s' -f [int][Math]::Floor($Span.TotalMinutes), $Span.Seconds) }
    return ('{0:0.0}s' -f $Span.TotalSeconds)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# One cargo step: @(name, args, hint). Returns the cargo exit code (0 = ok).
function Invoke-CargoStep([string]$Cargo, $Step, [int]$Index, [int]$Count) {
    $name = $Step[0]
    $cargoArgs = [string[]]$Step[1]
    $hint = $Step[2]
    Write-Step "[$Index/$Count] $name"
    Write-Host "    cargo $($cargoArgs -join ' ')"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $code = Invoke-Exe -FilePath $Cargo -Arguments $cargoArgs
    $sw.Stop()
    if ($code -ne 0) {
        Write-Host ''
        Write-Host "BUILD FAILED at step ${Index}/${Count}: $name (cargo exit code $code, after $(Format-Duration $sw.Elapsed))." -ForegroundColor Red
        Write-Host "Hint: $hint" -ForegroundColor Yellow
        if ($code -gt 0) { return $code }
        return 1
    }
    Write-Host "    [OK] $name ($(Format-Duration $sw.Elapsed))" -ForegroundColor Green
    return 0
}

function Invoke-Build {
    $cargo = Get-CargoPath
    Write-Host "Predator build - repo: $RepoRoot"
    Write-Host "cargo: $cargo"
    $info = Get-CargoInfo $cargo
    $releaseDir = Join-Path $info.TargetDir "$Target\release"
    $trayBuilt = Join-Path $releaseDir 'predator-tray.exe'
    $serviceBuilt = Join-Path $releaseDir 'predator-service.exe'

    $checks = @()
    if (-not $SkipChecks) {
        $checks += , @('Formatting (cargo fmt --check)', @('fmt', '--all', '--', '--check'), 'Run "cargo fmt --all" to fix the formatting. If rustfmt is missing: rustup component add rustfmt')
        $checks += , @('Type check (cargo check --all-targets)', @('check', '--all-targets'), 'Fix the compile errors listed above.')
        $checks += , @('Tests (cargo test --all-targets)', @('test', '--all-targets'), 'Fix the failing tests listed above.')
        $checks += , @('Lints (cargo clippy -D warnings)', @('clippy', '--all-targets', '--', '-D', 'warnings'), 'Fix the clippy warnings above. If clippy is missing: rustup component add clippy')
    }
    $trayStep = @('Release build: tray', @('build', '--release', '--target', $Target, '--bin', 'predator-tray'), "If the target is missing: rustup target add $Target")
    $serviceStep = @('Release build: service with the embedded tray', @('build', '--release', '--target', $Target, '--bin', 'predator-service', '--features', 'embed-tray'), "$EmbedVar must name the tray built in the previous step.")
    $count = $checks.Count + 2

    $index = 0
    foreach ($step in $checks) {
        $index++
        $code = Invoke-CargoStep $cargo $step $index $count
        if ($code -ne 0) { return $code }
    }
    $index++
    $code = Invoke-CargoStep $cargo $trayStep $index $count
    if ($code -ne 0) { return $code }
    if (-not (Test-Path -LiteralPath $trayBuilt -PathType Leaf)) { throw "Build output '$trayBuilt' is missing." }

    $index++
    $previous = [Environment]::GetEnvironmentVariable($EmbedVar, 'Process')
    try {
        [Environment]::SetEnvironmentVariable($EmbedVar, $trayBuilt, 'Process')
        $code = Invoke-CargoStep $cargo $serviceStep $index $count
    }
    finally {
        [Environment]::SetEnvironmentVariable($EmbedVar, $previous, 'Process')
    }
    if ($code -ne 0) { return $code }
    if (-not (Test-Path -LiteralPath $serviceBuilt -PathType Leaf)) { throw "Build output '$serviceBuilt' is missing." }

    Write-Step 'Assembling the release folder'
    $defaultOut = Join-Path $RepoRoot 'dist'
    $out = if ([string]::IsNullOrWhiteSpace($OutDir)) { $defaultOut } else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir) }
    $out = [System.IO.Path]::GetFullPath($out).TrimEnd('\')
    $outRoot = [System.IO.Path]::GetPathRoot($out)
    if ($out.Length -le $outRoot.TrimEnd('\').Length -or $out -ieq $RepoRoot.TrimEnd('\')) {
        throw "OutDir '$out' must be a dedicated folder (not a drive root or the repository root)."
    }
    if (Test-Path -LiteralPath $out) {
        # Emptying a junction / symbolic link would delete the files of its target.
        $outItem = Get-Item -LiteralPath $out -Force
        if (-not $outItem.PSIsContainer -or ($outItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "OutDir '$out' is a file, junction or symbolic link. Use a plain folder."
        }
        # Only a folder this script made (or an empty one) is emptied.
        $known = @($ReleaseExe, 'SHA256SUMS.txt', 'README.md', 'LICENSE')
        $foreign = @(Get-ChildItem -LiteralPath $out -Force | Where-Object { $known -notcontains $_.Name })
        if ($out -ieq $defaultOut -or $foreign.Count -eq 0) {
            Get-ChildItem -LiteralPath $out -Force | Remove-Item -Recurse -Force
        }
        else {
            throw "OutDir '$out' contains other files ($(($foreign | Select-Object -First 3 | ForEach-Object Name) -join ', ')). Use an empty folder."
        }
    }
    [void](New-Item -ItemType Directory -Path $out -Force)

    $files = New-Object System.Collections.Generic.List[string]
    Copy-Item -LiteralPath $serviceBuilt -Destination (Join-Path $out $ReleaseExe) -Force
    $files.Add($ReleaseExe)
    foreach ($doc in @('README.md', 'LICENSE')) {
        $src = Join-Path $RepoRoot $doc
        if (Test-Path -LiteralPath $src -PathType Leaf) {
            Copy-Item -LiteralPath $src -Destination (Join-Path $out $doc) -Force
            $files.Add($doc)
        }
        else {
            Write-Host "    [WARN] $doc not found in the repository; not included." -ForegroundColor Yellow
        }
    }
    $rows = foreach ($f in $files) {
        $full = Join-Path $out $f
        $item = Get-Item -LiteralPath $full
        [pscustomobject]@{
            File      = $f
            'Size KB' = [Math]::Round($item.Length / 1KB, 1)
            Bytes     = $item.Length
            SHA256    = Get-Sha256 $full
        }
    }
    $sums = @($rows | ForEach-Object { "$($_.SHA256) *$($_.File)" })
    Set-Content -LiteralPath (Join-Path $out 'SHA256SUMS.txt') -Value $sums -Encoding ASCII

    Write-Step 'Verifying the release file'
    $exe = Join-Path $out $ReleaseExe
    $v = Invoke-ExeCapture -FilePath $exe -Arguments @('version')
    $versionText = ([string]$v.Output).Trim()
    if ($v.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($versionText)) {
        throw "'$ReleaseExe version' failed (exit code $($v.ExitCode))."
    }
    if ($null -ne $info.Version -and -not $versionText.EndsWith($info.Version)) {
        throw "'$ReleaseExe version' printed '$versionText', expected version $($info.Version) (Cargo.toml)."
    }
    Write-Host "    [OK] $versionText" -ForegroundColor Green
    $h = Invoke-ExeCapture -FilePath $exe -Arguments @('help')
    if ($h.ExitCode -ne 0 -or -not ([string]$h.Output).Contains('setup')) { throw "'$ReleaseExe help' failed (exit code $($h.ExitCode))." }
    Write-Host '    [OK] help'
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('predator-verify-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $tmp)
    try {
        $extracted = Join-Path $tmp 'predator-tray.exe'
        $x = Invoke-ExeCapture -FilePath $exe -Arguments @('extract-tray', $extracted)
        if ($x.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $extracted -PathType Leaf)) {
            throw "'$ReleaseExe extract-tray' failed (exit code $($x.ExitCode)): the tray is not embedded."
        }
        $trayHash = Get-Sha256 $trayBuilt
        if ((Get-Sha256 $extracted) -ne $trayHash) { throw 'The embedded tray differs from the tray that was built.' }
        Write-Host "    [OK] embedded tray = built tray (SHA-256 $trayHash)" -ForegroundColor Green
    }
    finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host "Release folder: $out" -ForegroundColor Green
    $rows | Format-Table -AutoSize -Property File, 'Size KB', Bytes, SHA256 | Out-String -Width 220 | Write-Host
    $trayKb = (Get-Item -LiteralPath $trayBuilt).Length / 1KB
    Write-Host ('{0}: {1:N1} KB (of which the embedded tray: {2:N1} KB)' -f $ReleaseExe, ((Get-Item -LiteralPath $exe).Length / 1KB), $trayKb)
    Write-Host 'Checksums written to SHA256SUMS.txt'
    Write-Host ''
    Write-Host "Install: start $ReleaseExe (double-click). It asks for administrator rights, then installs" -ForegroundColor White
    Write-Host 'itself (bot token, pairing, service, tray). Start it again later for the management menu.'
    return 0
}

$exitCode = 1
try {
    $exitCode = Invoke-Build
    if ($exitCode -eq 0) { Write-Host 'BUILD SUCCEEDED' -ForegroundColor Green }
}
catch {
    Write-Host ''
    Write-Host "BUILD FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
exit $exitCode
