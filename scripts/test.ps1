#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the automated tests and, when the service is installed, its built-in self-test.

.DESCRIPTION
    1. cargo test --all-targets            (unit + integration tests, no side effects)
       With -Ignored the #[ignore] tests run too ("-- --include-ignored"). Those are live probes of
       this PC (event log access, network/battery/Tailscale status, Telegram with an invalid token).
       Two of them write test entries: one event (source PredatorSpinTest) to the Application log
       and a few failed SSH logins for the fake user predator-spin-test against the local sshd,
       which an installed service reports as alerts. They never shut down, lock, change settings
       or use a real token.
    2. predator-service.exe selftest       (only when the Predator service is installed; run this
       script from an elevated PowerShell so the self-test can read the protected data folder)

.PARAMETER Ignored
    Also run the #[ignore] live tests (see above).

.PARAMETER NoSelftest
    Skip the installed service's self-test.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test.ps1 -Ignored

.NOTES
    Exit code: 0 = everything passed, 1 = something failed.
#>
[CmdletBinding()]
param(
    [switch]$Ignored,
    [switch]$NoSelftest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ServiceName = 'PredatorRemoteController'

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

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CargoPath {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path -LiteralPath $cargoBin -PathType Container) {
        $parts = @($env:PATH -split ';' | ForEach-Object { $_.TrimEnd('\') })
        if ($parts -notcontains $cargoBin.TrimEnd('\')) { $env:PATH = "$cargoBin;$env:PATH" }
    }
    $cmd = Get-Command cargo -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $cmd) { throw 'cargo was not found. Install Rust from https://rustup.rs.' }
    return $cmd.Source
}

function Get-InstalledServiceExe {
    try {
        $info = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    }
    catch {
        return $null
    }
    if ($null -eq $info -or [string]::IsNullOrWhiteSpace($info.PathName)) { return $null }
    $c = $info.PathName.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -le 1) { return $null }
        $c = $c.Substring(1, $end - 1)
    }
    else {
        $idx = $c.IndexOf('.exe', [System.StringComparison]::OrdinalIgnoreCase)
        if ($idx -ge 0) { $c = $c.Substring(0, $idx + 4) }
    }
    if (Test-Path -LiteralPath $c -PathType Leaf) { return $c }
    return $null
}

$results = New-Object System.Collections.Generic.List[object]
$failed = $false
try {
    $cargo = Get-CargoPath
    $testArgs = @('test', '--all-targets')
    if ($Ignored) { $testArgs += @('--', '--include-ignored') }
    Write-Step "cargo $($testArgs -join ' ')"
    $code = Invoke-Exe -FilePath $cargo -Arguments $testArgs
    $results.Add([pscustomobject]@{ Step = "cargo $($testArgs -join ' ')"; Result = $(if ($code -eq 0) { 'PASSED' } else { "FAILED (exit code $code)" }) })
    if ($code -ne 0) { $failed = $true }

    if ($NoSelftest) {
        $results.Add([pscustomobject]@{ Step = 'predator-service.exe selftest'; Result = 'skipped (-NoSelftest)' })
    }
    else {
        $exe = Get-InstalledServiceExe
        if ($null -eq $exe) {
            $results.Add([pscustomobject]@{ Step = 'predator-service.exe selftest'; Result = 'skipped (service not installed)' })
        }
        else {
            Write-Step "$exe selftest"
            $admin = Test-IsAdmin
            if (-not $admin) {
                Write-Host '    Note: not elevated - checks that read the protected data folder may fail.' -ForegroundColor Yellow
            }
            $code = Invoke-Exe -FilePath $exe -Arguments @('selftest')
            if ($code -eq 0) {
                $results.Add([pscustomobject]@{ Step = 'predator-service.exe selftest'; Result = 'PASSED' })
            }
            elseif ($admin) {
                $results.Add([pscustomobject]@{ Step = 'predator-service.exe selftest'; Result = "FAILED (exit code $code)" })
                $failed = $true
            }
            else {
                $results.Add([pscustomobject]@{ Step = 'predator-service.exe selftest'; Result = "FAILED (exit code $code) - re-run elevated" })
            }
        }
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    $failed = $true
}

Write-Host ''
Write-Host '==================== Test summary ====================' -ForegroundColor White
$results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
if ($failed) {
    Write-Host 'TESTS FAILED' -ForegroundColor Red
    exit 1
}
Write-Host 'ALL TESTS PASSED' -ForegroundColor Green
exit 0
