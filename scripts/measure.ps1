#Requires -Version 5.1
<#
.SYNOPSIS
    Measures the CPU and memory use of the installed Predator service and tray app.

.DESCRIPTION
    Samples the running predator-service.exe (found through the SCM) and every running
    predator-tray.exe every -IntervalSeconds for -Seconds, then prints a Markdown table with:
      * average CPU % over the whole run (CPU time delta / wall time / logical CPUs) and the
        highest CPU % of any single sampling interval;
      * private bytes and working set (min / avg / max, MB);
      * thread and handle counts (min - max).
    Get-Process provides memory, threads and handles. When it cannot read the CPU time of the
    LocalSystem service (normal without elevation) the script uses Win32_Process
    KernelModeTime + UserModeTime instead, which needs no admin rights.

    The script only reads process counters; it never changes anything. Leave the PC idle while
    measuring to get the idle footprint.

.PARAMETER Seconds
    Measurement duration (default 300).

.PARAMETER IntervalSeconds
    Sampling interval (default 5).

.PARAMETER OutFile
    Optional path of a Markdown file to write the result to.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure.ps1 -Seconds 300 -OutFile .\measure.md

.NOTES
    Exit code: 0 = measured, 1 = the service is not running or could not be measured.
#>
[CmdletBinding()]
param(
    [ValidateRange(10, 86400)]
    [int]$Seconds = 300,
    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 5,
    [string]$OutFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ServiceName = 'PredatorRemoteController'
$TrayProcessName = 'predator-tray'
$Inv = [System.Globalization.CultureInfo]::InvariantCulture

function Format-Num([double]$Value, [int]$Decimals) {
    return $Value.ToString("F$Decimals", $Inv)
}

function New-Target([string]$Label, [int]$ProcessId) {
    return [pscustomobject]@{
        Label     = $Label
        ProcessId = $ProcessId
        CpuSource = $null
        Samples   = New-Object System.Collections.Generic.List[object]
        Exited    = $false
    }
}

# CPU time in milliseconds from Win32_Process (works for SYSTEM processes without elevation).
function Get-WmiCpuMs([int]$ProcessId) {
    $w = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId" -Property KernelModeTime, UserModeTime -ErrorAction SilentlyContinue
    if ($null -eq $w) { return $null }
    return ([double]$w.KernelModeTime + [double]$w.UserModeTime) / 10000.0
}

function Add-Sample($Target, [double]$ElapsedSeconds) {
    if ($Target.Exited) { return }
    $p = Get-Process -Id $Target.ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $p) {
        $Target.Exited = $true
        Write-Host "    $($Target.Label) (PID $($Target.ProcessId)) exited during the measurement." -ForegroundColor Yellow
        return
    }
    $cpuMs = $null
    if ($Target.CpuSource -ne 'wmi') {
        $tpt = $null
        try { $tpt = $p.TotalProcessorTime } catch { $tpt = $null }
        if ($null -ne $tpt) {
            $cpuMs = $tpt.TotalMilliseconds
            $Target.CpuSource = 'process'
        }
        elseif ($null -eq $Target.CpuSource) {
            $Target.CpuSource = 'wmi'
        }
    }
    if ($Target.CpuSource -eq 'wmi') { $cpuMs = Get-WmiCpuMs $Target.ProcessId }
    $Target.Samples.Add([pscustomobject]@{
            T       = $ElapsedSeconds
            CpuMs   = $cpuMs
            Private = [double]$p.PrivateMemorySize64
            WS      = [double]$p.WorkingSet64
            Threads = [int]$p.Threads.Count
            Handles = [int]$p.HandleCount
        })
}

function Get-Stats($Values) {
    $m = $Values | Measure-Object -Minimum -Maximum -Average
    return @{ Min = [double]$m.Minimum; Avg = [double]$m.Average; Max = [double]$m.Maximum }
}

function Get-Row($Target, [int]$LogicalCpus) {
    # ToArray(): @() over a List[object] held in a pscustomobject property throws
    # "Argument types do not match" in both Windows PowerShell 5.1 and PowerShell 7.
    $s = $Target.Samples.ToArray()
    if ($s.Count -lt 2) { return $null }
    $first = $s[0]
    $last = $s[$s.Count - 1]
    $wall = $last.T - $first.T
    $avgCpu = $null
    $peakCpu = $null
    $cpuUsed = $null
    if ($wall -gt 0 -and $null -ne $first.CpuMs -and $null -ne $last.CpuMs) {
        $cpuUsed = ($last.CpuMs - $first.CpuMs) / 1000.0
        $avgCpu = $cpuUsed / $wall / $LogicalCpus * 100.0
        $peakCpu = 0.0
        for ($i = 1; $i -lt $s.Count; $i++) {
            $dt = $s[$i].T - $s[$i - 1].T
            if ($dt -le 0 -or $null -eq $s[$i].CpuMs -or $null -eq $s[$i - 1].CpuMs) { continue }
            $pct = ($s[$i].CpuMs - $s[$i - 1].CpuMs) / 1000.0 / $dt / $LogicalCpus * 100.0
            if ($pct -gt $peakCpu) { $peakCpu = $pct }
        }
    }
    $priv = Get-Stats ($s | ForEach-Object { $_.Private / 1MB })
    $ws = Get-Stats ($s | ForEach-Object { $_.WS / 1MB })
    $th = Get-Stats ($s | ForEach-Object { $_.Threads })
    $hd = Get-Stats ($s | ForEach-Object { $_.Handles })
    $na = 'n/a'
    return ('| {0} | {1} | {2} | {3} | {4} | {5} | {6} / {7} / {8} | {9} / {10} / {11} | {12} - {13} | {14} - {15} |' -f
        $Target.Label, $Target.ProcessId, $s.Count,
        $(if ($null -ne $avgCpu) { Format-Num $avgCpu 3 } else { $na }),
        $(if ($null -ne $peakCpu) { Format-Num $peakCpu 3 } else { $na }),
        $(if ($null -ne $cpuUsed) { (Format-Num $cpuUsed 2) + ' s' } else { $na }),
        (Format-Num $priv.Min 2), (Format-Num $priv.Avg 2), (Format-Num $priv.Max 2),
        (Format-Num $ws.Min 2), (Format-Num $ws.Avg 2), (Format-Num $ws.Max 2),
        [int]$th.Min, [int]$th.Max, [int]$hd.Min, [int]$hd.Max)
}

function Write-Report($Targets, [double]$Elapsed, [int]$LogicalCpus, [string]$StartedText) {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Measured on $env:COMPUTERNAME ($LogicalCpus logical CPUs, $([Environment]::OSVersion.VersionString)), started $StartedText,")
    $lines.Add("duration $(Format-Num $Elapsed 0) s, one sample every $IntervalSeconds s (scripts/measure.ps1).")
    $lines.Add('')
    $lines.Add('| Process | PID | Samples | Avg CPU % | Peak CPU % (per interval) | CPU time used | Private MB (min / avg / max) | Working set MB (min / avg / max) | Threads (min - max) | Handles (min - max) |')
    $lines.Add('|---|---|---|---|---|---|---|---|---|---|')
    $any = $false
    foreach ($t in $Targets) {
        $row = Get-Row $t $LogicalCpus
        if ($null -ne $row) {
            $lines.Add($row)
            $any = $true
        }
        else {
            $lines.Add("| $($t.Label) | $($t.ProcessId) | $($t.Samples.Count) | not enough samples | | | | | | |")
        }
    }
    $lines.Add('')
    $lines.Add('CPU % is relative to the whole machine (100 % = all logical CPUs busy).')
    $text = $lines -join [Environment]::NewLine
    Write-Host ''
    Write-Host $text
    if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
        $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
        Set-Content -LiteralPath $path -Value $text -Encoding UTF8
        Write-Host ''
        Write-Host "Written to $path"
    }
    return $any
}

# ------------------------------------------------------------------------------------------------

try {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
}
catch {
    $svc = $null
}
if ($null -eq $svc) {
    Write-Host "The service $ServiceName is not installed. Install it first: run PredatorRemoteController.exe (built by scripts\build.ps1 into dist\)." -ForegroundColor Red
    exit 1
}
if ($svc.State -ne 'Running' -or [int]$svc.ProcessId -le 0) {
    Write-Host "The service $ServiceName is not running (state: $($svc.State)). Start it first." -ForegroundColor Red
    exit 1
}
if ($null -eq (Get-Process -Id ([int]$svc.ProcessId) -ErrorAction SilentlyContinue)) {
    Write-Host 'The service process is not visible to this session. Run this script from an elevated PowerShell.' -ForegroundColor Red
    exit 1
}

$targets = New-Object System.Collections.Generic.List[object]
$targets.Add((New-Target 'predator-service.exe (service)' ([int]$svc.ProcessId)))
foreach ($tp in @(Get-Process -Name $TrayProcessName -ErrorAction SilentlyContinue | Sort-Object Id)) {
    $targets.Add((New-Target "predator-tray.exe (session $($tp.SessionId))" $tp.Id))
}
if ($targets.Count -eq 1) {
    Write-Host 'Note: no predator-tray.exe is running; only the service is measured.' -ForegroundColor Yellow
}

$logical = [Environment]::ProcessorCount
$started = Get-Date
$startedText = $started.ToString('yyyy-MM-dd HH:mm', $Inv)
Write-Host "Measuring $($targets.Count) process(es) for $Seconds s (every $IntervalSeconds s). Keep the PC idle; Ctrl+C prints partial results."

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$completed = $false
try {
    $next = 0.0
    while ($true) {
        $elapsed = $sw.Elapsed.TotalSeconds
        foreach ($t in $targets) { Add-Sample $t $elapsed }
        if (@($targets | Where-Object { -not $_.Exited }).Count -eq 0) { break }
        if ($elapsed -ge $Seconds) { break }
        $pct = [int][Math]::Min(100, ($elapsed / $Seconds) * 100)
        Write-Progress -Activity 'Measuring Predator' -Status "$([int]$elapsed) / $Seconds s" -PercentComplete $pct
        $next = [Math]::Min($next + $IntervalSeconds, [double]$Seconds)
        $wait = $next - $sw.Elapsed.TotalSeconds
        if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
    }
    $completed = $true
}
finally {
    Write-Progress -Activity 'Measuring Predator' -Completed
    if (-not $completed) { Write-Host 'Measurement interrupted; partial results:' -ForegroundColor Yellow }
    $ok = Write-Report $targets $sw.Elapsed.TotalSeconds $logical $startedText
}
if (-not $ok) { exit 1 }
exit 0
