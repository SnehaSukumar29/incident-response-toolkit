<#
Core module for the PowerShell Incident Response Framework.
Handles case initialisation and HTML report generation.

Author: Sneha Sukumar | Anglia Ruskin University
#>

#----------Start Core module--------------------------------------------
Function Initialize-CaseModule {
    param(
        [Parameter(Mandatory=$true)][string]$CaseId,
        [Parameter(Mandatory=$true)][string]$CaseFolder
    )
    return @{
        CaseId     = $CaseId
        CaseFolder = $CaseFolder
        InitTime   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}

#----------New-IRReport------------------------------------------------------
Function New-IRReport {
    param(
        [Parameter(Mandatory=$true)][string]$CaseId,
        [Parameter(Mandatory=$true)][string]$TimeStamp,
        [Parameter(Mandatory=$true)][string]$CaseFolder,
        [Parameter(Mandatory=$true)][string]$VolatilePath,
        [Parameter(Mandatory=$true)][string]$RegistryPath,
        [Parameter(Mandatory=$true)][string]$FileSystemPath,
        [Parameter(Mandatory=$true)][string]$ReportPath,
        [Parameter(Mandatory=$true)][string]$InvestigatorName
    )

    function Read-ArtifactFile {
        param([string]$FilePath)
        if (Test-Path $FilePath) {
            return (Get-Content -Path $FilePath -Raw -Encoding UTF8)
        }
        return "No data collected."
    }

    # Read artifact files
    $sysInfoText     = Read-ArtifactFile (Join-Path $VolatilePath "SystemInfo.txt")
    $usersText       = Read-ArtifactFile (Join-Path $VolatilePath "LoggedInUsers.txt")
    $netText         = Read-ArtifactFile (Join-Path $VolatilePath "NetworkConnections.txt")
    $procsText       = Read-ArtifactFile (Join-Path $VolatilePath "RunningProcesses.txt")
    $defThreatsRaw   = Read-ArtifactFile (Join-Path $VolatilePath "DefenderThreats.txt")
    $defConfigRaw    = Read-ArtifactFile (Join-Path $VolatilePath "DefenderConfig.txt")
    $unsignedRaw     = Read-ArtifactFile (Join-Path $VolatilePath "UnsignedProcesses.txt")
    $schedTasksRaw   = Read-ArtifactFile (Join-Path $VolatilePath "ScheduledTasks.txt")
    $suspSvcRaw      = Read-ArtifactFile (Join-Path $VolatilePath "SuspiciousServices.txt")
    $scriptBlocksRaw = Read-ArtifactFile (Join-Path $VolatilePath "ScriptBlockLogs.txt")
    $dnsCacheRaw     = Read-ArtifactFile (Join-Path $VolatilePath "DnsCache.txt")
    $regRaw          = Read-ArtifactFile (Join-Path $RegistryPath "RegistryArtefacts.txt")
    $fsRaw           = Read-ArtifactFile (Join-Path $FileSystemPath "FileSystemArtefacts.txt")

    #---Highlighting functions---------------------------------------------------

    $regText = $regRaw `
        -replace '(?m)(\[!!!SUSPICIOUS!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(^\s+Value\s+:.*(?:Temp|AppData|Roaming|RAT)[^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(^\s+Reason:[^\r\n]*)', '<span class="flag-reason">$1</span>' `
        -replace '(?m)(\[!!!ALERT!!!\]:[^\r\n]*)', '<span class="flag-alert">$1</span>'

    $defThreatsText = $defThreatsRaw `
        -replace '(?m)(\[THREAT DETECTED\][^\r\n]*)', '<span class="flag-suspicious">$1</span>'

    $defConfigText = $defConfigRaw `
        -replace '(?m)(\[!!!TAMPERED!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[!!!SUSPICIOUS!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[!!!WARNING!!!\][^\r\n]*)', '<span class="flag-reason">$1</span>'

    $procsText = $procsText `
        -replace '(?m)(\[!!!SUSPICIOUS!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[!!!ALERT!!!\]:[^\r\n]*)', '<span class="flag-alert">$1</span>'

    $unsignedText = $unsignedRaw `
        -replace '(?m)(\[!!!SUSPICIOUS!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[UNSIGNED\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[!!!HASH MISMATCH!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[NOT TRUSTED\][^\r\n]*)', '<span class="flag-reason">$1</span>' `
        -replace '(?m)(\[!!!ALERT!!!\]:[^\r\n]*)', '<span class="flag-alert">$1</span>'

    $schedTasksText = $schedTasksRaw `
        -replace '(?m)(\[!!!SUSPICIOUS!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(^\s+Reason\s+:[^\r\n]*)', '<span class="flag-reason">$1</span>' `
        -replace '(?m)(\[!!!REVIEW!!!\][^\r\n]*)', '<span class="flag-reason">$1</span>' `
        -replace '(?m)(\[!!!ALERT!!!\]:[^\r\n]*)', '<span class="flag-alert">$1</span>'

    $suspSvcText = $suspSvcRaw `
        -replace '(?m)(\[!!!SUSPICIOUS!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[!!!ALERT!!!\]:[^\r\n]*)', '<span class="flag-alert">$1</span>'

    $scriptBlocksText = $scriptBlocksRaw `
        -replace '(?m)(\[!!!SUSPICIOUS!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[!!!ALERT!!!\]:[^\r\n]*)', '<span class="flag-alert">$1</span>'

    $fsText = $fsRaw `
        -replace '(?m)(\[!!!SUSPICIOUS!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[!!!ALERT!!!\]:[^\r\n]*)', '<span class="flag-alert">$1</span>'

    $dnsCacheText = $dnsCacheRaw `
        -replace '(?m)(\[!!!SUSPICIOUS!!!\][^\r\n]*)', '<span class="flag-suspicious">$1</span>' `
        -replace '(?m)(\[!!!ALERT!!!\]:[^\r\n]*)', '<span class="flag-alert">$1</span>'

    #---Summary Banner counts----------------------------------------------------
    # Count flagged indicators across all raw text files for the banner.

    function Count-Flags {
        param([string]$text, [string]$pattern)
        return ([regex]::Matches($text, $pattern)).Count
    }

    $count_suspicious = (
        (Count-Flags $regRaw          '\[!!!SUSPICIOUS!!!\]') +
        (Count-Flags $procsText       '\[!!!SUSPICIOUS!!!\]') +
        (Count-Flags $unsignedRaw     '\[!!!SUSPICIOUS!!!\]') +
        (Count-Flags $unsignedRaw     '\[UNSIGNED\]') +
        (Count-Flags $unsignedRaw     '\[!!!HASH MISMATCH!!!\]') +
        (Count-Flags $schedTasksRaw   '\[!!!SUSPICIOUS!!!\]') +
        (Count-Flags $suspSvcRaw      '\[!!!SUSPICIOUS!!!\]') +
        (Count-Flags $scriptBlocksRaw '\[!!!SUSPICIOUS!!!\]') +
        (Count-Flags $fsRaw           '\[!!!SUSPICIOUS!!!\]') +
        (Count-Flags $dnsCacheRaw     '\[!!!SUSPICIOUS!!!\]') +
        (Count-Flags $defThreatsRaw   '\[THREAT DETECTED\]') +
        (Count-Flags $defConfigRaw    '\[!!!TAMPERED!!!\]')
    )

    $count_warnings = (
        (Count-Flags $schedTasksRaw '\[!!!REVIEW!!!\]') +
        (Count-Flags $defConfigRaw  '\[!!!WARNING!!!\]') +
        (Count-Flags $unsignedRaw   '\[NOT TRUSTED\]')
    )

    #Determine overall verdict for banner colour
    if ($count_suspicious -gt 0) {
        $verdictClass = "verdict-critical"
        $verdictText  = "INDICATORS DETECTED"
        $verdictIcon  = "&#9888;"
    } elseif ($count_warnings -gt 0) {
        $verdictClass = "verdict-warn"
        $verdictText  = "REVIEW REQUIRED"
        $verdictIcon  = "&#9888;"
    } else {
        $verdictClass = "verdict-clean"
        $verdictText  = "NO INDICATORS FOUND"
        $verdictIcon  = "&#10003;"
    }

    $GeneratedAt = Get-Date -Format "dddd dd MMMM yyyy HH:mm:ss"
    $Hostname    = $env:COMPUTERNAME

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incident Response Report - $CaseId</title>
    <style>

        /* Reset and Base */
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f0f2f5;
            color: #1a1a2e;
            font-size: 14px;
        }

        /* Header */
        header {
            background: #1a2550;
            padding: 28px 48px;
            border-bottom: 4px solid #2e5baa;
        }
        .header-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .header-title h1 {
            font-size: 22px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: 0.5px;
        }
        .header-title p {
            color: #a8b8d8;
            margin-top: 4px;
            font-size: 12px;
            letter-spacing: 0.3px;
        }
        .header-badge {
            background: #2e5baa;
            color: #ffffff;
            padding: 6px 16px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        /* Case Metadata Bar */
        .meta-bar {
            background: #ffffff;
            border-bottom: 1px solid #dde3ed;
            padding: 16px 48px;
            display: flex;
            gap: 48px;
            flex-wrap: wrap;
        }
        .meta-item label {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            color: #6b7a99;
            font-weight: 600;
        }
        .meta-item span {
            display: block;
            font-size: 13px;
            color: #1a2550;
            font-weight: 600;
            margin-top: 3px;
        }

        /* Summary Banner */
        .summary-banner {
            margin: 24px 48px 0 48px;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 2px 6px rgba(0,0,0,0.10);
        }
        .summary-banner-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 24px;
            background: #1a2550;
        }
        .summary-banner-header h2 {
            color: #ffffff;
            font-size: 13px;
            font-weight: 600;
            letter-spacing: 0.8px;
            text-transform: uppercase;
        }
        .verdict-badge {
            padding: 5px 14px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        .verdict-critical { background: #c0392b; color: #ffffff; }
        .verdict-warn     { background: #e67e22; color: #ffffff; }
        .verdict-clean    { background: #27ae60; color: #ffffff; }

        .summary-banner-body {
            background: #ffffff;
            padding: 20px 24px;
            display: flex;
            gap: 32px;
            flex-wrap: wrap;
            border: 1px solid #dde3ed;
            border-top: none;
        }
        .summary-stat {
            text-align: center;
            min-width: 100px;
        }
        .summary-stat .stat-number {
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }
        .summary-stat .stat-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #6b7a99;
            margin-top: 6px;
        }
        .stat-red    { color: #c0392b; }
        .stat-orange { color: #e67e22; }
        .stat-blue   { color: #2e5baa; }
        .stat-green  { color: #27ae60; }

        .summary-divider {
            width: 1px;
            background: #dde3ed;
            align-self: stretch;
        }

        .summary-note {
            flex: 1;
            min-width: 200px;
            font-size: 12px;
            color: #6b7a99;
            line-height: 1.7;
            align-self: center;
            padding-left: 8px;
        }

        /* Main Content */
        main {
            max-width: 1200px;
            margin: 24px auto;
            padding: 0 48px;
        }

        /* Section Cards */
        .section {
            background: #ffffff;
            border: 1px solid #dde3ed;
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
        }
        .section-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 13px 20px;
            background: #f7f9fc;
            border-bottom: 1px solid #dde3ed;
        }
        .section-icon {
            width: 28px; height: 28px;
            border-radius: 4px;
            display: flex; align-items: center;
            justify-content: center;
            font-size: 14px;
        }
        .icon-sys      { background: #e8f0fe; }
        .icon-usr      { background: #e6f4ea; }
        .icon-net      { background: #fef3e2; }
        .icon-proc     { background: #f3e8fd; }
        .icon-reg      { background: #fce8e8; }
        .icon-def      { background: #e8f4fd; }
        .icon-defcfg   { background: #fff8e8; }
        .icon-unsigned { background: #fce8e8; }
        .icon-sched    { background: #f0f4e8; }
        .icon-svc      { background: #f4e8f0; }
        .icon-script   { background: #e8f0e8; }
        .icon-fs       { background: #fef0e8; }
        .icon-dns      { background: #e8f4fd; }

        .section-header h2 {
            font-size: 14px;
            font-weight: 600;
            color: #1a2550;
        }

        /* Pre / Artifact Text */
        pre {
            padding: 20px 24px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.8;
            color: #2c3e60;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 420px;
            overflow-y: auto;
            background: #fafbfd;
        }
        pre::-webkit-scrollbar { width: 5px; }
        pre::-webkit-scrollbar-track { background: #f0f2f5; }
        pre::-webkit-scrollbar-thumb { background: #c5cede; border-radius: 3px; }

        /* Suspicious Entry Highlighting */
        .flag-suspicious {
            color: #c0392b;
            font-weight: 700;
            background: #fff5f5;
            display: inline;
        }
        .flag-reason {
            color: #e67e22;
            font-weight: 600;
            display: inline;
        }
        .flag-alert {
            color: #c0392b;
            font-weight: 700;
            display: inline;
        }

        /* Footer */
        footer {
            text-align: center;
            padding: 20px 48px;
            color: #6b7a99;
            font-size: 11px;
            border-top: 1px solid #dde3ed;
            margin-top: 8px;
            background: #ffffff;
        }
        footer strong { color: #1a2550; }

    </style>
</head>
<body>

<!-- Header -->
<header>
    <div class="header-top">
        <div class="header-title">
            <h1>Incident Response Report</h1>
            <p>USB-Deployable PowerShell IR Framework &nbsp;&bull;&nbsp; Anglia Ruskin University</p>
        </div>
        <div class="header-badge">Forensic Evidence</div>
    </div>
</header>

<!-- Case Metadata -->
<div class="meta-bar">
    <div class="meta-item"><label>Case ID</label><span>$CaseId</span></div>
    <div class="meta-item"><label>Host</label><span>$Hostname</span></div>
    <div class="meta-item"><label>Investigator</label><span>$InvestigatorName</span></div>
    <div class="meta-item"><label>Generated</label><span>$GeneratedAt</span></div>
    <div class="meta-item"><label>Status</label><span>Collection Complete</span></div>
</div>

<!-- Summary Banner -->
<div class="summary-banner">
    <div class="summary-banner-header">
        <h2>&#128202; Collection Summary</h2>
        <span class="verdict-badge $verdictClass">$verdictIcon &nbsp; $verdictText</span>
    </div>
    <div class="summary-banner-body">
        <div class="summary-stat">
            <div class="stat-number stat-red">$count_suspicious</div>
            <div class="stat-label">Suspicious Flags</div>
        </div>
        <div class="summary-divider"></div>
        <div class="summary-stat">
            <div class="stat-number stat-orange">$count_warnings</div>
            <div class="stat-label">Warnings</div>
        </div>
        <div class="summary-divider"></div>
        <div class="summary-stat">
            <div class="stat-number stat-blue">13</div>
            <div class="stat-label">Sections Collected</div>
        </div>
        <div class="summary-divider"></div>
        <div class="summary-note">
            Suspicious flags indicate entries matching known malicious indicators
            (unsigned processes, suspicious paths, registry persistence, DNS anomalies).
            Warnings require manual review but are not automatically malicious.
            Scroll down to review each section. Flagged entries are highlighted in red.
        </div>
    </div>
</div>

<main>

    <!-- System Information -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-sys">&#128187;</div>
            <h2>System Information</h2>
        </div>
        <pre>$sysInfoText</pre>
    </div>

    <!-- Logged-in Users -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-usr">&#128100;</div>
            <h2>Logged-in Users</h2>
        </div>
        <pre>$usersText</pre>
    </div>

    <!-- Network Connections -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-net">&#127760;</div>
            <h2>Network Connections</h2>
        </div>
        <pre>$netText</pre>
    </div>

    <!-- DNS Cache -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-dns">&#128225;</div>
            <h2>DNS Cache</h2>
        </div>
        <pre>$dnsCacheText</pre>
    </div>

    <!-- Running Processes -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-proc">&#9881;</div>
            <h2>Running Processes</h2>
        </div>
        <pre>$procsText</pre>
    </div>

    <!-- Unsigned Process Detection -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-unsigned">&#128274;</div>
            <h2>Unsigned Process Detection</h2>
        </div>
        <pre>$unsignedText</pre>
    </div>

    <!-- Scheduled Tasks Audit -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-sched">&#128197;</div>
            <h2>Scheduled Tasks Audit</h2>
        </div>
        <pre>$schedTasksText</pre>
    </div>

    <!-- Suspicious Services -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-svc">&#128295;</div>
            <h2>Suspicious Services Detection</h2>
        </div>
        <pre>$suspSvcText</pre>
    </div>

    <!-- Registry Artefacts -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-reg">&#128273;</div>
            <h2>Registry Artefacts</h2>
        </div>
        <pre>$regText</pre>
    </div>

    <!-- FileSystem Artefacts -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-fs">&#128193;</div>
            <h2>FileSystem Artefacts</h2>
        </div>
        <pre>$fsText</pre>
    </div>

    <!-- PowerShell Script Block Logs -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-script">&#128196;</div>
            <h2>PowerShell Script Block Logs</h2>
        </div>
        <pre>$scriptBlocksText</pre>
    </div>

    <!-- Windows Defender Threat History -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-def">&#128737;</div>
            <h2>Windows Defender Threat History</h2>
        </div>
        <pre>$defThreatsText</pre>
    </div>

    <!-- Windows Defender Configuration Audit -->
    <div class="section">
        <div class="section-header">
            <div class="section-icon icon-defcfg">&#9881;</div>
            <h2>Windows Defender Configuration Audit</h2>
        </div>
        <pre>$defConfigText</pre>
    </div>

</main>

<footer>
    Generated by <strong>PowerShell IR Framework v1.0</strong> &nbsp;&bull;&nbsp;
    Sneha Sukumar &nbsp;&bull;&nbsp; Anglia Ruskin University &nbsp;&bull;&nbsp; $GeneratedAt
</footer>

</body>
</html>
"@

    $html | Out-File -FilePath $ReportPath -Encoding UTF8
}

Export-ModuleMember -Function Initialize-CaseModule, New-IRReport