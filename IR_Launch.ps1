<#
Automated Incident Response using PowerShell
Author: Sneha Sukumar
Supervised by: Andrew Moore
Anglia Ruskin University
Version 1.0
#>

[CmdletBinding()]
param(
    [string]$EvidenceRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#------------Module Imports----------------------------------------------------
$CoreModulePath       = Join-Path $PSScriptRoot "modules\IR_Core.psm1"
$VolatileModulePath   = Join-Path $PSScriptRoot "modules\IR_Volatile.psm1"
$RegistryModulePath   = Join-Path $PSScriptRoot "modules\IR_Registry.psm1"
$FileSystemModulePath = Join-Path $PSScriptRoot "modules\IR_FileSystem.psm1"

Import-Module $CoreModulePath       -Force
Import-Module $VolatileModulePath   -Force
Import-Module $RegistryModulePath   -Force
Import-Module $FileSystemModulePath -Force

$script:LogPath = $null

#-----------Helper Functions--------------------------------------------------

function Test-Admin {
    try {
        $id        = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Write-ConsoleBanner {
    Write-Host ""
    Write-Host "====================================================================="
    Write-Host "  USB-Deployable PowerShell based Live Incident Response Framework  "
    Write-Host "                           Version 1.0                              "
    Write-Host "====================================================================="
    Write-Host ""
}

function Write-IRLog {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $entryTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine   = "[$entryTime] [$Level] $Message"
    Write-Host $logLine
    if ($script:LogPath -and -not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        Add-Content -Path $script:LogPath -Value $logLine
    }
}

#------------New-IntegrityLog--------------------------------------------------
#Generates SHA-256 hashes for all collected evidence files.
#Saved as an integrity log to support chain of custody verification.
#Referenced from RFC 3227 (Brezinski & Killalea, 2002).

function New-IntegrityLog {
    param(
        [Parameter(Mandatory=$true)][string]$CaseFolder,
        [Parameter(Mandatory=$true)][string]$LogsPath
    )

    $separator  = "=" * 60
    $output     = @()
    $output    += $separator
    $output    += "  SHA-256 EVIDENCE INTEGRITY LOG"
    $output    += "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output    += "  Case      : $(Split-Path $CaseFolder -Leaf)"
    $output    += $separator
    $output    += ""
    $output    += "  Hashes are generated using SHA-256 (Get-FileHash)."
    $output    += "  This log supports chain of custody verification"
    $output    += "  per RFC 3227 evidence collection guidelines."
    $output    += ""
    $output    += ("  {0,-18} {1,-65} {2}" -f "Subfolder", "File", "SHA-256 Hash")
    $output    += "  " + ("-" * 110)

    $fileCount  = 0
    $errorCount = 0

    $subfolders = @("Volatile", "Registry", "FileSystem")

    foreach ($sub in $subfolders) {
        $subPath = Join-Path $CaseFolder $sub
        if (-not (Test-Path $subPath)) { continue }

        $files = Get-ChildItem -Path $subPath -Filter "*.txt" -ErrorAction SilentlyContinue

        foreach ($f in $files | Sort-Object Name) {
            try {
                $hash = Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop
                $output += ("  {0,-18} {1,-65} {2}" -f $sub, $f.Name, $hash.Hash)
                $fileCount++
            }
            catch {
                $output += ("  {0,-18} {1,-65} ERROR: {2}" -f $sub, $f.Name, $_.Exception.Message)
                $errorCount++
            }
        }
    }

    $output += ""
    $output += $separator
    $output += "  SUMMARY"
    $output += $separator
    $output += "  Files hashed  : $fileCount"
    $output += "  Hash errors   : $errorCount"
    $output += ""
    $output += "  To verify integrity, re-run Get-FileHash on any file above"
    $output += "  and compare against the recorded hash value."
    $output += ""
    $output += $separator

    $logPath = Join-Path $LogsPath "Hashes.txt"
    ($output -join "`r`n") | Out-File -FilePath $logPath -Encoding UTF8

    return $logPath
}

# ---------- Main Execution ---------------------------------------------------
try {
    Write-ConsoleBanner

    if (-not (Test-Admin)) {
        throw "Script must be run as Administrator."
    }

    Write-Host "  Please enter your name (Investigator): " -NoNewline
    $InvestigatorName = Read-Host
    if ([string]::IsNullOrWhiteSpace($InvestigatorName)) {
        $InvestigatorName = "Unknown Investigator"
    }
    Write-Host ""

    $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $CaseId    = "IR_$TimeStamp"

    if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
        $minFreeGB     = 1
        $fallback      = "C:\IR_Lab\output"
        $usbFolderName = "IR_Cases"

        $usb = Get-CimInstance Win32_LogicalDisk |
               Where-Object { $_.DriveType -eq 2 -and $_.FreeSpace -ge ($minFreeGB * 1GB) } |
               Sort-Object FreeSpace -Descending |
               Select-Object -First 1

        $EvidenceRoot = if ($usb) { Join-Path $usb.DeviceID $usbFolderName } else { $fallback }
    }

    foreach ($path in @($EvidenceRoot, (Join-Path $EvidenceRoot $CaseId))) {
        if (-not (Test-Path $path)) { New-Item -Path $path -ItemType Directory | Out-Null }
    }

    $CaseFolder = Join-Path $EvidenceRoot $CaseId

    foreach ($folder in @("Logs","Volatile","Registry","FileSystem","Reports")) {
        $fp = Join-Path $CaseFolder $folder
        if (-not (Test-Path $fp)) { New-Item -Path $fp -ItemType Directory | Out-Null }
    }

    $LogPath        = Join-Path $CaseFolder "Logs\IR_Log.txt"
    $script:LogPath = $LogPath
    if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType File | Out-Null }

    $CaseModule       = Initialize-CaseModule       -CaseId $CaseId -CaseFolder $CaseFolder
    $VolatileModule   = Initialize-VolatileModule   -CaseFolder $CaseFolder
    $RegistryModule   = Initialize-RegistryModule   -CaseFolder $CaseFolder
    $FileSystemModule = Initialize-FileSystemModule -CaseFolder $CaseFolder

    Write-IRLog "Investigator  : $InvestigatorName"
    Write-IRLog "Core module initialized.       Init time : $($CaseModule.InitTime)"
    Write-IRLog "Volatile module initialized.   Target    : $($VolatileModule.TargetPath)"
    Write-IRLog "Registry module initialized.   Target    : $($RegistryModule.TargetPath)"
    Write-IRLog "FileSystem module initialized. Target    : $($FileSystemModule.TargetPath)"
    Write-IRLog "Case ID       : $CaseId"
    Write-IRLog "EvidenceRoot  : $EvidenceRoot"
    Write-IRLog "CaseFolder    : $CaseFolder"
    Write-IRLog "LogPath       : $LogPath"

    # -- Volatile Collection -----------------------------------------------------
    Write-Host ""
    Write-Host "---------------------------------------------------------------------"
    Write-Host "  Starting Volatile Artifact Collection..."
    Write-Host "---------------------------------------------------------------------"

    $VolatilePath    = $VolatileModule.TargetPath
    $collectionStart = Get-Date

    $t = Get-Date
    Write-IRLog "START Get-SystemInfo"
    $sysInfo = Get-SystemInfo
    $sysInfo | Out-File -FilePath (Join-Path $VolatilePath "SystemInfo.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-SystemInfo        ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-LoggedInUsers"
    $users = Get-LoggedInUsers
    $users | Out-File -FilePath (Join-Path $VolatilePath "LoggedInUsers.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-LoggedInUsers     ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-NetworkConnections"
    $netConns = Get-NetworkConnections
    $netConns | Out-File -FilePath (Join-Path $VolatilePath "NetworkConnections.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-NetworkConnections ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-RunningProcesses"
    $procs = Get-RunningProcesses
    $procs | Out-File -FilePath (Join-Path $VolatilePath "RunningProcesses.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-RunningProcesses  ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-DefenderThreats"
    $defThreats = Get-DefenderThreats
    $defThreats | Out-File -FilePath (Join-Path $VolatilePath "DefenderThreats.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-DefenderThreats   ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-DefenderConfig"
    $defConfig = Get-DefenderConfig
    $defConfig | Out-File -FilePath (Join-Path $VolatilePath "DefenderConfig.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-DefenderConfig    ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-UnsignedProcesses"
    $unsignedProcs = Get-UnsignedProcesses
    $unsignedProcs | Out-File -FilePath (Join-Path $VolatilePath "UnsignedProcesses.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-UnsignedProcesses ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-ScheduledTasksAudit"
    $scheduledTasks = Get-ScheduledTasksAudit
    $scheduledTasks | Out-File -FilePath (Join-Path $VolatilePath "ScheduledTasks.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-ScheduledTasksAudit ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-SuspiciousServices"
    $suspServices = Get-SuspiciousServices
    $suspServices | Out-File -FilePath (Join-Path $VolatilePath "SuspiciousServices.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-SuspiciousServices ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-ScriptBlockLogs"
    $scriptBlockLogs = Get-ScriptBlockLogs
    $scriptBlockLogs | Out-File -FilePath (Join-Path $VolatilePath "ScriptBlockLogs.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-ScriptBlockLogs   ${elapsed}s"

    $t = Get-Date
    Write-IRLog "START Get-DnsCache"
    $dnsCache = Get-DnsCache
    $dnsCache | Out-File -FilePath (Join-Path $VolatilePath "DnsCache.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-DnsCache          ${elapsed}s"

    # -- Registry Collection -----------------------------------------------------
    Write-Host ""
    Write-Host "---------------------------------------------------------------------"
    Write-Host "  Starting Registry Artifact Collection..."
    Write-Host "---------------------------------------------------------------------"

    $RegistryPath = $RegistryModule.TargetPath

    $t = Get-Date
    Write-IRLog "START Get-RegistryArtefacts"
    $regArtefacts = Get-RegistryArtefacts
    $regArtefacts | Out-File -FilePath (Join-Path $RegistryPath "RegistryArtefacts.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-RegistryArtefacts ${elapsed}s"

    # -- FileSystem Collection ---------------------------------------------------
    Write-Host ""
    Write-Host "---------------------------------------------------------------------"
    Write-Host "  Starting FileSystem Artifact Collection..."
    Write-Host "---------------------------------------------------------------------"

    $FileSystemPath = $FileSystemModule.TargetPath

    $t = Get-Date
    Write-IRLog "START Get-FileSystemArtefacts"
    $fsArtefacts = Get-FileSystemArtefacts
    $fsArtefacts | Out-File -FilePath (Join-Path $FileSystemPath "FileSystemArtefacts.txt") -Encoding UTF8
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   Get-FileSystemArtefacts ${elapsed}s"

    # -- Evidence Integrity Log --------------------------------------------------
    Write-Host ""
    Write-Host "---------------------------------------------------------------------"
    Write-Host "  Generating Evidence Integrity Log..."
    Write-Host "---------------------------------------------------------------------"

    $LogsPath = Join-Path $CaseFolder "Logs"
    $t = Get-Date
    Write-IRLog "START New-IntegrityLog"
    $integrityLogPath = New-IntegrityLog -CaseFolder $CaseFolder -LogsPath $LogsPath
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   New-IntegrityLog      ${elapsed}s"
    Write-IRLog "Evidence integrity log saved: $integrityLogPath"

    # -- Report Generation -------------------------------------------------------
    Write-Host ""
    Write-Host "---------------------------------------------------------------------"
    Write-Host "  Generating HTML Report..."
    Write-Host "---------------------------------------------------------------------"

    $ReportPath = Join-Path $CaseFolder "Reports\IR_Report.html"

    $t = Get-Date
    Write-IRLog "START New-IRReport"
    New-IRReport `
        -CaseId           $CaseId `
        -TimeStamp        $TimeStamp `
        -CaseFolder       $CaseFolder `
        -VolatilePath     $VolatilePath `
        -RegistryPath     $RegistryPath `
        -FileSystemPath   $FileSystemPath `
        -ReportPath       $ReportPath `
        -InvestigatorName $InvestigatorName
    $elapsed = [int]((Get-Date) - $t).TotalSeconds
    Write-IRLog "END   New-IRReport          ${elapsed}s"
    Write-IRLog "HTML report generated: $ReportPath"

    # -- Summary -----------------------------------------------------------------
    $totalRuntime = [int]((Get-Date) - $collectionStart).TotalSeconds

    Write-Host ""
    Write-Host "====================================================================="
    Write-Host "  Collection Complete"
    Write-Host "====================================================================="
    Write-Host "  Case ID        : $CaseId"
    Write-Host "  Investigator   : $InvestigatorName"
    Write-Host "  Case Folder    : $CaseFolder"
    Write-Host "  Report         : $ReportPath"
    Write-Host "  Integrity Log  : $integrityLogPath"
    Write-Host "  Total Runtime  : ${totalRuntime}s"
    Write-Host "====================================================================="
    Write-Host ""

    Write-IRLog "Total collection runtime: ${totalRuntime}s"
    Write-IRLog "Incident response collection completed successfully."

}
catch {
    if ($script:LogPath -and -not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        Add-Content -Path $script:LogPath -Value (
            "[{0}] [!!!ERROR!!!] FATAL: {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_.Exception.Message
        )
    }
    Write-Host ""
    Write-Host "FATAL ERROR: $($_.Exception.Message)"
    Write-Host "Script terminated."
    exit 1
}