<#
Collects: System Info, Logged-in Users, Network Connections, Running Processes,
          Defender Threats, Defender Config, Unsigned Processes, Scheduled Tasks,
          Suspicious Services, Script Block Logs, DNS Cache.

Author: Sneha Sukumar | Anglia Ruskin University
#>

#---------------Starts the module--------------------------------
Function Initialize-VolatileModule {
    param(
        [Parameter(Mandatory=$true)][string]$CaseFolder
    )
    $VolatilePath = Join-Path $CaseFolder "Volatile"
    return @{
        Status      = "Volatile module loaded"
        TargetPath  = $VolatilePath
        InvokedTime = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}


#-------------------Get-SystemInfo----------------------------------
Function Get-SystemInfo {
#It is collects OS, CPU, RAM, BIOS and uptime from the WMI/CIM.
#Collected first as it gives a context to everything else

    $separator = "=" * 60

    $os   = Get-CimInstance Win32_OperatingSystem
    $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS

    $totalRAM_GB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $freeRAM_GB  = [math]::Round($os.FreePhysicalMemory  / 1MB, 2)
    $uptime      = (Get-Date) - $os.LastBootUpTime

    $output  = @()
    $output += $separator
    $output += "  SYSTEM INFORMATION"
    $output += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += $separator
    $output += ""
    $output += "  Hostname          : $($env:COMPUTERNAME)"
    $output += "  Domain            : $($cs.Domain)"
    $output += "  OS                : $($os.Caption)"
    $output += "  OS Version        : $($os.Version)"
    $output += "  OS Build          : $($os.BuildNumber)"
    $output += "  Architecture      : $($os.OSArchitecture)"
    $output += "  Install Date      : $($os.InstallDate)"
    $output += "  Last Boot         : $($os.LastBootUpTime)"
    $output += "  System Uptime     : $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
    $output += ""
    $output += "  Processor         : $($cpu.Name)"
    $output += "  CPU Cores         : $($cpu.NumberOfCores)"
    $output += "  Logical Processors: $($cpu.NumberOfLogicalProcessors)"
    $output += ""
    $output += "  Total RAM         : $totalRAM_GB GB"
    $output += "  Free  RAM         : $freeRAM_GB GB"
    $output += ""
    $output += "  BIOS Version      : $($bios.SMBIOSBIOSVersion)"
    $output += "  Manufacturer      : $($cs.Manufacturer)"
    $output += "  Model             : $($cs.Model)"
    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

#-------------------Get-LoggedInUsers-------------------------------------------------
Function Get-LoggedInUsers {
#Gets all the active sessions using query.exe, and falls back to CIM if not available
#It also lists all local accounts and if anything is unexpected, it stands out

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  LOGGED-IN USERS"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""

    try {
        $queryResult = query user 2>&1
        if ($queryResult -match "No User exists") {
            $output += "  No interactive user sessions found."
        } else {
            foreach ($line in $queryResult) {
                $output += "  $line"
            }
        }
    }
    catch {
        $output += "  [!!!WARNING!!!] query.exe unavailable. Falling back to CIM."
    }

    $output += ""
    $output += "  ----Active Local Accounts (CIM)----"
    $output += ""

    try {
        $localUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
                      Select-Object Name, Disabled, PasswordRequired, AccountType
        foreach ($u in $localUsers) {
            $status = if ($u.Disabled) { "DISABLED" } else { "ENABLED" }
            $output += ("  {0,-25} Status: {1,-10} PasswordRequired: {2}" -f $u.Name, $status, $u.PasswordRequired)
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve local accounts: $_"
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

#------------Get-NetworkConnections---------------------------------------------
Function Get-NetworkConnections {
#It will pull established TCP connections, listening ports and active adapters.
#PIDs are resolved to process names which makes suspicious ports easier to spot

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  NETWORK CONNECTIONS"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator

    # Build a PID-to-ProcessName lookup table once
    # so we don't call Get-Process repeatedly inside the loops
    $pidMap = @{}
    try {
        Get-Process | ForEach-Object {
            if (-not $pidMap.ContainsKey($_.Id)) {
                $pidMap[$_.Id] = $_.Name
            }
        }
    }
    catch {
        # Non-fatal - fall back to PID only if this fails
    }

    function Resolve-Pid {
        param([int]$Pid)
        if ($pidMap.ContainsKey($Pid)) { return "$Pid ($($pidMap[$Pid]))" }
        return "$Pid"
    }

    $output += ""
    $output += "  ----Active TCP Connections----"
    $output += ""
    try {
        $tcpConns = Get-NetTCPConnection |
                    Where-Object { $_.State -eq 'Established' } |
                    Sort-Object RemoteAddress

        if ($tcpConns) {
            $output += ("  {0,-22} {1,-22} {2,-12} {3}" -f "LocalAddress:Port","RemoteAddress:Port","State","PID (Process)")
            $output += "  " + ("-" * 80)
            foreach ($c in $tcpConns) {
                $local      = "$($c.LocalAddress):$($c.LocalPort)"
                $remote     = "$($c.RemoteAddress):$($c.RemotePort)"
                $pidResolved = Resolve-Pid $c.OwningProcess
                $output += ("  {0,-22} {1,-22} {2,-12} {3}" -f $local, $remote, $c.State, $pidResolved)
            }
        } else {
            $output += "  No established TCP connections found."
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve TCP connections: $_"
    }

    $output += ""
    $output += "  ----Listening Ports----"
    $output += ""
    try {
        $listening = Get-NetTCPConnection -State Listen |
                     Sort-Object LocalPort |
                     Select-Object -Unique LocalPort, LocalAddress, OwningProcess

        if ($listening) {
            $output += ("  {0,-10} {1,-25} {2}" -f "Port","LocalAddress","PID (Process)")
            $output += "  " + ("-" * 50)
            foreach ($l in $listening) {
                $pidResolved = Resolve-Pid $l.OwningProcess
                $output += ("  {0,-10} {1,-25} {2}" -f $l.LocalPort, $l.LocalAddress, $pidResolved)
            }
        } else {
            $output += "  No listening ports found."
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve listening ports: $_"
    }

    $output += ""
    $output += "  ----Network Adapters----"
    $output += ""
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($a in $adapters) {
            $ipInfo = Get-NetIPAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue |
                      Where-Object { $_.AddressFamily -eq 'IPv4' }
            $ip = if ($ipInfo) { $ipInfo.IPAddress } else { "N/A" }

            $rawSpeed = $a.LinkSpeed
            $speedStr = if ($rawSpeed -is [int64] -or $rawSpeed -is [uint64]) {
                "$([math]::Round($rawSpeed / 1MB, 0)) Mbps"
            } else {
                "$rawSpeed"
            }
            $output += "  $($a.Name) | MAC: $($a.MacAddress) | IP: $ip | Speed: $speedStr"
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve adapter info: $_"
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

#-----------Get-RunningProcesses----------------------------------------------
Function Get-RunningProcesses {
#It will list all running proccesses sorted by the CPU.
#If anything running out of Temp or Appdata, it gets flagged inline

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  RUNNING PROCESSES"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""
    $output   += ("  {0,-8} {1,-35} {2,-10} {3}" -f "PID","Name","Mem(MB)","Path")
    $output   += "  " + ("-" * 90)

    $flaggedCount = 0

    try {
        $procs = Get-Process | Sort-Object CPU -Descending

        foreach ($p in $procs) {
            $memMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
            $path  = try { $p.MainModule.FileName } catch { "Access Denied" }

            $isSuspicious = $path -match '(?i)(\\temp\\|\\appdata\\|\\roaming\\)'

            if ($isSuspicious) {
                $flaggedCount++
                $output += ("  {0,-8} {1,-35} {2,-10} {3}" -f $p.Id, $p.Name, $memMB, $path)
                $output += "  [!!!SUSPICIOUS!!!] Process running from suspicious location: $path"
                $output += ""
            } else {
                $output += ("  {0,-8} {1,-35} {2,-10} {3}" -f $p.Id, $p.Name, $memMB, $path)
            }
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve processes: $_"
    }

    $output += ""
    $output += "  Total processes: $((Get-Process).Count)"

    if ($flaggedCount -gt 0) {
        $output += ""
        $output += "  [!!!ALERT!!!]: $flaggedCount process(es) running from suspicious locations."
        $output += "      Processes in Temp or AppData are strong indicators of malware."
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

#-----------Get-DefenderThreats----------------------------------------------
Function Get-DefenderThreats {
#It will check Defender threat history using Get-MpThreat and Get-MpThreatDetection
#Shows both known active threats and recent detection events.

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  WINDOWS DEFENDER THREAT HISTORY"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""

    # Section 1 - Known threats (Get-MpThreat)
    $output += "  ----Known Threats (Get-MpThreat)----"
    $output += ""
    try {
        $threats = Get-MpThreat -ErrorAction Stop

        if ($threats) {
            foreach ($t in $threats) {
                $output += "  [!!!THREAT DETECTED!!!]"
                $output += ("  {0,-25} : {1}" -f "Threat ID",        $t.ThreatID)
                $output += ("  {0,-25} : {1}" -f "Threat Name",      $t.ThreatName)
                $output += ("  {0,-25} : {1}" -f "Severity",         $t.SeverityID)
                $output += ("  {0,-25} : {1}" -f "Category",         $t.CategoryID)
                $output += ("  {0,-25} : {1}" -f "Status",           $t.ThreatStatusID)
                $output += ("  {0,-25} : {1}" -f "Active",           $t.IsActive)
                $output += ""
            }
        } else {
            $output += "  [OK] No known threats detected by Windows Defender."
            $output += ""
        }
    }
    catch {
        $output += "  [INFO] Get-MpThreat unavailable or returned no data: $_"
        $output += ""
    }

    # Section 2 - Recent detections (Get-MpThreatDetection)
    $output += "  ----Recent Detection Events (Get-MpThreatDetection)----"
    $output += ""
    try {
        $detections = Get-MpThreatDetection -ErrorAction Stop |
                      Sort-Object InitialDetectionTime -Descending |
                      Select-Object -First 20

        if ($detections) {
            foreach ($d in $detections) {
                $output += ("  {0,-25} : {1}" -f "Detection Time",   $d.InitialDetectionTime)
                $output += ("  {0,-25} : {1}" -f "Threat ID",        $d.ThreatID)
                $output += ("  {0,-25} : {1}" -f "Process Name",     $d.ProcessName)
                $output += ("  {0,-25} : {1}" -f "Action Taken",     $d.RemediationTime)
                $output += ("  {0,-25} : {1}" -f "Resources",        ($d.Resources -join ", "))
                $output += ""
            }
        } else {
            $output += "  [OK] No recent detection events found."
            $output += ""
        }
    }
    catch {
        $output += "  [INFO] Get-MpThreatDetection unavailable or returned no data: $_"
        $output += ""
    }

    $output += $separator

    return ($output -join "`r`n")
}

#----------------Get-DefenderConfig------------------------------------------------
Function Get-DefenderConfig {
#It will check Defender settings for signs of tampering or any deliberate disabling
#If any exclusion paths are added by an attacker, it will be shown up here.

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  WINDOWS DEFENDER CONFIGURATION AUDIT"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""

    try {
        $pref = Get-MpPreference -ErrorAction Stop

        $rtEnabled     = -not $pref.DisableRealtimeMonitoring
        $behavEnabled  = -not $pref.DisableBehaviorMonitoring
        $ioavEnabled   = -not $pref.DisableIOAVProtection
        $scriptEnabled = -not $pref.DisableScriptScanning
        $cloudEnabled  = ($pref.MAPSReporting -ne 0)

        $output += "  ----Core Protection Settings----"
        $output += ""

        if ($rtEnabled) {
            $output += "  [OK]      Real-Time Monitoring   : ENABLED"
        } else {
            $output += "  [!!!TAMPERED!!!] Real-Time Monitoring   : DISABLED"
        }

        if ($behavEnabled) {
            $output += "  [OK]      Behaviour Monitoring   : ENABLED"
        } else {
            $output += "  [!!!TAMPERED!!!] Behaviour Monitoring   : DISABLED"
        }

        if ($ioavEnabled) {
            $output += "  [OK]      IOAV Protection        : ENABLED"
        } else {
            $output += "  [!!!TAMPERED!!!] IOAV Protection        : DISABLED"
        }

        if ($scriptEnabled) {
            $output += "  [OK]      Script Scanning        : ENABLED"
        } else {
            $output += "  [!!!TAMPERED!!!] Script Scanning        : DISABLED"
        }

        if ($cloudEnabled) {
            $output += "  [OK]      Cloud Reporting (MAPS) : ENABLED"
        } else {
            $output += "  [!!!WARNING!!!]    Cloud Reporting (MAPS) : DISABLED (may be intentional)"
        }

        $output += ""
        $output += "  ----Exclusion Paths (Maybe added by the attacker)----"
        $output += ""

        if ($pref.ExclusionPath) {
            foreach ($excl in $pref.ExclusionPath) {
                $output += "  [!!!SUSPICIOUS!!!] Exclusion Path : $excl"
            }
        } else {
            $output += "  [OK] No exclusion paths configured."
        }

        $output += ""
        $output += "  ----Exclusion Processes----"
        $output += ""

        if ($pref.ExclusionProcess) {
            foreach ($excl in $pref.ExclusionProcess) {
                $output += "  [!!!SUSPICIOUS!!!] Exclusion Process : $excl"
            }
        } else {
            $output += "  [OK] No exclusion processes configured."
        }

        $output += ""
        $output += "  ----Signature Information----"
        $output += ""
        $output += ("  {0,-35} : {1}" -f "Signature Version",      $pref.SignatureDisableUpdateOnStartupWithoutEngine)
        $output += ("  {0,-35} : {1}" -f "Engine Updates Enabled",  (-not $pref.DisableArchiveScanning))

    }
    catch {
        $output += "  [INFO] Get-MpPreference unavailable: $_"
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

#------------Get-UnsignedProcesses---------------------------------------------
Function Get-UnsignedProcesses {
#It will run Get-AuthenticodeSignature against every running process path
#However, all valid signed process still get flagged if they're running from Temp or AppData

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  UNSIGNED PROCESS DETECTION"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""
    $output   += "  Checking all running process paths against digital signatures..."
    $output   += ""

    $flaggedCount = 0
    $checkedCount = 0
    $skippedCount = 0

    try {
        $procs = Get-Process | Where-Object { $_.Id -ne 0 } | Sort-Object Name

        foreach ($p in $procs) {

            $procPath = $null
            try {
                $procPath = $p.MainModule.FileName
            }
            catch {
                $skippedCount++
                continue
            }

            if ([string]::IsNullOrWhiteSpace($procPath)) { $skippedCount++; continue }
            if (-not (Test-Path $procPath))               { $skippedCount++; continue }

            $checkedCount++

            try {
                $sig = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction Stop

                switch ($sig.Status) {

                    'Valid' {
                        $suspiciousPath = $procPath -match '(?i)(temp|appdata\\local\\temp|roaming)'
                        if ($suspiciousPath) {
                            $flaggedCount++
                            $output += "  [!!!SUSPICIOUS!!!] PID: $($p.Id) | Name: $($p.Name)"
                            $output += "        Path      : $procPath"
                            $output += "        Signature : Valid but running from suspicious location"
                            $output += "        Signer    : $($sig.SignerCertificate.Subject)"
                            $output += ""
                        }
                    }

                    'NotSigned' {
                        $flaggedCount++
                        $output += "  [UNSIGNED] PID: $($p.Id) | Name: $($p.Name)"
                        $output += "        Path      : $procPath"
                        $output += "        Signature : NOT SIGNED"
                        $output += ""
                    }

                    'HashMismatch' {
                        $flaggedCount++
                        $output += "  [!!!HASH MISMATCH!!!] PID: $($p.Id) | Name: $($p.Name)"
                        $output += "        Path      : $procPath"
                        $output += "        Signature : HASH MISMATCH - file may have been tampered"
                        $output += ""
                    }

                    'NotTrusted' {
                        $flaggedCount++
                        $output += "  [NOT TRUSTED] PID: $($p.Id) | Name: $($p.Name)"
                        $output += "        Path      : $procPath"
                        $output += "        Signature : Certificate not trusted"
                        $output += "        Signer    : $($sig.SignerCertificate.Subject)"
                        $output += ""
                    }

                    default {
                        $flaggedCount++
                        $output += "  [UNKNOWN STATUS] PID: $($p.Id) | Name: $($p.Name)"
                        $output += "        Path      : $procPath"
                        $output += "        Signature : $($sig.Status)"
                        $output += ""
                    }
                }
            }
            catch {
                $skippedCount++
            }
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve process list: $_"
    }

    $output += $separator
    $output += "  SUMMARY"
    $output += $separator
    $output += "  Processes checked  : $checkedCount"
    $output += "  Processes skipped  : $skippedCount (system/access denied)"
    $output += "  Flagged entries    : $flaggedCount"

    if ($flaggedCount -gt 0) {
        $output += ""
        $output += "  [!!!ALERT!!!]: $flaggedCount process(es) flagged for investigation."
        $output += "      Review flagged entries above."
    } else {
        $output += ""
        $output += "  [OK] All checked processes are validly signed."
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

#-------------Get-ScheduledTasksAudit-------------------------------------------
Function Get-ScheduledTasksAudit {
#It will list out all non-Microsoft schduled tasks for manual review.
#Microsoft tasks are just counted along and they're trusted by default
#But, tasks running from Temp or AppData will get flagged immediately.

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  SCHEDULED TASKS AUDIT "
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""

    $flaggedCount = 0
    $totalCount   = 0

    try {
        $allTasks   = Get-ScheduledTask -ErrorAction Stop
        $msTasks    = $allTasks | Where-Object { $_.TaskPath -like "\Microsoft\*" }
        $nonMsTasks = $allTasks | Where-Object { $_.TaskPath -notlike "\Microsoft\*" }
        $totalCount = $allTasks.Count

        $output += "  ----Non-Microsoft Scheduled Tasks (Priority Review)----"
        $output += ""

        if ($nonMsTasks) {
            foreach ($task in $nonMsTasks | Sort-Object TaskPath, TaskName) {

                $flaggedCount++

                $actionDetail = "N/A"
                try {
                    $action = $task.Actions | Select-Object -First 1
                    if ($action.Execute) {
                        $actionDetail = $action.Execute
                        if ($action.Arguments) { $actionDetail += " $($action.Arguments)" }
                    }
                }
                catch { $actionDetail = "Could not retrieve action" }

                $triggerDetail = "N/A"
                try {
                    $trigger = $task.Triggers | Select-Object -First 1
                    if ($trigger) {
                        $triggerDetail = $trigger.CimClass.CimClassName -replace 'MSFT_Task',''
                    }
                }
                catch { $triggerDetail = "Could not retrieve trigger" }

                $isSuspicious = $actionDetail -match '(?i)(temp|appdata|roaming|%temp%|%appdata%)'

                if ($isSuspicious) {
                    $output += "  [!!!SUSPICIOUS!!!] Task  : $($task.TaskName)"
                    $output += "        Path    : $($task.TaskPath)"
                    $output += "        Action  : $actionDetail"
                    $output += "        Trigger : $triggerDetail"
                    $output += "        State   : $($task.State)"
                    $output += "        Reason  : Action runs from suspicious location"
                } else {
                    $output += "  [!!!REVIEW!!!] Task    : $($task.TaskName)"
                    $output += "        Path    : $($task.TaskPath)"
                    $output += "        Action  : $actionDetail"
                    $output += "        Trigger : $triggerDetail"
                    $output += "        State   : $($task.State)"
                }
                $output += ""
            }
        } else {
            $output += "  [OK] No non-Microsoft scheduled tasks found."
            $output += ""
        }

        $output += "  ----Microsoft Scheduled Tasks (Count Only)----"
        $output += ""
        $output += "  [INFO] $($msTasks.Count) Microsoft scheduled tasks present (not listed - trusted)."
        $output += ""

    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve scheduled tasks: $_"
        $output += ""
    }

    $output += $separator
    $output += "  SUMMARY"
    $output += $separator
    $output += "  Total tasks found      : $totalCount"
    $output += "  Non-Microsoft tasks    : $flaggedCount"

    if ($flaggedCount -gt 0) {
        $output += ""
        $output += "  [!!!ALERT!!!]: $flaggedCount non-Microsoft task(s) require review."
        $output += "      Non-Microsoft tasks are not automatically malicious but"
        $output += "      should be verified against known installed software."
    } else {
        $output += ""
        $output += "  [OK] No non-Microsoft scheduled tasks detected."
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

#-------------Get-SuspiciousServices--------------------------------------------
Function Get-SuspiciousServices {
#It will scan all Windows services for the ones running from suspicious paths.
#Legitimate services will never live in Temp or AppData adn any match here is worth investigating

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  SUSPICIOUS SERVICES DETECTION"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""

    $totalCount   = 0
    $flaggedCount = 0

    try {
        $allServices = Get-WmiObject Win32_Service -ErrorAction Stop
        $totalCount  = $allServices.Count

        $output += "  ----All Services: Suspicious Path Check----"
        $output += ""

        foreach ($svc in $allServices | Sort-Object Name) {
            $path = $svc.PathName
            if ([string]::IsNullOrWhiteSpace($path)) { continue }

            $isSuspicious = $path -match '(?i)(\\temp\\|\\appdata\\|\\roaming\\|%temp%|%appdata%)'

            if ($isSuspicious) {
                $flaggedCount++
                $output += "  [!!! SUSPICIOUS !!!] Service : $($svc.Name)"
                $output += "        Display Name : $($svc.DisplayName)"
                $output += "        Path         : $path"
                $output += "        State        : $($svc.State)"
                $output += "        Start Mode   : $($svc.StartMode)"
                $output += "        Run As       : $($svc.StartName)"
                $output += ""
            }
        }

        if ($flaggedCount -eq 0) {
            $output += "  [OK] No services found running from suspicious locations."
            $output += ""
        }

        $output += "  ----Stopped Services with Suspicious Indicators----"
        $output += ""

        $stoppedSuspicious = $allServices | Where-Object {
            $_.State -eq 'Stopped' -and
            $_.StartMode -eq 'Auto' -and
            $_.PathName -match '(?i)(\\temp\\|\\appdata\\|\\roaming\\)'
        }

        if ($stoppedSuspicious) {
            foreach ($svc in $stoppedSuspicious) {
                $output += "  [!!!SUSPICIOUS!!!] Stopped Auto-Start Service: $($svc.Name)"
                $output += "        Path     : $($svc.PathName)"
                $output += "        Run As   : $($svc.StartName)"
                $output += ""
            }
        } else {
            $output += "  [OK] No stopped auto-start services with suspicious paths found."
            $output += ""
        }

    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve services: $_"
        $output += ""
    }

    $output += $separator
    $output += "  SUMMARY"
    $output += $separator
    $output += "  Total services examined : $totalCount"
    $output += "  Suspicious services     : $flaggedCount"

    if ($flaggedCount -gt 0) {
        $output += ""
        $output += "  [!!!ALERT!!!]: $flaggedCount service(s) running from suspicious locations."
        $output += "      These should be investigated immediately."
    } else {
        $output += ""
        $output += "  [OK] No suspicious services detected."
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

#-----------Get-ScriptBlockLogs-----------------------------------------------
Function Get-ScriptBlockLogs {
#It will read Event ID 4104 from the PowerShell Operational log.
#It will also look for encoded commands, download cradles and other known patterns.
#However, skips the IR tool scripts to keep the output clean and tidy.

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  POWERSHELL SCRIPT BLOCK LOGS"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""

    $suspiciousCount = 0
    $totalCount      = 0

    $suspiciousPatterns = @(
        'Invoke-Expr' + 'ession',
        'IE' + 'X ',
        'IE' + 'X(',
        '-Encoded' + 'Command',
        '-en' + 'c ',
        'FromBase6' + '4String',
        'Download' + 'String',
        'Download' + 'File',
        'Web' + 'Client',
        'Net.Web' + 'Client',
        'shell' + 'code',
        'Virtual' + 'Alloc',
        'Create' + 'Thread',
        'Invoke-Mime' + 'katz',
        'Invoke-Shell' + 'code',
        'Invoke-Reflective' + 'PEInjection',
        'powershell -w hi' + 'dden',
        'by' + 'pass',
        'System.Reflection.' + 'Assembly'
    )

    try {
        $logName = 'Microsoft-Windows-PowerShell/Operational'

        $events = Get-WinEvent -LogName $logName -MaxEvents 100 `
                  -ErrorAction Stop |
                  Where-Object { $_.Id -eq 4104 } |
                  Select-Object -First 50

        $totalCount = ($events | Measure-Object).Count

        if ($totalCount -eq 0) {
            $output += "  [INFO] No script block log events found."
            $output += "  [INFO] Script block logging may not be enabled on this system."
            $output += ""
        } else {
            $output += "  [INFO] $totalCount script block events examined."
            $output += ""
            $output += "  ----Suspicious Script Block Entries----"
            $output += ""

            foreach ($event in $events) {
                $message = $event.Message
                if ([string]::IsNullOrWhiteSpace($message)) { continue }

                $isOwnScript = $message -like "*IR_Volatile*" -or
                               $message -like "*IR_Core*" -or
                               $message -like "*IR_Launch*" -or
                               $message -like "*IR_Registry*"
                if ($isOwnScript) { continue }

                $matchedPatterns = @()
                foreach ($pattern in $suspiciousPatterns) {
                    if ($message -like "*$pattern*") { $matchedPatterns += $pattern }
                }

                if ($matchedPatterns.Count -gt 0) {
                    $suspiciousCount++

                    $scriptText = ""
                    try {
                        $scriptText = $event.Properties[2].Value
                        if ([string]::IsNullOrWhiteSpace($scriptText)) {
                            $scriptText = $message.Substring(0, [Math]::Min(300, $message.Length))
                        }
                        if ($scriptText.Length -gt 300) {
                            $scriptText = $scriptText.Substring(0, 300) + "... [truncated]"
                        }
                    }
                    catch { $scriptText = "Could not extract script content" }

                    $output += "  [!!!SUSPICIOUS!!!]"
                    $output += ("  {0,-20} : {1}" -f "Time",     $event.TimeCreated)
                    $output += ("  {0,-20} : {1}" -f "Event ID", $event.Id)
                    $output += ("  {0,-20} : {1}" -f "Matched",  ($matchedPatterns -join ', '))
                    $output += ("  {0,-20} : {1}" -f "Content",  $scriptText)
                    $output += ""
                }
            }

            if ($suspiciousCount -eq 0) {
                $output += "  [OK] No suspicious patterns detected in script block logs."
                $output += ""
            }
        }
    }
    catch [System.Exception] {
        if ($_.Exception.Message -like "*No events were found*") {
            $output += "  [INFO] No PowerShell script block events found."
            $output += "  [INFO] Script block logging may not be enabled on this system."
            $output += ""
        } else {
            $output += "  [!!!ERROR!!!] Could not retrieve script block logs: $_"
            $output += ""
        }
    }

    $output += $separator
    $output += "  SUMMARY"
    $output += $separator
    $output += "  Total events examined  : $totalCount"
    $output += "  Suspicious entries     : $suspiciousCount"

    if ($suspiciousCount -gt 0) {
        $output += ""
        $output += "  [!!!ALERT!!!]: $suspiciousCount suspicious script block event(s) detected."
        $output += "      Review flagged entries above immediately."
    } elseif ($totalCount -gt 0) {
        $output += ""
        $output += "  [OK] No suspicious patterns found in script block logs."
    } else {
        $output += ""
        $output += "  [INFO] Script block logging not enabled or no events recorded."
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

#-----------Get-DnsCache-------------------------------------------------------
Function Get-DnsCache {
#It will read the DNS client cache to find recently resolved domains.
#All suspicious TLDs and known C2 infrastructure domains will get flagged.
#An empty cache can itself indicate anti-forensic activity.

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  DNS CACHE"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""
    $output   += "  DNS cache records recently resolved domains. Suspicious entries"
    $output   += "  may indicate C2 beaconing, phishing activity, or malware callbacks."
    $output   += ""

    # Known suspicious TLD and domain patterns worth flagging
    $suspiciousPatterns = @(
        '\.tk$', '\.pw$', '\.cc$', '\.xyz$', '\.top$', '\.ru$',
        '\.su$', '\.cn$', 'ngrok', 'duckdns', 'no-ip', 'ddns',
        'hopto', 'servebeer', 'serveftp', 'zapto', 'myftp',
        'dyndns', 'freedns', 'linkpc', 'chickenkiller'
    )

    $flaggedCount = 0
    $totalCount   = 0

    try {
        $dnsEntries = Get-DnsClientCache -ErrorAction Stop |
                      Sort-Object Entry

        $totalCount = ($dnsEntries | Measure-Object).Count

        if ($totalCount -eq 0) {
            $output += "  [INFO] DNS cache is empty or was recently flushed."
            $output += ""
        } else {
            $output += ("  {0,-50} {1,-10} {2,-8} {3}" -f "Entry (Domain)", "Type", "TTL", "Data")
            $output += "  " + ("-" * 90)

            foreach ($entry in $dnsEntries) {

                # Check against suspicious patterns
                $isSuspicious = $false
                foreach ($pattern in $suspiciousPatterns) {
                    if ($entry.Entry -match $pattern) {
                        $isSuspicious = $true
                        break
                    }
                }

                $entryName = $entry.Entry
                $entryType = $entry.Type
                $entryTTL  = $entry.TimeToLive
                $entryData = $entry.Data

                if ($isSuspicious) {
                    $flaggedCount++
                    $output += "  [!!!SUSPICIOUS!!!] $entryName"
                    $output += ("        Type : {0,-8}  TTL : {1,-8}  Data : {2}" -f $entryType, $entryTTL, $entryData)
                    $output += ""
                } else {
                    $output += ("  {0,-50} {1,-10} {2,-8} {3}" -f $entryName, $entryType, $entryTTL, $entryData)
                }
            }
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve DNS cache: $_"
        $output += ""
    }

    # Summary
    $output += ""
    $output += $separator
    $output += "  SUMMARY"
    $output += $separator
    $output += "  Total DNS entries : $totalCount"
    $output += "  Flagged entries   : $flaggedCount"

    if ($flaggedCount -gt 0) {
        $output += ""
        $output += "  [!] ALERT: $flaggedCount DNS entry/entries match suspicious domain patterns."
        $output += "      Flagged entries may indicate C2 beaconing or malware callbacks."
        $output += "      Cross-reference with network connections for confirmation."
    } elseif ($totalCount -gt 0) {
        $output += ""
        $output += "  [OK] No suspicious domain patterns detected in DNS cache."
    } else {
        $output += ""
        $output += "  [INFO] DNS cache empty - may have been flushed prior to collection."
        $output += "         This itself can be an indicator of anti-forensic activity."
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

Export-ModuleMember -Function Initialize-VolatileModule, Get-SystemInfo, `
                               Get-LoggedInUsers, Get-NetworkConnections, `
                               Get-RunningProcesses, Get-DefenderThreats, `
                               Get-DefenderConfig, Get-UnsignedProcesses, `
                               Get-ScheduledTasksAudit, Get-SuspiciousServices, `
                               Get-ScriptBlockLogs, Get-DnsCache