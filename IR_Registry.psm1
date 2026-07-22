<#
Registry artefact collection module for the PowerShell Incident Response Framework.
Collects: Autorun keys (HKCU and HKLM Run/RunOnce), flags suspicious entries.

Author: Sneha Sukumar | Anglia Ruskin University
#>

#------------Start the registry module-----------------------------------------
Function Initialize-RegistryModule {
    param(
        [Parameter(Mandatory=$true)][string]$CaseFolder
    )
    $RegistryPath = Join-Path $CaseFolder "Registry"
    return @{
        Status      = "Registry module loaded"
        TargetPath  = $RegistryPath
        InvokedTime = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}

#-----------Get-RegistryArtefacts---------------------------------------------
Function Get-RegistryArtefacts {
#It will check all six Run and RunOnce keys across HKCU and HKLM
#Also flags anything pointing to Temp, AppData, Roaming, or matching the RAT test artefact names that are used in testing.

    $separator = "=" * 60
    $output    = @()

    $output += $separator
    $output += "  REGISTRY ARTEFACTS "
    $output += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += $separator
    $output += ""

    # Registry keys to examine
    $registryKeys = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    # Suspicious path indicators
    $suspiciousPatterns = @(
        "temp",
        "appdata",
        "roaming",
        "%temp%",
        "%appdata%",
        "rat_backdoor",
        "rat_persistence"
    )

    $totalEntries  = 0
    $flaggedCount  = 0

    foreach ($keyPath in $registryKeys) {

        $output += "  Registry Key: $keyPath"
        $output += "  " + ("-" * 56)

        # Check if key exists
        if (-not (Test-Path $keyPath)) {
            $output += "  [INFO] Key does not exist on this system."
            $output += ""
            continue
        }

        try {
            $keyValues = Get-ItemProperty -Path $keyPath -ErrorAction Stop

            # Get all properties except built-in PSObject properties
            $entries = $keyValues.PSObject.Properties |
                       Where-Object {
                           $_.Name -notin @(
                               'PSPath','PSParentPath','PSChildName',
                               'PSProvider','PSDrive'
                           )
                       }

            if (-not $entries) {
                $output += "  [INFO] No entries found in this key."
                $output += ""
                continue
            }

            foreach ($entry in $entries) {

                $totalEntries++
                $entryName  = $entry.Name
                $entryValue = $entry.Value

                # Check if this entry is suspicious
                $isSuspicious = $false
                $matchedPattern = ""

                foreach ($pattern in $suspiciousPatterns) {
                    if ($entryValue -like "*$pattern*") {
                        $isSuspicious   = $true
                        $matchedPattern = $pattern
                        break
                    }
                }

                if ($isSuspicious) {
                    $flaggedCount++
                    $output += "  [!!!SUSPICIOUS!!!] Name  : $entryName"
                    $output += "                       Value : $entryValue"
                    $output += "                       Reason: Path contains '$matchedPattern'"
                    $output += ""
                } else {
                    $output += "  [OK]  Name  : $entryName"
                    $output += "        Value : $entryValue"
                    $output += ""
                }
            }
        }
        catch {
            $output += "  [!!!ERROR!!!] Could not read key: $_"
            $output += ""
        }
    }

    #Summary
    $output += $separator
    $output += "  SUMMARY"
    $output += $separator
    $output += "  Total entries examined : $totalEntries"
    $output += "  Suspicious entries     : $flaggedCount"

    if ($flaggedCount -gt 0) {
        $output += ""
        $output += "  [!!!ALERT!!!]: $flaggedCount suspicious autorun entry/entries detected."
        $output += "      Review flagged entries above immediately."
    } else {
        $output += ""
        $output += "  [OK] No suspicious autorun entries detected."
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

Export-ModuleMember -Function Initialize-RegistryModule, Get-RegistryArtefacts