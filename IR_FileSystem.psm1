<#
FileSystem artefact collection module for the PowerShell IR Framework.
Collects: Recently accessed files, executables in suspicious locations.

Author: Sneha Sukumar | Anglia Ruskin University
#>

#----------- Start FileSystem Module--------------------------------------
Function Initialize-FileSystemModule {
    param(
        [Parameter(Mandatory=$true)][string]$CaseFolder
    )
    $FileSystemPath = Join-Path $CaseFolder "FileSystem"
    return @{
        Status      = "FileSystem module loaded"
        TargetPath  = $FileSystemPath
        InvokedTime = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}

#------------Get-FileSystemArtefacts-------------------------------------------
Function Get-FileSystemArtefacts {
#It will chek shell:recent for the last 30 accessed files
#It will also scan Temp, AppData\Local and AppData\Roaming for executables
#Any of the executables found in those locations will get flagged as it's not supposed to exist there.

    $separator = "=" * 60
    $output    = @()
    $output   += $separator
    $output   += "  FILESYSTEM ARTEFACTS"
    $output   += "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output   += $separator
    $output   += ""

    $flaggedCount = 0

    # ── Section 1: Recently Accessed Files (shell:recent) ────────────────────
    $output += "  ----Recently Accessed Files (shell:recent)----"
    $output += ""

    try {
        $recentPath = [System.Environment]::GetFolderPath('Recent')

        if (Test-Path $recentPath) {
            $recentFiles = Get-ChildItem -Path $recentPath -ErrorAction SilentlyContinue |
                           Sort-Object LastWriteTime -Descending |
                           Select-Object -First 30

            if ($recentFiles) {
                $output += ("  {0,-50} {1}" -f "File Name", "Last Accessed")
                $output += "  " + ("-" * 75)
                foreach ($f in $recentFiles) {
                    $output += ("  {0,-50} {1}" -f $f.Name, $f.LastWriteTime)
                }
            } else {
                $output += "  [INFO] No recently accessed files found."
            }
        } else {
            $output += "  [INFO] Recent files folder not accessible."
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not retrieve recently accessed files: $_"
    }

    $output += ""

    # ── Section 2: Executables in Temp ───────────────────────────────────────
    $output += "  ----Executable Files in TEMP----"
    $output += ""

    try {
        $tempPath = $env:TEMP
        $exeExtensions = @('*.exe','*.bat','*.ps1','*.vbs','*.cmd','*.scr','*.dll')

        $tempFiles = @()
        foreach ($ext in $exeExtensions) {
            $found = Get-ChildItem -Path $tempPath -Filter $ext `
                     -ErrorAction SilentlyContinue -Force
            if ($found) { $tempFiles += $found }
        }

        $tempFiles = $tempFiles | Sort-Object LastWriteTime -Descending

        if ($tempFiles) {
            foreach ($f in $tempFiles) {
                $flaggedCount++
                $output += "  [!!!SUSPICIOUS!!!] File     : $($f.Name)"
                $output += ("        Full Path  : {0}" -f $f.FullName)
                $output += ("        Size       : {0} KB" -f [math]::Round($f.Length / 1KB, 1))
                $output += ("        Created    : {0}" -f $f.CreationTime)
                $output += ("        Modified   : {0}" -f $f.LastWriteTime)
                $output += ""
            }
        } else {
            $output += "  [OK] No executable files found in TEMP."
            $output += ""
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not scan TEMP folder: $_"
        $output += ""
    }

    # ── Section 3: Executables in AppData\Local ──────────────────────────────
    $output += "  ----Executable Files in AppData\Local (Top Level)----"
    $output += ""

    try {
        $appDataLocal = $env:LOCALAPPDATA
        $exeExtensions = @('*.exe','*.bat','*.ps1','*.vbs','*.cmd','*.scr')

        $appDataFiles = @()
        foreach ($ext in $exeExtensions) {
            $found = Get-ChildItem -Path $appDataLocal -Filter $ext `
                     -ErrorAction SilentlyContinue -Force
            if ($found) { $appDataFiles += $found }
        }

        $appDataFiles = $appDataFiles | Sort-Object LastWriteTime -Descending

        if ($appDataFiles) {
            foreach ($f in $appDataFiles) {
                $flaggedCount++
                $output += "  [!!!SUSPICIOUS!!!] File     : $($f.Name)"
                $output += ("        Full Path  : {0}" -f $f.FullName)
                $output += ("        Size       : {0} KB" -f [math]::Round($f.Length / 1KB, 1))
                $output += ("        Created    : {0}" -f $f.CreationTime)
                $output += ("        Modified   : {0}" -f $f.LastWriteTime)
                $output += ""
            }
        } else {
            $output += "  [OK] No executable files found in AppData\Local top level."
            $output += ""
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not scan AppData\Local: $_"
        $output += ""
    }

    # ── Section 4: Executables in AppData\Roaming (Top Level) ────────────────
    $output += "  ----Executable Files in AppData\Roaming (Top Level)----"
    $output += ""

    try {
        $appDataRoaming = $env:APPDATA
        $exeExtensions  = @('*.exe','*.bat','*.ps1','*.vbs','*.cmd','*.scr')

        $roamingFiles = @()
        foreach ($ext in $exeExtensions) {
            $found = Get-ChildItem -Path $appDataRoaming -Filter $ext `
                     -ErrorAction SilentlyContinue -Force
            if ($found) { $roamingFiles += $found }
        }

        $roamingFiles = $roamingFiles | Sort-Object LastWriteTime -Descending

        if ($roamingFiles) {
            foreach ($f in $roamingFiles) {
                $flaggedCount++
                $output += "  [!!!SUSPICIOUS!!!] File     : $($f.Name)"
                $output += ("        Full Path  : {0}" -f $f.FullName)
                $output += ("        Size       : {0} KB" -f [math]::Round($f.Length / 1KB, 1))
                $output += ("        Created    : {0}" -f $f.CreationTime)
                $output += ("        Modified   : {0}" -f $f.LastWriteTime)
                $output += ""
            }
        } else {
            $output += "  [OK] No executable files found in AppData\Roaming top level."
            $output += ""
        }
    }
    catch {
        $output += "  [!!!ERROR!!!] Could not scan AppData\Roaming: $_"
        $output += ""
    }

    # ── Summary ───────────────────────────────────────────────────────────────
    $output += $separator
    $output += "  SUMMARY"
    $output += $separator
    $output += "  Suspicious executables found : $flaggedCount"

    if ($flaggedCount -gt 0) {
        $output += ""
        $output += "  [!!!ALERT!!!]: $flaggedCount suspicious executable(s) detected."
        $output += "      Executables in Temp or AppData are strong indicators"
        $output += "      of malware dropper activity. Investigate immediately."
    } else {
        $output += ""
        $output += "  [OK] No suspicious executables found in monitored locations."
    }

    $output += ""
    $output += $separator

    return ($output -join "`r`n")
}

Export-ModuleMember -Function Initialize-FileSystemModule, Get-FileSystemArtefacts