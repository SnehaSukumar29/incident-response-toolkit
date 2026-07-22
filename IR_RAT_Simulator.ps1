<#
RAT Simulation Script for the PowerShell Incident Response Framework
Author: Sneha Sukumar | Anglia Ruskin University

WARNING: FOR USE IN ISOLATED VM ONLY. NEVER RUN ON A REAL MACHINE.

USAGE:
    .\IR_RAT_Simulator.ps1 -Mode Simulate    #Plant artefact and open 60s window to run IR tool
    .\IR_RAT_Simulator.ps1 -Mode Cleanup     #Remove all planted artefacts

TESTING SEQUENCE:
    Terminal 1:  .\IR_RAT_Simulator.ps1 -Mode Simulate
    Terminal 2:  .\IR_Launch.ps1                          (run immediately)
    After test:  .\IR_RAT_Simulator.ps1 -Mode Cleanup
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Simulate','Cleanup')]
    [string]$Mode
)

# ── Artefact definitions ──────────────────────────────────────────────────────
$FakeExeName = "RAT_Backdoor.exe"
$FakeExePath = "$env:TEMP\$FakeExeName"
$RegKeyPath  = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RegKeyName  = "RAT_Persistence"
$ListenPort  = 4444

# ── SIMULATE ──────────────────────────────────────────────────────────────────
if ($Mode -eq 'Simulate') {

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  IR RAT Simulator - Planting Test Artefacts"
    Write-Host "  !! ISOLATED VM ONLY - TESTING USE ONLY !!"
    Write-Host "============================================================"
    Write-Host ""

    # 1. Copy cmd.exe to TEMP as RAT_Backdoor.exe
    Write-Host "[*] Dropping RAT_Backdoor.exe to TEMP..."
    Copy-Item -Path "$env:SystemRoot\System32\cmd.exe" -Destination $FakeExePath -Force
    Write-Host "    Created : $FakeExePath"

    # 2. Plant registry persistence key
    Write-Host "[*] Writing registry Run key..."
    Set-ItemProperty -Path $RegKeyPath -Name $RegKeyName -Value $FakeExePath -Force
    Write-Host "    Key     : $RegKeyPath\$RegKeyName"
    Write-Host "    Value   : $FakeExePath"

    # 3. Launch RAT_Backdoor.exe as a hidden process
    Write-Host "[*] Spawning hidden RAT_Backdoor.exe process..."
    $hiddenProc = Start-Process -FilePath $FakeExePath `
                                -ArgumentList "/c timeout /t 300 /nobreak" `
                                -WindowStyle Hidden `
                                -PassThru
    Write-Host "    PID     : $($hiddenProc.Id)"
    Write-Host "    Name    : RAT_Backdoor (visible in process list)"

    # 4. Open TCP listener on port 4444 for 60 seconds
    Write-Host ""
    Write-Host "[*] Opening TCP listener on port $ListenPort for 60 seconds..."
    Write-Host "    --> Run IR_Launch.ps1 NOW in another terminal <--"
    Write-Host ""

    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $ListenPort)
        $listener.Start()
        Write-Host "[+] Port $ListenPort is now OPEN. Waiting 60 seconds..."
        Start-Sleep -Seconds 60
    }
    finally {
        if ($listener) { $listener.Stop() }
        Write-Host "[*] Port $ListenPort listener closed."
    }

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  Simulation complete."
    Write-Host "  Run cleanup when done: .\IR_RAT_Simulator.ps1 -Mode Cleanup"
    Write-Host "============================================================"
    Write-Host ""
}

# ── CLEANUP ───────────────────────────────────────────────────────────────────
if ($Mode -eq 'Cleanup') {

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  IR RAT Simulator - Cleaning Up Test Artefacts"
    Write-Host "============================================================"
    Write-Host ""

    # Remove registry key
    try {
        Remove-ItemProperty -Path $RegKeyPath -Name $RegKeyName -ErrorAction Stop
        Write-Host "[+] Registry key removed: $RegKeyName"
    }
    catch {
        Write-Host "[-] Registry key not found (already removed or never planted)."
    }

    # Kill RAT_Backdoor.exe processes first, then delete file
    $killed = 0
    Get-Process -Name "RAT_Backdoor" -ErrorAction SilentlyContinue | ForEach-Object {
        try { Stop-Process -Id $_.Id -Force; $killed++ } catch { }
    }
    if ($killed -gt 0) {
        Write-Host "[+] Stopped $killed RAT_Backdoor.exe process(es)."
    } else {
        Write-Host "[-] No RAT_Backdoor processes found."
    }

    Start-Sleep -Seconds 1

    # Delete fake exe
    try {
        Remove-Item -Path $FakeExePath -Force -ErrorAction Stop
        Write-Host "[+] RAT_Backdoor.exe deleted."
    }
    catch {
        Write-Host "[-] Could not delete file: $_"
    }

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  Cleanup complete. VM is clean."
    Write-Host "============================================================"
    Write-Host ""
}