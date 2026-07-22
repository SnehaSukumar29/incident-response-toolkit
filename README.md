# 🛡️ Incident Response Toolkit

A modular, USB-deployable PowerShell Incident Response framework for Windows 10/11 
that automates forensic artefact collection and generates colour-coded HTML reports.

Developed as my Final Year Project — BSc (Hons) Cyber Security,  
Anglia Ruskin University, Cambridge (2025/26).

---

## 📌 Overview

When a security incident occurs, the first minutes are critical. This toolkit 
automates the live response phase on Windows systems — collecting volatile and 
non-volatile forensic artefacts, verifying evidence integrity via SHA-256 hashing, 
and producing a structured HTML report — all in a single script execution.

Designed to run from a USB drive with no installation required.

---

## ⚙️ Features

**Volatile Artefact Collection**
- Running processes (with unsigned process detection)
- Active network connections
- Logged-in users
- DNS cache
- Scheduled tasks audit (flags suspicious entries)
- Suspicious services detection
- Windows Defender threat and configuration status
- PowerShell script block logs

**Registry Artefact Collection**
- Persistence mechanism inspection across key registry hives
- Automatic flagging of suspicious values with `[!!!SUSPICIOUS!!!]` alerts

**FileSystem Artefact Collection**
- Filesystem anomaly detection and artefact collection

**Evidence Integrity**
- SHA-256 hash generation for all collected evidence files
- Chain of custody log following RFC 3227 guidelines

**Automated HTML Report**
- Colour-coded report with highlighted suspicious findings
- Sections for all collected artefact categories
- Timestamped case ID for each investigation

**RAT Simulator (Testing Only)**
- Controlled script that plants process, registry, and filesystem artefacts  
  simulating RAT behaviour — for use in isolated VMs only

---

## 🛠️ Technologies Used

- PowerShell (modular architecture with `.psm1` modules)
- Windows Management Instrumentation (WMI / CimInstance)
- Windows Event Logs
- SHA-256 hashing (Get-FileHash)
- HTML and CSS report generation
- Windows Defender API (Get-MpThreat, Get-MpComputerStatus)

---

## 📂 Repository Structure
incident-response-toolkit/
│
├── IR_Launch.ps1          # Main launcher — run this as Administrator
├── modules/
│   ├── IR_Core.psm1       # Case initialisation and HTML report generation
│   ├── IR_Volatile.psm1   # Volatile artefact collection functions
│   ├── IR_Registry.psm1   # Registry inspection and persistence checks
│   └── IR_FileSystem.psm1 # FileSystem artefact collection
├── IR_RAT_Simulator.ps1   # ⚠️ Testing only — isolated VM use
└── README.md

---

## 🚀 How to Run

1. Copy the toolkit folder to a USB drive or local directory
2. Open PowerShell **as Administrator**
3. Navigate to the toolkit folder
4. Run:

```powershell
.\IR_Launch.ps1
```

5. Enter your name when prompted (recorded as Investigator in the report)
6. The framework automatically detects a connected USB drive and saves evidence there, or falls back to `C:\IR_Lab\output`
7. All artefacts are saved to a timestamped case folder
8. Open `Reports\IR_Report.html` in any browser to view findings

---

## 📋 Output Structure

Each run creates a timestamped case folder:
IR_20250601_143022/
├── Logs/
│   ├── IR_Log.txt         # Full execution log with timestamps
│   └── Hashes.txt         # SHA-256 integrity log (RFC 3227)
├── Volatile/              # 11 artefact files
├── Registry/              # Registry inspection output
├── FileSystem/            # Filesystem artefact output
└── Reports/
└── IR_Report.html     # Colour-coded HTML report

---

## ⚠️ Disclaimer

This toolkit was developed for educational purposes as part of a university 
final year project. Use only on systems you own or have explicit permission 
to investigate. The RAT simulator must only be executed inside an isolated 
virtual machine.

---

## 🎯 Skills Demonstrated

- Incident response methodology and live forensics
- PowerShell modular scripting architecture
- Windows forensic artefact collection (volatile and non-volatile)
- Evidence integrity and chain of custody (RFC 3227)
- Automated HTML report generation
- Threat detection logic and suspicious activity flagging

---

*Completed as part of BSc (Hons) Cyber Security — Anglia Ruskin University, Cambridge.*
