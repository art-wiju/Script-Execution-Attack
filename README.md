# Incident Response Simulation - AutoIt Script Execution (T1059)

## Overview
This GitHub project simulates a script execution attack using the Atomic Red Team's AutoIt script test for MITRE ATT&CK technique T1059 - Command and Scripting Interpreter. It guides you through setting up the attack in an Azure Windows VM, detecting it using Microsoft Defender for Endpoint (MDE), and conducting an incident response investigation aligned with NIST 800-61 guidelines.

---

## 📚 Tools & Frameworks
- Azure Virtual Machines
- Microsoft Defender for Endpoint
- Microsoft Sentinel
- Wireshark
- PowerShell
- Atomic Red Team Scripts
- Optional: DeepBlueCLI
- Incident Response Framework: NIST 800-61

---

## 🔗 Important Links
- **Atomic Red Script**: [T1059.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.yaml#L4)
- **MITRE T1059 Description**: [Atomic Red Team T1059](https://www.atomicredteam.io/atomic-red-team/atomics/T1059#atomic-test-1---autoit-script-execution)
- **Wireshark**: [Download](https://www.wireshark.org/download.html)
- **DeepBlueCLI**: [Download](https://www.sans.org/tools/deepbluecli/)
- **Git for Windows**: [Download](https://git-scm.com/download/win)
- **Video Walkthrough**: [YouTube](https://youtu.be/N8SfZfiM3m0)
- **Lab Author**: [LinkedIn](https://www.linkedin.com/in/chris-herrera-cyber/) 

---

## 🛠️ Step-by-Step Setup

### Step 1: Prepare Azure VM
- Create Azure Windows VM with a public IP
- Disable firewall & allow all NSG inbound traffic
- Onboard VM to Microsoft Defender for Endpoint
- Install tools:
  - Wireshark
  - Git for Windows
  - (Optional) DeepBlueCLI

### Step 2: Configure MDE Detection Rules
Create KQL detection rules to identify suspicious behavior:

**Rule 1**: AutoIt3.exe executing calc.au3 from user/temp/downloads:
```kql
DeviceProcessEvents
| where DeviceName == "your-device-name"
| where FileName =~ "AutoIt3.exe"
| where ProcessCommandLine has_any (".au3", "calc.au3")
| where FolderPath has_any ("Users", "Temp", "Downloads")
```

**Rule 2**: AutoIt3.exe launching calc.exe:
```kql
DeviceProcessEvents
| where DeviceName == "your-device-name"
| where InitiatingProcessFileName =~ "AutoIt3.exe"
| where FileName =~ "calc.exe"
```

**Rule 3**: PowerShell using Invoke-WebRequest:
```kql
DeviceProcessEvents
| where DeviceName == "your-device-name"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "wget", "curl")
| where ProcessCommandLine has "autoit" and "getfile.pl"
```

**Rule 4**: PowerShell installing AutoIt:
```kql
DeviceFileEvents
| where DeviceName == "your-device-name"
| where FileName has "autoit" and FileName endswith ".exe"
| where InitiatingProcessFileName =~ "powershell.exe"
```

![image](https://github.com/user-attachments/assets/ffa13f51-e32b-4657-847f-89caa940d9aa)

### Step 3: Start capturing traffic with Wireshark

![image](https://github.com/user-attachments/assets/9c2f3e85-9018-409a-966e-85e45576f092)

### Step 4: Detonate the Attack
Execute the attack inside the VM:
```powershell
git clone https://github.com/redcanaryco/atomic-red-team.git
cd C:\Users\<YourUser>\atomic-red-team
$env:PathToAtomicsFolder = "C:\Users\<YourUser>\atomic-red-team\atomics\"
Install-Module -Name Invoke-AtomicRedTeam -Force -AllowClobber
Import-Module Invoke-AtomicRedTeam
Set-ExecutionPolicy Bypass -Scope Process -Force
Invoke-AtomicTest T1059 -GetPrereqs -PathToAtomicsFolder $env:PathToAtomicsFolder
Invoke-AtomicTest T1059 -PathToAtomicsFolder $env:PathToAtomicsFolder
```
Confirm Calculator launches. Save Wireshark capture.

### Step 5: Review Alerts
- Navigate to MDE > Assets > Devices > Your VM > Alerts
- Confirm detection rules were triggered

---

## 🔍 Step 6: Incident Response (NIST 800-61)

### Key Tasks
1. Identify attack vector (in this lab: internal simulation)
2. Review precursors and indicators (e.g., AutoIt download, process creation)
3. Validate if this is a true or false positive
4. Document findings
5. Escalate incident if true positive

### Analyze MDE Logs
- View Alert timeline > Expand logs
- Look for Event IDs like 8408 with `Invoke-WebRequest`
- Confirm AutoIt3.exe and calc.au3 execution

![WhatsApp Image 2025-05-09 at 15 55 39_01b680d8](https://github.com/user-attachments/assets/2a1eaeb9-e4e4-455f-8de3-368347f25418)

![image](https://github.com/user-attachments/assets/eab513f1-a79f-4f76-b26e-255394eebc80)

### Analyze PCAP with Wireshark
Display filter to find the download:
```
tls && ip.src == 10.1.0.64 && frame contains "autoitscript.com"
```
Full communication:
```ip.addr == 10.1.0.64 && ip.addr == 212.227.91.231 && tls```

![image](https://github.com/user-attachments/assets/312d46e6-f48b-4070-bb6a-850d60924fdb)

### Analyze Sentinel Logs
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName == "specific-device-name"
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, ActionType, InitiatingProcessFileName, ReportId
| order by Timestamp desc
```
![WhatsApp Image 2025-05-09 at 15 33 30_8b36bb1f](https://github.com/user-attachments/assets/b4b415cf-a882-4e3c-a7fb-b5fb8b9284c5)

---

## Indicators of Compromise (IoCs)

### Domains
- `www.autoitscript.com`

### IP Addresses
- `212.227.91.231`

### File Hashes (MD5)
- `a65b5df1a846fb0bb7ad4b2da19bbbcd` – *autoit-v3-setup.exe*
- `0adb9b817f1df7807576c2d7068dd931` – *AutoIt3.exe*

### Observed Command Execution
```powershell
powershell.exe & {Start-Process -FilePath "C:\Program Files (x86)\AutoIt3\AutoIt3.exe" -ArgumentList "C:\Users\jchris\atomic-red-team\atomics\T1059\src\calc.au3"}
```

--- 

## Why AutoIt and `.au3` Files Should Raise Alerts

**AutoIt** is a legit scripting language used to automate Windows tasks, but it’s often abused by attackers to execute malicious payloads. It uses `.au3` scripts, which can be compiled into standalone executables.

### Why It's Dangerous

- **LOLBIN abuse**: `AutoIt3.exe` is often used by threat actors to run malicious scripts.
- **Obfuscation**: Scripts are easy to obfuscate, hiding malicious behavior.
- **Low AV detection**: Compiled AutoIt malware often evades AV and EDR.
- **Common in malware**: Frequently seen in commodity malware loaders and phishing lures.

### Detection Tips

- Flag execution of `AutoIt3.exe`, especially from user/temp folders.
- Monitor `.au3` files being executed or downloaded from the internet.
- Correlate with suspicious network activity or child process creation.

---

## Yara Rule (Detect AutoIt Script Execution)

```yara

// This YARA rule detects suspicious AutoIt script usage, typically linked to malicious activities.
// It checks for the presence of AutoIt script components like the AutoIt3.exe
// and the use of PowerShell with Start-Process to execute AutoIt scripts.
// The rule flags potentially malicious behavior based on the strings and file hashes provided.

rule Suspicious_AutoIt_Usage
{
    meta:
        description = "Detects potentially malicious AutoIt script usage"
        author = "Wilson"
        date = "2025-05-10"
        hash1 = "a65b5df1a846fb0bb7ad4b2da19bbbcd" // autoit-v3-setup.exe
        hash2 = "0adb9b817f1df7807576c2d7068dd931" // AutoIt3.exe
        reference = "https://www.autoitscript.com"
        severity = "medium"
        tags = "autoit, au3, t1059"

    strings:
        $s1 = "C:\\Program Files (x86)\\AutoIt3\\AutoIt3.exe"
        $s2 = ".au3"
        $s3 = "calc.au3"
        $ps1 = "powershell.exe"
        $cmd = "Start-Process"

    condition:
        1 of ($s*) and $ps1 and $cmd
}


