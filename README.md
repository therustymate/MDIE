# MDIE
Maybe Defender Isn't Enough? - Microsoft Defender Bypass Loader for Red Teams

**MDIE (Maybe Defender Isn't Enough?) Loader is a PE loader specifically designed for red team operations and research to bypass Microsoft Defender**. The goal of this project is to study the detection techniques used by Defender and methods to evade them, demonstrating Defender's limitations. By integrating practically effective evasion techniques from the research, the loader will be developed for use in red team engagements and research. By open-sourcing this project, we hope to raise corporate awareness that relying solely on Defender without EDR in internal networks leaves organizations highly vulnerable to malwares.

## Disclaimer

This document and all associated materials are provided strictly for **legitimate security research, education, and authorized antivirus detection capability testing purposes only.**
The techniques and concepts described herein involve advanced software security, malware analysis, and development methods, and **any unauthorized use, reproduction, distribution, or malicious deployment against systems without explicit permission is strictly prohibited.**

By accessing and utilizing this material, you acknowledge and agree to comply with all applicable laws and regulations,
and to obtain proper authorization before conducting any security testing or research activities.

The author and affiliated parties **expressly disclaim all legal liability and responsibility for any misuse, unauthorized actions, or damages arising from the use of this information.**

Furthermore, this research was conducted to study current antivirus detection limitations, develop evasion techniques for educational purposes, and enhance cybersecurity expertise.
The disclosure of this technology is purely for advancing the security industry and academic research.

Therefore, all risks, legal responsibilities, and consequences resulting from the use or misuse of this document rest solely with the user.
The author and related parties are fully indemnified from any direct or indirect damages.

By reading or using this document, you are deemed to have accepted all the above conditions.

## Research Scope
**The scope of this research is limited to MDAV (Microsoft Defender Antivirus)**. MDE (Microsoft Defender for Endpoint) is **not included**, and the scope is restricted to the core Defender product, excluding EDR-related technologies.

### MDE vs MDAV
![MDE Detection Layer](https://learn.microsoft.com/en-us/defender-endpoint/media/next-gen-protection-engines.png)

MDE provides a significantly more robust detection system compared to MDAV. It is classified as an EDR (Endpoint Detection and Response) software, not a traditional antivirus solution.

Details: [Advanced technologies at the core of Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav)

## MDAV Research
First, I'll check the official Microsoft Learn documentation to see if there are other detection technologies not found in the Security UI.

Microsoft Learn: [Microsoft Defender Antivirus in Windows Overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows)

### Documented MDAV Services
Based on the official Microsoft Learn documentation, here are the services for Microsoft Defender:

| Service Type                              | Service Name                  | Service Identifier    |
|:------------------------------------------|:------------------------------|:----------------------|
| MDAV Core Service                         | MpDefenderCoreService.exe     | MdCoreSvc             |
| MDAV Service                              | MsMpEng.exe                   | WinDefend             |
| MDAV Network Realtime Inspection Service  | NisSrv.exe                    | WdNisSvc              |
| Microsoft Endpoint DLP Service            | MpDlpService.exe              | MDDlpSvc              |

```ps
PS C:\WINDOWS\system32> Get-Service -Name MdCoreSvc,WinDefend,WdNisSvc,MDDlpSvc -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-Table -AutoSize

Name       Status StartType
----       ------ ---------
MDCoreSvc Running Automatic
WdNisSvc  Running    Manual
WinDefend Running Automatic
```

### ProcMon64 Research

When you set a filter in ProcMon64 with ProcessName + is + "MsMpEng.exe" and run a custom scan, you can observe the Operations (APIs) being called during the scan.

* `./MsMpEng.exe Research/ProcMon64/README.md` (AI Analysis Report)
* `./MsMpEng.exe Research/ProcMon64/MDAVCustomScan.CSV` (CSV File)
* `./MsMpEng.exe Research/ProcMon64/MDAVCustomScan.PML` (ProcMon64 File)

Based on DeepSeek AI analysis, MDAV employs a hierarchical scanning approach: Metadata → USN Journal → File Content. This methodology demonstrates a deliberate effort to minimize system resource consumption and reduce process interference/error generation during scanning operations.

[ProcMon64 Analysis Report](./MsMpEng.exe%20Research/ProcMon64/README.md)

### Detect It Easy

Based on the API list from the import table that can be utilized for malware detection, we were able to infer the approximate scanning functionalities:

* **General file scanning** (hash, signature, heuristic, integrity, and signature verification)
* **ETW-based event tracking**
* **Partial memory scanning**
  * Stack analysis (unwinding, etc.)
  * Simple memory scanning (heap, library, resource usage analysis, etc.)
* **Registry inspection**

Since there is a high probability that other detection techniques exist (e.g., AMSI), we will proceed with reverse engineering.

[Detect It Easy Analysis Report](./MsMpEng.exe%20Research/Detect%20It%20Easy/README.md)

## Reverse Engineering

### ETW Reverse Engineering
[ETW Reverse Engineering Analysis Report](./MsMpEng.exe%20Research/Reverse%20Engineering/ETW/README.md)

Based on speculation, it uses a system called **Asimov** to detect malicious behavior. **Asimov is a powerful feedback and diagnostic mechanism designed to remotely monitor real‑time usage data from users' computers**. Inferring from this, it appears to **collect telemetry information using ETW**, transmit this data via Asimov to an **ML or equivalent system in the cloud**, where malicious behavior detection is carried out.

| Title             | Information                                               |
|:------------------|:----------------------------------------------------------|
| SessionName       | MpWppTracing-20251224-111713-00000003-fffffffeffffffff    |
| Guid              | {2A94554C-2FBE-46D0-9FA6-60562281B0CB}                    |
| Level             | 0 (WINEVENT_LEVEL_LOG_ALWAYS)                             |
| MatchAnyKeyword   | 0x3 (READ_KEYWORD OR WRITE_KEYWORD)                       |
| MatchAllKeyword   | 0x0 (False)                                               |

Reference: [Defining Keywords Used to Classify Types of Events](https://learn.microsoft.com/en-us/windows/win32/wes/defining-keywords-used-to-classify-types-of-events)

## References
* [Advanced technologies at the core of Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav)
* [Engineering detection around Microsoft Defender](https://blog.sekoia.io/engineering-detection-around-microsoft-defender/)
* [Microsoft Defender Antivirus full scan considerations and best practices](https://learn.microsoft.com/en-us/defender-endpoint/mdav-scan-best-practices)
* [AMSI.fail - PowerShell AMSI Disable Script Generator](https://amsi.fail/)
* [Microsoft Defender Antivirus in Windows Overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows)
* [Requirements for Microsoft Defender Antivirus to run in passive mode](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility#requirements-for-microsoft-defender-antivirus-to-run-in-passive-mode)
* [Better know a data source: Antimalware Scan Interface](https://redcanary.com/blog/threat-detection/better-know-a-data-source/amsi/)