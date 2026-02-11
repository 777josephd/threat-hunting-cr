# New Zero-Day Announced on News

## Table of Contents

- [Executive Summary](#executive-summary)
- [Scope of Impact](#scope-of-impact)
- [Key Technical Findings](#key-technical-findings)
- [Containment Action](#containment-action)
- [Risk Assessment](#risk-assessment)
- [Appendix A - Hunting Queries](#appendix-a---hunting-queries)
- [Appendix B - MITRE ATT&CK Mapping](#appendix-b---mitre-attck-mapping)

## Executive Summary

Ransomware was discovered in the network and actively affecting numerous machines, estimated around 110 infected machines over the past 30 days. We confirmed the spread and the business impact is currently ongoing. Immediate action requirements include isolating each known infected machine, collecting necessary evidence for forensic investigations, then completely wiping and reimaging with last known validated backups.
Initial access vector remains under investigation.

## Scope of Impact

File rename events consistent with PwnCrypt encryption were observed on 110 systems within the past 30 days.
The earliest event occurred on Jan 12, 2026 at 08:13 AM.

## Key Technical Findings

A PowerShell script `pwncrypt.ps1` was created and executed.
FileRenamed events showed encryption behavior.
No evidence of lateral movement detected at this time.
No C2 communication observed.

## Containment Action

Infected hosts isolated via MDE.
Hash of `pwncrypt.ps1` generated and blocked.
PowerShell unsigned execution temporarily restricted.
Backup validation initiated.

## Risk Assessment

Data exfiltration is not currently suspected.
Encryption is limited to local directories.
Ransomware is still active.

## Appendix A - Hunting Queries

A1 - Detection of Encrypted Files.

<img width="1504" height="817" alt="KQL1" src="https://github.com/user-attachments/assets/4e24dd98-98c7-4e24-9e1a-940ba780cda1" />
Used to identify hosts with encrypted file extensions.

A2 - Host Enumeration

<img width="1504" height="817" alt="KQL2" src="https://github.com/user-attachments/assets/b0eb56a2-309f-459c-95f4-fbedc93fa57a" />
Determined number of affected endpoints.

A3 - Identification of Malicious Script

<img width="1542" height="835" alt="KQL4" src="https://github.com/user-attachments/assets/7db65836-0e91-49d2-9e46-7fbfe94daad9" />
A3.1

<img width="1505" height="447" alt="MalScr" src="https://github.com/user-attachments/assets/d907438c-f532-4e78-97d7-a04169eab831" />
Confirmed the existence of the malicious ransomware script.

A4 - Confirm Multi-system Infection

<img width="1542" height="835" alt="KQL5" src="https://github.com/user-attachments/assets/86132275-0653-494c-b558-feb1ea071950" />
Shows each host directly infected with the malicious ransomware script.

## Appendix B - MITRE ATT&CK Mapping

`MITRE: T1059.001` – Command and Scripting Interpreter: PowerShell

Execution of `pwncrypt.ps1` to encrypt files.

The ransomware leverages a PowerShell-based payload to perform encryption operations, demonstrating abuse of native scripting capabilities to execute malicious code and automate file encryption across targeted directories.

`MITRE: T1486` – Data Encrypted for Impact

File renaming and AES-256 encryption with .pwncrypt extension.

The observed behavior of encrypting files and modifying filenames (e.g., hello.txt → hello.pwncrypt.txt) directly aligns with ransomware impact techniques designed to deny access to data.

`MITRE: T1083` – File and Directory Discovery

Targeting of specific directories (e.g., C:\Users\Public\Desktop).

The ransomware selectively encrypts files within defined directories, indicating prior enumeration or predefined targeting of accessible file paths.

`MITRE: T1070.004` – Indicator Removal on Host: File Deletion (Potential)

Possible removal of original unencrypted files after encryption.

Ransomware commonly deletes or overwrites original files following encryption to prevent recovery. If confirmed in logs, this would indicate deliberate impact amplification through file removal.

`MITRE: TA0040` – Impact (Tactic)

Encryption of user-accessible data to disrupt operations.

The encryption of files within user directories represents a direct impact to system availability and business continuity, consistent with ransomware objectives.

`MITRE: TA0002` – Execution (Tactic)

Malicious script-based payload execution.

The use of a PowerShell script to carry out encryption reflects execution of attacker-controlled code within the enterprise environment.

`MITRE: TA0007` – Discovery (Tactic)

Directory targeting prior to encryption.

The defined targeting of specific file paths indicates knowledge or enumeration of system structure prior to impact execution.



