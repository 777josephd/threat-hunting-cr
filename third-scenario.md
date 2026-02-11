# Suspected Data Exfiltration from PIPd Employee

### Tools:
  - Microsoft Azure
  - Microsoft Defender for Endpoint

Employee John Doe works in a sensitive department. They were recently placed on a performance improvement plan (PIP).
After learning about this, John became erratic and threw a fit. Management raised concerns that John may be planning to steal proprietary information, then quit the company.
We are tasked with investigating John's activities on his corporate device (windows-target-) using Microsoft MDE and ensure nothing suspicious is taking place.

First, inspecting DeviceFileEvents with the following query:

KQL: <FirstKQL>
```
DeviceFileEvents
| where DeviceName == "windows-target-"
| take 20
| order by Timestamp asc
```
<img width="1730" height="817" alt="FirstKQL" src="https://github.com/user-attachments/assets/a72c12d1-3ca4-41ca-b7f6-2744d0fd2cd2" />

We see an entry with FileName "VMAgentLogs.zip".

We can use the following query to further investigate instances regarding files ending with zip.

KQL:
```
DeviceFileEvents
| where DeviceName == "windows-target-"
| where FileName endswith "zip"
| order by Timestamp asc
```
<img width="1730" height="817" alt="SecondKQL" src="https://github.com/user-attachments/assets/b4e4681d-b4f2-45e2-bf3f-ee8bc66dba42" />

Here, we find an abundant amount of .zip-related log entries at regular intervals, all associated with John's corporate device.

Broadening our scope, we can include numerous well-known archive programs and associate their activity with John's corporate device.

KQL: <ThirdKQL>
```
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "windows-target-";
DeviceProcessEvents
| where FileName has_any(archive_applications)
| order by Timestamp desc
```
<img width="1736" height="817" alt="ThirdKQL" src="https://github.com/user-attachments/assets/0a305157-37cd-4cf4-ac61-ef041b5ac428" />

We can observe multiple instances of 7z.exe running on multiple different devices on the network.

In order to investigate relevant events surrounding the host machine and 7z process, we can select a Timestamp then create a query to analyze surrounding events while excluding the zip processes.

KQL:
```
let VMName = "windows-target-";
let specificTime = datetime(2026-02-04T23:29:58.4167645Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 30m) .. (specificTime + 30m))
| where DeviceName == VMName
| where FileName !endswith ".zip"
| order by Timestamp desc
```
<img width="1736" height="817" alt="ThirdKQL" src="https://github.com/user-attachments/assets/a6bafbca-d44e-4d70-8cfb-2522a3f5e012" />

Parsing through the logs, we can observe multiple suspicious FileName instances, including the 7z.exe and a new, 7z2408-x64.exe.

Investigating these logs, along with PowerShell logs within the time frame scope, we can see the malicious script: `exfiltratedata.ps1`

<img width="1736" height="817" alt="PSScript2" src="https://github.com/user-attachments/assets/37c17053-bf9c-42a9-99b4-02bebb52011b" />

The log entry with FileName field 7z.exe shows the information that was archived for exfiltration: `"7z.exe" a C:\ProgramData\employee-data-20260204232950.zip C:\ProgramData\employee-data-temp20260204232950.csv`

<img width="1736" height="817" alt="7zZip" src="https://github.com/user-attachments/assets/8894effa-6464-4600-88c9-435423c11210" />

Maintaining the same time frame, we can pivot towards network communications involving the host in question and examine logs and activity.

KQL:
```
let VMName = "windows-target-";
let specificTime = datetime(2026-02-04T23:29:58.4167645Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 5m) .. (specificTime + 5m))
| where DeviceName == VMName
| order by Timestamp desc
```
<img width="1736" height="817" alt="FifthKQL" src="https://github.com/user-attachments/assets/60037f7c-3f85-4925-a110-6127d0268b38" />

We find a suspicious outbound connection to an unknown URL, IP 20[.]60[.]181[.]193, and upon further examination, we can see clear indicators of data exfiltration.

<img width="744" height="371" alt="DExfil" src="https://github.com/user-attachments/assets/c65ec79f-f798-4430-9520-53b8e6e7f390" />

Modifying the query slightly, we can examine connections established via RemotePort 443. Doing so, we discover a secondary IP, 20[.]60[.]133[.]132

KQL:
```
let VMName = "windows-target-";
let specificTime = datetime(2026-02-04T23:29:58.4167645Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 5m) .. (specificTime + 5m))
| where DeviceName == VMName
| where RemotePort == "443"
| order by Timestamp desc
```
<img width="1736" height="817" alt="SixthKQL" src="https://github.com/user-attachments/assets/2aca92ac-a2fc-41ee-aea3-587776e305a2" />

Further investigation would entail plugging the domain and IP addresses into DNS lookup tools and sites to pursue further research.

# MITRE ATT&CK Mapping

`MITRE: T1059.001` – Command and Scripting Interpreter: PowerShell

Execution of exfiltratedata.ps1.

PowerShell scripts were executed within the timeframe of archive creation and outbound communication. The use of PowerShell indicates automated data collection and preparation activity consistent with malicious scripting for data staging and exfiltration.

`MITRE: T1005` – Data from Local System

Collection of employee-data-temp20260204232950.csv from local directory.

The creation and handling of locally stored CSV data within C:\ProgramData indicates collection of data from the local system prior to packaging. This reflects targeted gathering of potentially sensitive proprietary information.

`MITRE: T1074.001` – Data Staged: Local Data Staging

Temporary CSV file created prior to archive creation.

The presence of a structured temporary file in ProgramData demonstrates deliberate staging of collected data prior to compression. Staging is commonly used to organize data for efficient exfiltration.

`MITRE: T1560.001` – Archive Collected Data: Archive via Utility

Use of 7z.exe to create employee-data-20260204232950.zip.

Execution of 7-Zip to compress staged data into a single archive reflects a standard attacker technique to consolidate files, reduce size, and prepare data for transfer outside the organization.

`MITRE: T1105` – Ingress Tool Transfer (If 7z2408-x64.exe was downloaded)

Execution of 7z2408-x64.exe installer.

The presence of a standalone 7-Zip installer suggests the potential transfer and installation of tooling to facilitate compression. If downloaded from an external source, this indicates tool ingress prior to data exfiltration.

`MITRE: T1041` – Exfiltration Over C2 Channel

Outbound HTTPS connection to external IP addresses over port 443.

Network logs show suspicious outbound communications to 20[.]60[.]181[.]193 and 20[.]60[.]133[.]132 over TCP 443 within minutes of archive creation. Using HTTPS blends exfiltration traffic with normal encrypted web activity, making detection more difficult.

`MITRE: T1567.002` – Exfiltration to Cloud Storage (If IP resolves to cloud provider)

Outbound communication to remote infrastructure likely hosted externally.

If the destination IP addresses resolve to cloud-hosted infrastructure, this suggests the possibility of data being uploaded to external storage services, a common insider and attacker exfiltration method.

`MITRE: T1083` – File and Directory Discovery

PowerShell-driven enumeration of files prior to staging.

The sequence of script execution and file handling suggests enumeration of accessible directories before selecting and staging sensitive data for compression.

`MITRE: TA0009` – Collection (Tactic)

Systematic preparation of proprietary data prior to departure.

The coordinated use of scripting, local staging, and compression demonstrates structured collection behavior consistent with insider data theft.

`MITRE: TA0010` – Exfiltration (Tactic)

Transmission of archived data to external infrastructure.

The creation of compressed archives followed immediately by outbound encrypted communications reflects a complete exfiltration workflow typical of insider intellectual property theft scenarios.





















