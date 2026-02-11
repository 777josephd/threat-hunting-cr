# Sudden Network Slowdowns

### Tools:
  - Microsoft Azure
  - Microsoft Defender for Endpoint

The server team has noticed significant network performance degradation on some of their older devices attached to the 10[.]0[.]0[.]0/16 network.
After ruling out external DDoS attacks, the security team suspects something may be going on internally.

All traffic originating from within the local network is allowed by all hosts by default.
There is also unrestricted use of PowerShell and other applications in the environment.

First, we will attempt to gather relevant data from logs, network traffic and endpoints.
Using the following queries, we will ensure relevant data is available from all key sources for analysis.

KQL:
```
DeviceNetworkEvents
| order by Timestamp desc
| take 10
```
<img width="1640" height="946" alt="FirstKQL" src="https://github.com/user-attachments/assets/c2ef5f95-0fba-4744-b5ce-46121e4fb7a5" />

Already we can see something suspicious. Host `jad-th-vm1` received a ConnectionFailed ActionType when attempting to connect to itself over port 993.

<img width="1470" height="407" alt="SecondScreen" src="https://github.com/user-attachments/assets/6f8609d7-de2c-47c6-9832-a96bf3ccbd28" />

Continuing with table validation..

KQL:
```
DeviceFileEvents
| order by Timestamp desc
| take 10
```
<img width="1489" height="773" alt="SecondKQL" src="https://github.com/user-attachments/assets/6261d06a-8672-439c-8221-32e27371d14e" />

Using the following query, we can see just how many instances the suspicious host attempted and failed to connect to itself.

KQL:
```
DeviceNetworkEvents
| where DeviceName == "jad-th-vm1"
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount desc
```
<img width="1504" height="543" alt="FourthKQL" src="https://github.com/user-attachments/assets/c3ebbe4b-4b14-49ea-86ea-f511602e9c81" />

Now focusing on the suspicious host, we can inspect the DeviceNetworkEvents table entries specific to the IP.

KQL:
```
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == "10.0.0.187"
| order by Timestamp desc
```
<img width="1464" height="292" alt="TimelineViz" src="https://github.com/user-attachments/assets/7949a567-cd7d-4402-8110-7d95b0b5964c" />
<img width="1504" height="817" alt="FifthKQL" src="https://github.com/user-attachments/assets/2cc1ebe9-9e76-42f6-8160-d3f6a4deee30" />

Here, we can see numerous failed connection attempts from the host VM to itself, seemingly enumerating each port.
Switching to `order by Timestamp asc`, we can now pinpoint the Timestamp field in which the port enumeration began.

<img width="1504" height="817" alt="SeventhKQL" src="https://github.com/user-attachments/assets/c98c4ea3-dce9-471d-bf3c-b9e734569feb" />

Pivoting to the DeviceProcessEvents table, we can reference our specified time collected from the Timestamp, the host's name and we can project the command-line entries relevant to the investigation.

KQL:
```
let VMName = "jad-th-vm1";
let specificTime = datetime(2026-02-11T00:19:02.8956707Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
<img width="1504" height="817" alt="EigthKQL" src="https://github.com/user-attachments/assets/2101e562-bfaf-4450-847b-9ca2aa941393" />

After parsing through a few logs, we find our malicious event.
```"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1```
This command launches a PowerShell script from Windows command-line, using the -ExecutionPolicy Bypass flag to bypass any policies in place regarding script execution, and executes the file at the location C:\programdata\portscan.ps1.

The investigation would continue by uncovering how the file ended up on the machine, followed by quarantine and other appropriate IR remediation efforts.

# MITRE ATT&CK Mapping

`MITRE: T1046` – Network Service Discovery

Repeated failed connections to multiple internal hosts.

The numerous failed connection attempts to many hosts and ports within the 10.0.0.0/16 range indicate likely internal network scanning to identify open services and reachable systems.

`MITRE: T1046` – Network Service Discovery

Host enumerating its own ports (self-connection attempts).

Repeated connection failures from a host to itself across multiple ports suggest automated port enumeration to identify listening services or validate scanning functionality.

`MITRE: T1046` – Network Service Discovery
(Potentially also `T1018` – Remote System Discovery)

High volume of ConnectionFailed events from single internal IP.

Systematic failed connections to numerous internal IP addresses reflect reconnaissance behavior aimed at discovering active hosts and accessible network services.

`MITRE: T1059.001` – Command and Scripting Interpreter: PowerShell

Use of PowerShell with ExecutionPolicy Bypass.

Launching PowerShell with -ExecutionPolicy Bypass indicates deliberate execution of scripts while circumventing security controls, a common attacker and red team technique.

`MITRE: T1059.001` – Command and Scripting Interpreter: PowerShell
`MITRE: T1105` – Ingress Tool Transfer (if script was delivered remotely)

Execution of script from C:\ProgramData.

Executing portscan.ps1 from a writable directory such as C:\ProgramData suggests staging of tooling for reconnaissance or follow-on actions.

`MITRE: TA0007` – Discovery (Tactic)

Internal reconnaissance after initial access.

The behavior collectively demonstrates internal discovery activity consistent with post-compromise reconnaissance aimed at identifying additional targets for lateral movement.

`MITRE: T1059` – Command and Scripting Interpreter

Unrestricted PowerShell use in environment.

The absence of PowerShell restrictions increases attacker flexibility and facilitates execution of malicious scripts without additional privilege escalation.
