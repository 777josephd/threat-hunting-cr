# Devices Accidentally Exposed to the Internet

### Tools used:
  - Microsoft Azure
  - Microsoft Defender for Endpoint (MDE)


During routine maintenance, the security team is tasked with investigating VMs in the shared services cluster that have mistakenly been exposed to the public Internet.
The goal is to identify misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

Looking into the DeviceInfo table, we focus on windows-target-1 ("windows-target-" in KQL).
With the following query, we can validate that the Windows VM has been Internet facing for several days, with a public IP of 172[.]176[.]88[.]102.

KQL:
```
DeviceInfo
| where DeviceName == "windows-target-"
| where IsInternetFacing == "1"
| order by Timestamp desc
```
<img width="1189" height="817" alt="FirstKQL" src="https://github.com/user-attachments/assets/df4c1afa-acb1-4459-996d-627273b39ed6" />

With the host name confirmed, we can pivot to a new table; DeviceLogonEvents.
Using the following query, we can specify the host and filter for failed logon attempts, specifically from remote IP addresses.

KQL:
```
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
<img width="1189" height="817" alt="SecondKQL" src="https://github.com/user-attachments/assets/f59f9199-5072-44c8-a49f-fc5228753bdf" />

We can see that multiple bad actors have been discovered as having multiple attempts to logon to the target machine.
Using the following query, we can sort the top 5 most attempts by IP and verify their success.

KQL:
```
let SuspiciousIPs = dynamic(["149.50.101.27","111.11.4.120","109.205.211.14","94.26.88.47","57.129.20.205"]);
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(SuspiciousIPs)
```
<img width="1189" height="817" alt="ThirdKQL" src="https://github.com/user-attachments/assets/69411b6c-6f70-44c0-a83f-9c81f9d27457" />

Other IP addresses were also checked, and only internal sources showed successful remote network logons.

Although the device was exposed to the Internet and clear evidence of brute-forcing had occurred, there are no indicators that unauthorized access has been achieved by any potential threat actors.
