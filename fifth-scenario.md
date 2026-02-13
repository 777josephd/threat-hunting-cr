# Threat Hunt Report (Unauthorized TOR Usage)
**Detection of Unauthorized TOR Browser Installation and Use**

## Scenario:
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks.

---

## High-Level TOR related IoC Discovery Plan:
1. Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events
2. Check DeviceProcessEvents for any signs of installation or usage
3. Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports

---

## Steps Taken

1. Isolate events with "tor" as a relevant IoC. Order by descending to show most recent activity first.
<img width="1379" height="596" alt="Step1" src="https://github.com/user-attachments/assets/013e113d-c0a0-48fb-a5f7-a27b98baaad4" />

2. Further isolate the suspicious host to see all relevant information beyond initial scope.
<img width="1379" height="661" alt="Step2" src="https://github.com/user-attachments/assets/0a1e4e12-4abc-47c5-9c30-4d5ccf43b590" />

3. Pivoting to DeviceProcessEvents, we can see the user silently installing tor browser via ProcessCommandLine. `2026-02-12T22:38:22.9017944Z`
<img width="1379" height="573" alt="Step4" src="https://github.com/user-attachments/assets/539d33fb-8f65-432c-a0ae-9d600d74b684" />

4. We confirm usage of tor browser.
<img width="1379" height="835" alt="Step3" src="https://github.com/user-attachments/assets/0c03cec8-bca7-4e31-b2c5-f0fd0f8f5b19" />

5. Pivoting again to DeviceNetworkEvents, we can focus our attention to network traffic beyond the well-known port range with the intention to observe tor-specific traffic.
<img width="1379" height="835" alt="Step5" src="https://github.com/user-attachments/assets/37dbb2fa-8ac9-4953-95b8-603764511dde" />

6. Finally, we can see the user creating a "tor-shopping-list" file.
<img width="1379" height="472" alt="Step6" src="https://github.com/user-attachments/assets/1c8a59b4-a3f2-4768-bf1f-e9e4c9f4ec73" />

---

## Chronological Events

1. File Download - TOR Installer

    - Timestamp: 2026-02-12T22:38:22.9017944Z
    - Event: The user "jad9872" downloaded a file named tor-browser-windows-x86_64-portable-15.0.5.exe to the Downloads folder.
    - Action: File download detected.
    - File Path: C:\Users\jad9872\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe

2. Process Execution - TOR Browser Launch

    - Timestamp: 2026-02-12T22:42:25.7755988Z
    - Event: User "jad9872" opened the TOR browser. Subsequent processes associated with TOR browser, such as firefox.exe and tor.exe, were also created, indicating that the browser launched successfully.
    - Action: Process creation of TOR browser-related executables detected.
    - File Path: C:\Users\jad9872\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

3. Network Connection - TOR Network

    - Timestamp: 2026-02-12T22:42:33.7128362Z
    - Event: A network connection to IP 83.148.245.77 on port 9001 by user "jad9872" was established using tor.exe, confirming TOR browser network activity.
    - Action: Connection success.
    - Process: tor.exe
    - File Path: c:\users\jad9872\desktop\tor browser\browser\torbrowser\tor\tor.exe

4. Additional Network Connections - TOR Browser Activity

    - Timestamps:
        - 2026-02-12T22:42:34.4387012Z - Connected to 193.200.229.34 on port 9000.
        - 2026-02-12T22:43:04.2839566Z - Local connection to 82.165.201.185 on port 9001.
    - Event: Additional TOR network connections were established, indicating ongoing activity by user "jad9872" through the TOR browser.
    - Action: Multiple successful connections detected.

5. File Creation - TOR Shopping List

    - Timestamp: 2026-02-12T22:52:12.5485263Z
    - Event: The user "jad9872" created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their TOR browser activities.
    - Action: File creation detected.
    - File Path: C:\Users\jad9872\Desktop\tor-shopping-list.txt

---

## Summary

A structured investigation was conducted to identify potential TOR-related activity by reviewing DeviceFileEvents, DeviceProcessEvents, and DeviceNetworkEvents for indicators such as tor.exe and firefox.exe. 
Analysis revealed that user jad9872 downloaded the TOR Browser installer (tor-browser-windows-x86_64-portable-15.0.5.exe) to the Downloads directory at 2026-02-12T22:38:22Z. Subsequent process telemetry confirmed silent installation and execution of TOR components, including tor.exe and firefox.exe, 
indicating successful browser launch. Network logs showed multiple outbound connections over known TOR relay ports (9000/9001), validating active communication with the TOR network. Finally, a file named tor-shopping-list.txt was created on the user’s desktop, suggesting post-installation activity potentially associated with TOR usage.

---

## Response Taken
TOR usage was confirmed on endpoint `jad-thl-vm`. The device was isolated and the user's direct manager was notified.

---

## MDE Tables Referenced:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Detection Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"
| order by Timestamp desc

// TOR Browser being silently installed
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
let TargetVM = "jad-thl-vm";
DeviceProcessEvents
| where ProcessCommandLine contains "tor"
| where DeviceName == TargetVM
| order by Timestamp desc

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort > 1024
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where DeviceName == "jad-thl-vm"
| where FileName contains "shopping"
```
